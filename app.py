from flask import Flask, request, jsonify, render_template, session, Response
from flask_cors import CORS
import traceback
from utils.config import get_openai_api_key, test_confluence_connection, test_slack_connection
import os
import datetime
from urllib.parse import urlparse
from pdfminer.high_level import extract_text
from llm.bedrock_handler import BedrockHandler
from utils.confluence_handler import decide_document_source, load_confluence_documents
from utils.slack_handler import load_slack_thread
from utils.document_handler import process_pdf_file
from rag.rag_handler import RAGHandler
from llm.openai_module import OpenAIHandler
from core.threat_modeling import ThreatModelingHandler
from core.dread import DreadHandler
from core.mitigation import MitigationHandler
from core.attack_tree import AttackTreeHandler
from core.cvss import CvssHandler
from utils.storage import StorageHandler
import base64
from core.chat import Chat
import json
import uuid
import logging

from core.design_objectives import DesignObjectiveAlignmentHandler


# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(
    app,
    resources={r"/*": {
        "origins": [
            "http://localhost:3000",
            "https://threatshield-frontend.onrender.com",
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin", "Accept"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
    }}
)

# --- Data directories (local vs Render disk) ---
BASE_DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
STORAGE_ROOT = os.path.join(BASE_DATA_DIR, "storage")
UPLOAD_ROOT = os.path.join(BASE_DATA_DIR, "uploads")

os.makedirs(STORAGE_ROOT, exist_ok=True)
os.makedirs(UPLOAD_ROOT, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_ROOT

SETTINGS_PATH = os.path.join(BASE_DATA_DIR, "settings.json")

def load_settings() -> dict:
    """
    Load global settings from settings.json.
    Safe to call even if the file doesn't exist.
    """
    if not os.path.exists(SETTINGS_PATH):
        return {}
    try:
        with open(SETTINGS_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading settings.json: {e}")
        return {}


# Custom error handler to capture and format all errors
@app.errorhandler(Exception)
def handle_exception(e):
    # Get the full traceback
    error_traceback = traceback.format_exc()
    # Log the error with traceback
    logging.error(f"Unhandled exception: {str(e)}\n{error_traceback}")
    
    # Format the error response
    error_response = {
        "error": str(e),
        "traceback": error_traceback,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    # Return a JSON response with the error details
    return jsonify(error_response), 500

# Initialize handlers
storage_handler = StorageHandler()

# We'll choose the LLM handler per request based on settings/details.json
# Global chat instance to maintain conversation history across requests
chat_instance = None

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def extract_text_from_pdf(pdf_path):
    return extract_text(pdf_path)

def get_llm_handler(assessment_id: str | None = None):
    """
    Decide which LLM backend to use (OPENAI or BEDROCK) for a given assessment.

    Priority:
    1. Per-assessment storage/{id}/details.json (llmProvider)
    2. Env LLM_METHOD
    3. BEDROCK
    """
    # Default from env
    provider = os.getenv("LLM_METHOD", "BEDROCK").upper()

    # --- Hard guard: don't use OpenAI if the key is missing/placeholder ---
    openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY") or ""
    if provider == "OPENAI":
        # common placeholders / empty values
        bad_values = {"", "DOESNTWORK", "CHANGE_ME", "YOUR_KEY_HERE", "NONE", "NULL"}
        if openai_key.strip().upper() in bad_values:
            logging.warning("LLM_METHOD=OPENAI but OPENAI_API_KEY is missing/placeholder. Falling back to BEDROCK.")
            provider = "BEDROCK"


    # Try to override per assessment
    if assessment_id:
        try:
            details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
            if os.path.exists(details_path):
                with open(details_path, "r") as f:
                    details = json.load(f)

                if details.get("llmProvider"):
                    provider = details["llmProvider"].upper()
        except Exception as e:
            logging.error(f"Error reading llmProvider from details.json: {e}")

    logging.info(f"Using {provider} LLM provider for assessment {assessment_id}")

    # Correct routing — DO NOT use OpenAIHandler for Bedrock
    if provider == "BEDROCK":
        from llm.bedrock_handler import BedrockHandler
        return BedrockHandler()

    # Default to OpenAI
    return OpenAIHandler()



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_documents():
    # Handle Confluence input  
    confluence_url = request.form.get('confluence_url')

    # Get threat modeling inputs
    session['name'] = request.form.get('name', 'Not specified').replace(" ", "_")
    session['description'] = request.form.get('description', 'Not specified')
    session['app_type'] = request.form.get('app_type', 'Not specified')
    session['sensitivity_level'] = request.form.get('sensitivity_level', 'Not specified')
    session['internet_facing'] = request.form.get('internet_facing', 'Yes')
    session['authentication'] = request.form.getlist('authentication[]')
    session['authentication_str'] = ', '.join(session['authentication']) if session['authentication'] else 'Not specified'
    session['sensitive_data'] = request.form.get('sensitive_data', 'Not specified')

    # Get and log initial custom prompt
    session['custom_prompt'] = request.form.get('custom_prompt', '')
    logging.info(f"Initial custom prompt from form: '{session['custom_prompt']}'")
    
    # Get additional document sources
    additional_info = request.form.get('additional_info', '{}')
    assessment_id = None

    try:
        additional_info_json = json.loads(additional_info)
        # Store additional info in a file
        assessment_id = storage_handler.create_assessment()
        session['assessment_id'] = assessment_id
        
        # Process and store additional document sources
        enhanced_info = {
            "confluenceDoc": None,
            "slackThread": None,
            "meetingTranscript": None
        }
        
        session['custom_prompt'] += "##Custom Prompt: "
        # Extract Confluence content if provided
        if additional_info_json.get('confluenceDoc'):
            try:
                logging.info(f"Attempting to extract content from Confluence URL: {additional_info_json['confluenceDoc']}")
                confluence_result = load_confluence_documents(additional_info_json['confluenceDoc'])
                
                # Process the content
                content = "\n\n".join([doc.page_content for doc in confluence_result])
                enhanced_info['confluenceDoc'] = {
                    "url": additional_info_json['confluenceDoc'],
                    "content": content,
                    "title": "Confluence Document"
                }
                
                # Add to custom prompt
                logging.info(f"Successfully extracted {len(confluence_result)} documents from Confluence")
                confluence_content = (
                    f"##Additional Details\n\nAdditional Confluence Content:\n{content[:1000]}..."
                    if len(content) > 1000 else
                    f"\n\nAdditional Confluence Content:\n{content}"
                )
                session['custom_prompt'] += confluence_content
                logging.info(f"Added Confluence content to custom prompt: '{confluence_content}'")
                
            except Exception as e:
                logging.error(f"Error extracting Confluence content: {str(e)}")
                enhanced_info['confluenceDoc'] = {
                    "url": additional_info_json['confluenceDoc'],
                    "error": str(e)
                }
                session['custom_prompt'] += (
                    f"\n\nAdditional Confluence Document Link (content extraction failed):\n"
                    f"{additional_info_json['confluenceDoc']}"
                )
        
        # Extract Slack thread content if provided
        if additional_info_json.get('slackThread'):
            try:
                logging.info(f"Attempting to extract content from Slack thread: {additional_info_json['slackThread']}")
                slack_result = load_slack_thread(additional_info_json['slackThread'])
                
                enhanced_info['slackThread'] = {
                    "url": additional_info_json['slackThread'],
                    "content": slack_result['content'],
                    "channel": slack_result['channel']
                }
                
                logging.info(f"Successfully extracted {slack_result.get('message_count', 0)} messages from Slack thread")
                content = slack_result['content']
                slack_content = (
                    f"\n\nSlack Thread Content:\n{content[:1000]}..."
                    if len(content) > 1000 else
                    f"\n\nSlack Thread Content:\n{content}"
                )
                session['custom_prompt'] += slack_content
                logging.info(f"Added Slack content to custom prompt: '{slack_content}'")
                
            except Exception as e:
                logging.error(f"Error extracting Slack thread content: {str(e)}")
                enhanced_info['slackThread'] = {
                    "url": additional_info_json['slackThread'],
                    "error": str(e)
                }
                session['custom_prompt'] += (
                    f"\n\nSlack Thread Link (content extraction failed):\n"
                    f"{additional_info_json['slackThread']}"
                )
        
        # Store meeting transcript if provided
        if additional_info_json.get('meetingTranscript'):
            enhanced_info['meetingTranscript'] = {
                "content": additional_info_json['meetingTranscript'],
                "title": "Meeting Transcript"
            }
            meeting_content = f"\n\nMeeting Transcript:\n{additional_info_json['meetingTranscript']}"
            session['custom_prompt'] += meeting_content
            logging.info(f"Added meeting transcript to custom prompt: '{meeting_content}'")
        
        # Save enhanced info to file
        additional_info_path = os.path.join(STORAGE_ROOT, assessment_id, 'additionalinfo.json')
        os.makedirs(os.path.dirname(additional_info_path), exist_ok=True)
        with open(additional_info_path, 'w') as f:
            json.dump(enhanced_info, f, indent=2)
            
    except json.JSONDecodeError:
        logging.error("Failed to parse additional_info JSON")
        # If parsing failed and we don't have an assessment yet, create one now
        if not assessment_id:
            assessment_id = storage_handler.create_assessment()
            session['assessment_id'] = assessment_id
    
    image_files = request.files.getlist('image_files')

    logging.info("Request files: %s", request.files)
    pdf_files = request.files.getlist('pdf_file')
    logging.info("Retrieved PDF files: %s", pdf_files)
    image_files = request.files.getlist('image_files')
    print(image_files)
    persist_dir = ""
    documents = []
    
    # Determine persist directory based on Confluence space or random name
    if session['name']:
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{session['name']}")
    else:
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{uuid.uuid4()}")
    
    # Ensure the persist directory exists
    os.makedirs(persist_dir, exist_ok=True)
    
    try:
        # Process documents from either Confluence or PDF
        temp_pdf_path = None
        documents = []
        
        # Handle PDF files if provided
        temp_pdf_paths = []
        if pdf_files:
            try:
                logging.info(f"PDF files received: {len(pdf_files)}")
                for i, pdf_file in enumerate(pdf_files):
                    if pdf_file and hasattr(pdf_file, 'filename'):
                        logging.info(f"PDF file {i+1}: {pdf_file.filename}, content_type: {pdf_file.content_type}")
                    else:
                        logging.warning(f"PDF file {i+1} is invalid or missing filename attribute")
                
                upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['name'] + "_files")
                os.makedirs(upload_dir, exist_ok=True)
                logging.info(f"Created upload directory: {upload_dir}")
                
                for pdf_file in pdf_files:
                    if pdf_file and pdf_file.filename:
                        temp_pdf_path = os.path.join(upload_dir, pdf_file.filename)
                        logging.info(f"Saving PDF file to: {temp_pdf_path}")
                        pdf_file.save(temp_pdf_path)
                        
                        if not os.path.exists(temp_pdf_path):
                            error_msg = f"Failed to save PDF file: {pdf_file.filename}"
                            logging.error(error_msg)
                            raise ValueError(error_msg)
                            
                        file_size = os.path.getsize(temp_pdf_path)
                        logging.info(f"PDF file saved to: {temp_pdf_path} (size: {file_size} bytes)")
                        
                        if file_size == 0:
                            logging.warning(f"PDF file is empty: {pdf_file.filename}")
                        else:
                            temp_pdf_paths.append(temp_pdf_path)
                            logging.info(f"Added {temp_pdf_path} to processing list")
                    
            except Exception as e:
                logging.error(f"Error saving PDF file: {str(e)}")
                return jsonify({"error": f"Error saving PDF file: {str(e)}"}), 500
        
        try:
            # decide_document_source will handle both Confluence and PDF sources
            documents = decide_document_source(confluence_url, file_paths=temp_pdf_paths)
            if not documents:
                raise ValueError("No documents were extracted from the source")
                
            logging.info(f"Documents processed: {len(documents)}")
            for i, doc in enumerate(documents):
                content = doc.page_content if hasattr(doc, 'page_content') else str(doc)
                logging.info(f"Document {i+1} content length: {len(content)}")
                if len(content) == 0:
                    logging.warning(f"Document {i+1} is empty")
                else:
                    logging.info(f"Document {i+1} first 100 chars: {content[:100]}")
                    
        except Exception as e:
            logging.error(f"Error processing documents: {str(e)}")
            return jsonify({"error": f"Error processing documents: {str(e)}"}), 500
    except Exception as e:
        logging.error(f"Error processing documents: {str(e)}")
        return jsonify({"error": f"Error processing documents: {str(e)}"}), 500

    # ---------- LLM + RAG HANDLING (NOW INSIDE FUNCTION) ----------

    # Ensure we have an assessment_id
    assessment_id = session.get('assessment_id') or assessment_id
    if not assessment_id:
        assessment_id = storage_handler.create_assessment()
        session['assessment_id'] = assessment_id

    # --- Ensure details.json exists early so provider routing works during upload ---
    details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
    if not os.path.exists(details_path):
        os.makedirs(os.path.dirname(details_path), exist_ok=True)

        # If you already have a preferred provider from env, persist it
        default_provider = (os.getenv("LLM_METHOD") or "BEDROCK").upper()

        stub_details = {
            "llmProvider": default_provider
        }

        try:
            with open(details_path, "w") as f:
                json.dump(stub_details, f, indent=2)
            logging.info(f"Wrote stub details.json early for upload provider routing: {stub_details}")
        except Exception as e:
            logging.error(f"Failed writing stub details.json: {e}")


    # Choose LLM based on assessment details (if already present) or env default
    llm_handler = get_llm_handler(assessment_id)

    # RAG handler (it expects something that behaves like OpenAIHandler, which BedrockHandler does too)
    rag_handler = RAGHandler(openai_handler=llm_handler, persist_dir=persist_dir, assessment_id=assessment_id)

    # Process images to retrieve microservices
    microservices_list = []

    for image in image_files:
        logging.info("Image exists: %s", image)
        try:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], session['name'] + "_files")
            os.makedirs(image_path, exist_ok=True)

            save_path = os.path.join(image_path, image.filename)
            logging.info("Saving image to: %s", save_path)

            image.save(save_path)
            logging.info(f"Image saved to: {save_path}")

            microservices = rag_handler.rag_image(save_path)
            microservices_list.append(microservices)

        except Exception as e:
            logging.error(f"Error processing image {image.filename}: {str(e)}")
            microservices_list.append({"error": f"Failed to process image: {str(e)}"})

    # Generate RAG report
    try:
        rag_result = rag_handler.rag_main(documents)
        logging.info("RAG report generated successfully")
    except Exception as e:
        logging.error(f"Error generating RAG report: {str(e)}")
        rag_result = f"Error generating RAG report: {str(e)}"
    
    # Store RAG results
    storage_handler.save_rag_result(assessment_id, rag_result)
    
    # Prepare page counts for each PDF file
    pdf_page_counts = {}
    for path in temp_pdf_paths:
        try:
            filename = os.path.basename(path)
            pages = process_pdf_file(path)
            pdf_page_counts[filename] = len(pages)
            logging.info(f"PDF file {filename} has {len(pages)} pages")
        except Exception as e:
            logging.error(f"Error getting page count for {path}: {str(e)}")
            pdf_page_counts[filename] = 0
    
    # Return results
    return jsonify({
        "message": "Documents processed successfully",
        "assessment_id": assessment_id,
        "document_count": len(documents),
        "microservices": microservices_list,
        "rag_result": rag_result,
        "pdf_page_counts": pdf_page_counts
    })




@app.route('/api/query-ai', methods=['POST'])
def query_ai():
    try:
        data = request.get_json()
        user_query = data.get('user_query')
        assessment_id = data.get('assessment_id')

        if not user_query:
            return jsonify({"error": "User query is required"}), 400
            
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        # Initialize OpenAI handler
        # Choose LLM provider
        llm_handler = get_llm_handler(assessment_id)

        global chat_instance
        if not chat_instance:
            chat_instance = Chat(llm_handler)
        else:
            # Optional: if Chat supports swapping the handler
            try:
                chat_instance.llm_handler = llm_handler
            except AttributeError:
                # Fallback: re-create the chat instance if the class doesn't expose that attribute
                chat_instance = Chat(llm_handler)

        Answer = chat_instance.chat_about_report(assessment_id=assessment_id, user_query=user_query)


        # Return the Answer directly without nesting it under 'result'
        # This matches the frontend's expectation of finding response.Result
        return jsonify(Answer)

    except Exception as e:
        logging.error(f"Error querying AI: {str(e)}")
        return jsonify({"error": f"Error querying AI: {str(e)}"}), 500

@app.route('/api/threat-model', methods=['GET'])
def generate_threat_model():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        # Get RAG results from storage
        rag_data = storage_handler.get_rag_result(assessment_id)
        if not rag_data:
            return jsonify({"error": "RAG results not found"}), 404

        rag_output = rag_data['result']

        # --- Load project details (details.json or session fallback) ---
        details_path = os.path.join(STORAGE_ROOT, assessment_id, 'details.json')
        custom_prompt = ""
        app_type = ""
        authentication_str = ""
        internet_facing = ""
        sensitive_data = ""

        if os.path.exists(details_path):
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)

                # Extract values from details.json
                app_type = details.get('applicationType', '')
                authentication_str = details.get('authenticationMethod', '')
                internet_facing = "Yes" if details.get('isInternetFacing', False) else "No"
                sensitive_data = details.get('dataSensitivityLevel', '')

                # Start the custom prompt from details
                custom_prompt = "Custom Prompt"
                logging.info(
                    f"Loaded project details from details.json: "
                    f"{app_type}, {authentication_str}, {internet_facing}, {sensitive_data}"
                )
            except Exception as e:
                logging.error(f"Error loading details.json: {str(e)}")
                # Fallback to session variables
                app_type = session.get('app_type', '')
                authentication_str = session.get('authentication_str', '')
                internet_facing = session.get('internet_facing', '')
                sensitive_data = session.get('sensitive_data', '')
        else:
            # Fallback to session variables if file doesn't exist
            logging.warning(
                f"details.json not found for assessment {assessment_id}, "
                f"falling back to session variables"
            )
            app_type = session.get('app_type', '')
            authentication_str = session.get('authentication_str', '')
            internet_facing = session.get('internet_facing', '')
            sensitive_data = session.get('sensitive_data', '')

        # --- Load additionalinfo.json for extra context (Confluence/Slack/meeting) ---
        additionalinfo_path = os.path.join(STORAGE_ROOT, assessment_id, 'additionalinfo.json')
        if os.path.exists(additionalinfo_path):
            try:
                with open(additionalinfo_path, 'r') as f:
                    additionalinfo = json.load(f)

                # Add Confluence content if available
                if additionalinfo.get('confluenceDoc') and additionalinfo['confluenceDoc'].get('content'):
                    custom_prompt += (
                        f"\n\nAdditional Confluence Content:\n"
                        f"{additionalinfo['confluenceDoc']['content']}"
                    )

                # Add Slack thread content if available
                if additionalinfo.get('slackThread') and additionalinfo['slackThread'].get('content'):
                    custom_prompt += (
                        f"\n\nSlack Thread Content:\n"
                        f"{additionalinfo['slackThread']['content']}"
                    )

                # Add meeting transcript if available
                if additionalinfo.get('meetingTranscript') and additionalinfo['meetingTranscript'].get('content'):
                    custom_prompt += (
                        f"\n\nMeeting Transcript:\n"
                        f"{additionalinfo['meetingTranscript']['content']}"
                    )

                logging.info("Added additional context from additionalinfo.json")
            except Exception as e:
                logging.error(f"Error loading additionalinfo.json: {str(e)}")
                # Try to get custom prompt from session as fallback
                session_custom_prompt = session.get('custom_prompt', '')
                if session_custom_prompt:
                    custom_prompt += f"\n\n{session_custom_prompt}"
        else:
            # Try to get custom prompt from session as fallback
            logging.warning(
                f"additionalinfo.json not found for assessment {assessment_id}, "
                f"checking session for custom prompt"
            )
            session_custom_prompt = session.get('custom_prompt', '')
            if session_custom_prompt:
                custom_prompt += f"\n\n{session_custom_prompt}"

        # Ensure custom_prompt is not None
        if custom_prompt is None:
            custom_prompt = ''
            logging.warning("Custom prompt was None, setting to empty string")

        # Log the custom prompt for debugging
        logging.info(f"Final custom prompt: {custom_prompt[:100]}...")

        # --- Organization context (settings.json) ---
        org_context = ""
        if os.path.exists('settings.json'):
            try:
                with open('settings.json', 'r') as f:
                    settings = json.load(f)
                org_context = settings.get('preContext', '')
                logging.info(
                    f"Loaded organization context from settings.json: {org_context[:100]}..."
                )
            except Exception as e:
                logging.error(f"Error loading organization context from settings.json: {str(e)}")

        # --- Methodology must be present in details.json ---
        methodology = None
        if os.path.exists(details_path):
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)

                methodology = details.get('threatModelingMethodology')
                if methodology:
                    logging.info(
                        f"Using threat modeling methodology from details.json: {methodology}"
                    )
                else:
                    error_msg = "No threat modeling methodology found in details.json"
                    logging.error(error_msg)
                    return jsonify({"error": error_msg}), 400
            except Exception as e:
                error_msg = f"Error reading methodology from details.json: {str(e)}"
                logging.error(error_msg)
                return jsonify({"error": error_msg}), 500
        else:
            error_msg = f"details.json not found for assessment {assessment_id}"
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 404

        # --- Choose LLM provider & build threat model ---
        llm_handler = get_llm_handler(assessment_id)
        threat_modeling_handler = ThreatModelingHandler(llm_handler)

        # Generate threat model (this will internally create the prompt)
        threat_model_result = threat_modeling_handler.generate_threat_model(
            app_type=app_type,
            authentication=authentication_str,
            internet_facing=internet_facing,
            sensitive_data=sensitive_data,
            app_input=rag_output,
            custom_prompt=custom_prompt,
            org_context=org_context,
            assessment_id=assessment_id
        )

        # Get the prompt that was actually used (for storage)
        threat_model_prompt = threat_modeling_handler.last_generated_prompt

        # --- Persist results in the same format the frontend expects ---
        storage_handler.save_threat_model(assessment_id, {
            "raw_response": {
                "threat_model": threat_model_result["threat_model"],
                "improvement_suggestions": threat_model_result["improvement_suggestions"]
            },
            "markdown": threat_model_result["markdown"]
        })

        logging.info(f"Prompt actually used for threat model: {threat_model_prompt}")

        # Initialize prompts storage if it doesn't exist
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}

        # Store the threat model prompt
        prompts_data["prompts"]["threat_model"] = threat_model_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])

        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": threat_model_result
        })

    except Exception as e:
        app.logger.error(f"Error generating threat model: {str(e)}")
        return jsonify({
            "error": "Failed to generate threat model",
            "details": str(e)
        }), 500


@app.route('/api/dread-assessment', methods=['GET'])
def generate_dread_assessment():
    """
    Risk scoring endpoint.

    - If details.json.riskScoringModel == 'CVSS'  → use CvssHandler + cvssSettings from settings.json
    - Otherwise (default)                         → use DreadHandler (existing behavior)

    For MVP1 this still returns under the same endpoint so the frontend
    doesn't have to change URLs – it just sees "Risk Scoring" results that
    may be DREAD or CVSS depending on how the assessment was configured.
    """
    try:
        # 1) Assessment ID
        assessment_id = request.args.get("assessment_id") or session.get("assessment_id")
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        # 2) Load threat model + attack tree from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        attack_tree_data = storage_handler.get_attack_tree(assessment_id)

        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404

        threat_raw = threat_model_data["result"]["raw_response"]
        attack_tree_raw = attack_tree_data["result"] if attack_tree_data else None

        # 3) Determine which risk model to use from details.json
        details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
        risk_model = "DREAD"  # default

        if os.path.exists(details_path):
            try:
                with open(details_path, "r") as f:
                    details = json.load(f)
                risk_model = (details.get("riskScoringModel") or "DREAD").upper()
            except Exception as e:
                logging.error(f"Error reading details.json for risk model: {e}")
        else:
            logging.warning(
                f"details.json not found for assessment {assessment_id}; "
                f"defaulting risk scoring to DREAD"
            )

        # 4) LLM provider (OpenAI / Bedrock)
        llm_handler = get_llm_handler(assessment_id)

        # 5) Existing prompts (or empty)
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}

        # -------------------------------
        # CVSS PATH
        # -------------------------------
        if risk_model == "CVSS":
            logging.info(f"Using CVSS risk scoring for assessment {assessment_id}")

            # Load global CVSS config from settings.json
            settings = load_settings()
            cvss_config = settings.get("cvssSettings", {}) or {}

            cvss_handler = CvssHandler(llm_handler)

            # Build prompt (if your CvssHandler exposes this)
            try:
                cvss_prompt = cvss_handler.create_cvss_assessment_prompt(
                    threat_model_result=threat_raw,
                    attack_tree_data=attack_tree_raw,
                    assessment_id=assessment_id,
                    cvss_config=cvss_config,
                )
            except TypeError:
                # If your implementation doesn't take cvss_config in the prompt builder:
                cvss_prompt = cvss_handler.create_cvss_assessment_prompt(
                    threat_model_result=threat_raw,
                    attack_tree_data=attack_tree_raw,
                    assessment_id=assessment_id,
                )

            # Generate CVSS assessment
            cvss_result = cvss_handler.generate_cvss_assessment(
                threat_model_result=threat_raw,
                attack_tree_data=attack_tree_raw,
                assessment_id=assessment_id,
                cvss_config=cvss_config,
            )

            # Store prompt under "cvss" for debugging / replay
            prompts_data["prompts"]["cvss"] = cvss_prompt
            storage_handler.save_prompts(assessment_id, prompts_data["prompts"])

            # For MVP1 we reuse the DREAD storage slot so other parts of the app keep working
            storage_handler.save_dread_assessment(assessment_id, cvss_result)

            return jsonify(
                {
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "result": cvss_result,
                }
            )

        # -------------------------------
        # DREAD PATH (existing behavior)
        # -------------------------------
        logging.info(f"Using DREAD risk scoring for assessment {assessment_id}")

        dread_handler = DreadHandler(llm_handler)

        dread_prompt = dread_handler.create_dread_assessment_prompt(
            threat_model_result=threat_raw,
            attack_tree_data=attack_tree_raw,
            assessment_id=assessment_id,
        )

        dread_result = dread_handler.generate_dread_assessment(
            threat_model_result=threat_raw,
            attack_tree_data=attack_tree_raw,
            assessment_id=assessment_id,
        )

        prompts_data["prompts"]["dread"] = dread_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])

        storage_handler.save_dread_assessment(assessment_id, dread_result)

        return jsonify(
            {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "result": dread_result,
            }
        )

    except Exception as e:
        logging.error(f"Error generating risk assessment (DREAD/CVSS): {str(e)}")
        return jsonify(
            {"error": f"Error generating risk assessment (DREAD/CVSS): {str(e)}"}
        ), 500


@app.route('/api/mitigations', methods=['GET'])
def generate_mitigations():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model, attack tree, and DREAD data from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        attack_tree_data = storage_handler.get_attack_tree(assessment_id)
        dread_data = storage_handler.get_dread_assessment(assessment_id)
        
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        # Choose LLM provider
        llm_handler = get_llm_handler(assessment_id)

        # Generate mitigations
        mitigation_handler = MitigationHandler(llm_handler)
        
        # Create the prompt for mitigations
        mitigation_prompt = mitigation_handler.create_mitigations_prompt(
            threat_model_data['result']['raw_response'],
            attack_tree_data['result'] if attack_tree_data else None,
            dread_data['result'] if dread_data else None,
            assessment_id
        )
        
        # Generate mitigations
        result = mitigation_handler.generate_mitigations(
            threat_model_data['result']['raw_response'],
            attack_tree_data['result'] if attack_tree_data else None,
            dread_data['result'] if dread_data else None,
            assessment_id
        )
        
        # Get existing prompts or initialize new
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the mitigations prompt
        prompts_data["prompts"]["mitigation"] = mitigation_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Store mitigation results
        storage_handler.save_mitigation_result(assessment_id, result)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": result
        })
        
    except Exception as e:
        logging.error(f"Error generating mitigations: {str(e)}")
        return jsonify({
            "error": f"Error generating mitigations: {str(e)}"
        }), 500

@app.route('/api/attack-tree', methods=['GET'])
def generate_attack_tree():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        # Choose LLM provider
        llm_handler = get_llm_handler(assessment_id)

        # Generate attack tree
        attack_tree_handler = AttackTreeHandler(llm_handler)
        
        # Create the prompt for attack tree
        attack_tree_prompt = attack_tree_handler.create_attack_tree_prompt(threat_model_data['result']['raw_response'], assessment_id)
        
        # Generate attack tree
        result = attack_tree_handler.generate_attack_tree(threat_model_data['result']['raw_response'], assessment_id)
        
        # Get existing prompts or initialize new
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the attack tree prompt
        prompts_data["prompts"]["attack_tree"] = attack_tree_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Ensure the result has the expected structure for the frontend
        if "attack_tree" not in result:
            # Create a default structure if missing
            result["attack_tree"] = {
                "nodes": [
                    {
                        "id": "error",
                        "type": "goal",
                        "label": "Error generating attack tree"
                    }
                ]
            }
        
        # Format the markdown for display
        if "markdown" in result:
            result["markdown"] = f"```mermaid\n{result['markdown']}\n```"
        
        # Store attack tree results
        storage_handler.save_attack_tree(assessment_id, result)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": result
        })
        
    except Exception as e:
        logging.error(f"Error generating attack tree: {str(e)}")
        return jsonify({
            "error": f"Error generating attack tree: {str(e)}"
        }), 500

@app.route('/api/test-cases', methods=['GET'])
def generate_test_cases():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model and mitigations from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        mitigation_data = storage_handler.get_mitigation_result(assessment_id)
        
        # Choose LLM provider
        llm_handler = get_llm_handler(assessment_id)

        response = llm_handler.get_completion(prompt)
        
        # Generate test cases based on threat model and mitigations
        prompt = f"""
        Generate security test cases for the following threat model and mitigations:
        
        Threat Model:
        {json.dumps(threat_model_data['result']['raw_response'], indent=2)}
        
        Mitigations:
        {json.dumps(mitigation_data['result'] if mitigation_data else {}, indent=2)}
        
        For each test case, provide:
        1. A title
        2. A description
        3. Test steps
        4. Expected results
        5. Related threats
        6. Related mitigations
        7. Priority (High, Medium, Low)
        8. Type (Functional, Security, Performance)
        
        Also provide a coverage summary with:
        1. Total number of test cases
        2. Number of threats covered
        3. Total number of threats
        4. Number of mitigations verified
        
        Format the response as a JSON object with 'test_cases' and 'coverage_summary' keys.
        """
        
        response = openai_handler.get_completion(prompt)
        
        try:
            # Parse the JSON response
            result = json.loads(response)
            
            # Ensure the result has the expected structure
            if 'test_cases' not in result:
                result['test_cases'] = []
            if 'coverage_summary' not in result:
                result['coverage_summary'] = {
                    'total_test_cases': len(result.get('test_cases', [])),
                    'threats_covered': 0,
                    'total_threats': len(threat_model_data['result']['raw_response'].get('threat_model', [])),
                    'mitigations_verified': 0
                }
                
            # Store test cases results
            storage_handler.save_test_cases(assessment_id, result)
            
            # Return in the format expected by the frontend
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "result": result
            })
            
        except json.JSONDecodeError:
            # If the response is not valid JSON, create a structured response
            logging.error("Failed to parse test cases response as JSON")
            result = {
                'test_cases': [],
                'coverage_summary': {
                    'total_test_cases': 0,
                    'threats_covered': 0,
                    'total_threats': len(threat_model_data['result']['raw_response'].get('threat_model', [])),
                    'mitigations_verified': 0
                },
                'raw_response': response
            }
            # Return in the format expected by the frontend
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "result": result
            })
        
    except Exception as e:
        logging.error(f"Error generating test cases: {str(e)}")
        return jsonify({
            "error": f"Error generating test cases: {str(e)}"
        }), 500
    
@app.route('/api/store-details', methods=['POST'])
def store_details():
    try:
        data = request.get_json()
        assessment_id = data.get('assessment_id')
        details = data.get('details')
        
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        if not details:
            return jsonify({"error": "Details are required"}), 400
            
        # Create the directory if it doesn't exist
        storage_dir = os.path.join(STORAGE_ROOT, assessment_id)
        os.makedirs(storage_dir, exist_ok=True)

        # Write the details to a JSON file
        details_file_path = os.path.join(storage_dir, 'details.json')
        with open(details_file_path, 'w') as f:
            json.dump(details, f, indent=2)
            
        return jsonify({
            "message": "Details stored successfully",
            "file_path": details_file_path
        })
        
    except Exception as e:
        logging.error(f"Error storing details: {str(e)}")
        return jsonify({
            "error": f"Error storing details: {str(e)}"
        }), 500

@app.route('/api/validate-connections', methods=['POST'])
def validate_connections():
    """
    Validate connections to external services like Confluence and Slack.
    """
    try:
        data = request.get_json()
        
        # Initialize response
        response = {
            "confluence": {"valid": True, "message": ""},
            "slack": {"valid": True, "message": ""}
        }
        
        # Validate Confluence connection if URL provided
        confluence_url = data.get('confluence_url')
        if confluence_url:
            # Basic URL validation
            try:
                parsed_url = urlparse(confluence_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    response["confluence"] = {"valid": False, "message": "Invalid Confluence URL format"}
                else:
                    # Test connection using credentials from .env file
                    success, message = test_confluence_connection(confluence_url)
                    response["confluence"] = {"valid": success, "message": message}
            except Exception as e:
                response["confluence"] = {"valid": False, "message": f"Invalid Confluence URL: {str(e)}"}
        
        # Validate Slack connection if URL provided
        slack_url = data.get('slack_url')
        if slack_url:
            # Basic URL validation
            try:
                parsed_url = urlparse(slack_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    response["slack"] = {"valid": False, "message": "Invalid Slack URL format"}
                else:
                    # Test connection using credentials from .env file
                    success, message = test_slack_connection(slack_url)
                    response["slack"] = {"valid": success, "message": message}
            except Exception as e:
                response["slack"] = {"valid": False, "message": f"Invalid Slack URL: {str(e)}"}
        
        return jsonify(response)
        
    except Exception as e:
        logging.error(f"Error validating connections: {str(e)}")
        return jsonify({
            "error": f"Error validating connections: {str(e)}"
        }), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        # Check if settings.json exists
        if os.path.exists('settings.json'):
            with open('settings.json', 'r') as f:
                settings = json.load(f)
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data": settings
            })
        else:
            # Return default settings if file doesn't exist
            default_settings = {
                "preContext": ""
            }
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data": default_settings
            })
    except Exception as e:
        logging.error(f"Error getting settings: {str(e)}")
        return jsonify({
            "error": f"Error getting settings: {str(e)}"
        }), 500

@app.route('/api/settings', methods=['POST'])
def save_settings():
    try:
        # Get settings from request
        settings = request.get_json()
        
        # Save settings to settings.json
        with open('settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
            
        return jsonify({
            "message": "Settings saved successfully",
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        logging.error(f"Error saving settings: {str(e)}")
        return jsonify({
            "error": f"Error saving settings: {str(e)}"
        }), 500

@app.route('/api/threat-model/<assessment_id>', methods=['DELETE'])
def delete_threat_model(assessment_id):
    # Check for admin cookie
    admin_cookie = request.cookies.get('admin')
    if not admin_cookie or admin_cookie.lower() != 'true':
        return jsonify({"error": "Unauthorized. Admin privileges required"}), 403
        
    try:
        # Delete from storage directory
        assessment_dir = os.path.join(STORAGE_ROOT, assessment_id)
        if os.path.exists(assessment_dir):
            import shutil
            shutil.rmtree(assessment_dir)
            
        # Delete from uploads directory
        upload_dirs = [
            os.path.join('uploads', f"{assessment_id}_files"),
            os.path.join('uploads', f"persist_{assessment_id}")
        ]
        for upload_dir in upload_dirs:
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)
                
        return jsonify({"message": f"Threat model {assessment_id} deleted successfully"})
    except Exception as e:
        logging.error(f"Error deleting threat model: {str(e)}")
        return jsonify({"error": f"Error deleting threat model: {str(e)}"}), 500

@app.route("/api/storage",methods=['GET'])
def access_storage():
    try:
        assessment_id = request.args.get('assessment_id')
        assessment_name = request.args.get('assessment_name')
        
        # If no assessment_id is provided, return list of all assessments
        if not assessment_id:
            assessments = storage_handler.retrive_from_storage()
            
            # For each assessment, try to read and include details.json
            for assessment in assessments:
                try:
                    details_path = os.path.join(STORAGE_ROOT, assessment['id'], 'details.json')
                    if os.path.exists(details_path):
                        with open(details_path, 'r') as f:
                            details = json.load(f)
                            assessment['details'] = details
                except Exception as e:
                    logging.error(f"Error reading details for assessment {assessment['id']}: {str(e)}")
                    assessment['details'] = None
            
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data": assessments
            })
        
        # If assessment_id is provided but no assessment_name, return error
        if not assessment_name:
            return jsonify({"error": "Assessment name is required when assessment ID is provided"}), 400
            
        # Get specific assessment data from storage
        retrieved_data = storage_handler.retrive_from_storage(assessment_id=assessment_id, assessment_name=assessment_name)
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": retrieved_data
        })
    except ValueError as e:
        logging.error(f"Invalid request: {str(e)}")
        return jsonify({
            "error": f"Invalid request: {str(e)}"
        }), 400
    except Exception as e:
        logging.error(f"Error retrieving data: {str(e)}")
        return jsonify({
            "error": f"Error retrieving data: {str(e)}"
        }), 500


@app.route('/api/report/download-json', methods=['GET'])
def download_combined_json():
    try:
        assessment_id = request.args.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Create the combined JSON structure
        combined_data = {
            "Info": {},
            "threatmodel": {},
            "attacktree": {},
            "dread": {},
            "mitigations": {}
        }
        
        # Load details.json
        details_path = os.path.join(STORAGE_ROOT, assessment_id, 'details.json')
        if os.path.exists(details_path):
            with open(details_path, 'r') as f:
                combined_data["Info"] = json.load(f)
        
        # Load threat_model.json
        threat_model_path = os.path.join(STORAGE_ROOT, assessment_id, 'threat_model.json')
        if os.path.exists(threat_model_path):
            with open(threat_model_path, 'r') as f:
                combined_data["threatmodel"] = json.load(f)
        
        # Load attack_tree.json
        attack_tree_path = os.path.join(STORAGE_ROOT, assessment_id, 'attack_tree.json')
        if os.path.exists(attack_tree_path):
            with open(attack_tree_path, 'r') as f:
                combined_data["attacktree"] = json.load(f)
        
        # Load dread_assessment.json
        dread_path = os.path.join(STORAGE_ROOT, assessment_id, 'dread_assessment.json')
        if os.path.exists(dread_path):
            with open(dread_path, 'r') as f:
                combined_data["dread"] = json.load(f)
        
        # Load mitigation.json
        mitigation_path = os.path.join(STORAGE_ROOT, assessment_id, 'mitigation.json')
        if os.path.exists(mitigation_path):
            with open(mitigation_path, 'r') as f:
                combined_data["mitigations"] = json.load(f)
        
        # Return as downloadable JSON file
        response = Response(
            json.dumps(combined_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=threat-shield-report-{assessment_id}.json'
            }
        )
        return response
        
    except Exception as e:
        logging.error(f"Error generating combined JSON: {str(e)}")
        return jsonify({
            "error": f"Error generating combined JSON: {str(e)}"
        }), 500

@app.route("/api/design-objectives", methods=["POST", "OPTIONS"])
@app.route("/api/design-objectives/alignment", methods=["POST", "OPTIONS"])
def api_design_objectives():
    from flask import request, jsonify

    # --- 1) Handle CORS preflight early ---
    if request.method == "OPTIONS":
        # Flask-CORS will attach Access-Control-Allow-Origin headers
        return ("", 204)

    # --- 2) Parse POST body safely ---
    data = request.get_json(silent=True) or {}

    assessment_id = data.get("assessment_id")
    architecture_context = data.get("architecture_context", "") or ""
    objectives_config = data.get("objectives") or {}

    # --- 3) Validate required fields ---
    if not assessment_id:
        return jsonify({"error": "assessment_id is required"}), 400

    if not architecture_context.strip():
        return jsonify({"error": "architecture_context is required"}), 400

    # --- 4) Run alignment handler using your existing abstraction ---
    llm_handler = get_llm_handler(assessment_id)
    do_handler = DesignObjectiveAlignmentHandler(llm_handler)

    result = do_handler.generate_alignment(
        architecture_context=architecture_context,
        objectives_config=objectives_config,
        assessment_id=assessment_id,
    )

    # --- 5) Return normalized JSON response ---
    return jsonify(result), 200



app.run(debug=True, host='0.0.0.0', port=5001)