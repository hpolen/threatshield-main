import json
import logging
import os
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---- Shared storage root (Render disk or local) ----
DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root-ish when local
)
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")


class MitigationHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        # client is kept for backwards compatibility (not used for Bedrock)
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()

    def _get_methodology_from_details(self, assessment_id):
        """
        Get the methodology from details.json for the given assessment_id.
        Raises an error if details.json doesn't exist or doesn't contain the methodology.
        """
        details_path = os.path.join(STORAGE_ROOT, assessment_id, 'details.json')
        logging.info(f"[Mitigation] Looking for details.json at: {details_path}")

        if not os.path.exists(details_path):
            error_msg = f"details.json not found for assessment {assessment_id}"
            logging.error(error_msg)
            raise ValueError(error_msg)
            
        try:
            with open(details_path, 'r') as f:
                details = json.load(f)
                methodology = details.get('threatModelingMethodology')
                if not methodology:
                    error_msg = f"No threat modeling methodology found in details.json for assessment {assessment_id}"
                    logging.error(error_msg)
                    raise ValueError(error_msg)
                return methodology
        except Exception as e:
            error_msg = f"Error reading methodology from details.json: {str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
    
    def create_mitigations_prompt(self, threat_model_result, attack_tree_data=None, dread_data=None, assessment_id=None):
        """
        Create prompt for generating mitigations using threats from threat model, attack tree, and DREAD assessment.
        (Same signature as original working version.)
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json for mitigations: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the mitigations prompt template from prompts.json ("mitigations" key)
        prompt_data = self.prompt_manager.get_prompt("mitigations")
        
        threats = threat_model_result.get('threat_model', [])
        
        # Format threats for mitigation analysis
        threat_descriptions = []
        for threat in threats:
            threat_type = threat.get('Threat Type', '')
            scenario = threat.get('Scenario', '')
            impact = threat.get('Potential Impact', '')
            threat_descriptions.append(
                f"Threat Type: {threat_type}\n"
                f"Scenario: {scenario}\n"
                f"Potential Impact: {impact}"
            )
        
        formatted_threats = "\n\n".join(threat_descriptions)
        
        # Add attack tree data if available
        attack_tree_context = ""
        if attack_tree_data and 'attack_tree' in attack_tree_data:
            attack_tree = attack_tree_data['attack_tree']
            attack_tree_context = f"\n\nAttack Tree Analysis:\n{json.dumps(attack_tree, indent=2)}"
            
        # Add DREAD assessment data if available
        dread_context = ""
        if dread_data and 'raw_response' in dread_data:
            dread_assessment = dread_data['raw_response']
            dread_context = f"\n\nDREAD Risk Assessment:\n{json.dumps(dread_assessment, indent=2)}"

        # Example format from prompts.json
        example_format = json.dumps(prompt_data.format.get("example", {}), indent=2)

        # Extra JSON strictness for Bedrock
        json_instructions = ""
        if self.openai_handler.method == "BEDROCK":
            json_instructions = """
IMPORTANT:
- Respond ONLY with valid JSON.
- Do NOT include markdown code fences, prose, or explanations outside the JSON.
- The JSON must include a top-level key "mitigations" with an array of items.
"""

        prompt = f"""
{prompt_data.system_context} {prompt_data.task}

{json_instructions}

EXPECTED JSON ITEM FORMAT (per threat, example only):
{example_format}

Below is the list of identified threats:
{formatted_threats}

{attack_tree_context}

{dread_context}

{prompt_data.instructions}

YOUR RESPONSE:
- MUST be valid JSON
- MUST have a top-level key "mitigations"
- MUST map each threat (Threat Type + Scenario) to one or more mitigation strings
- DO NOT wrap the JSON in a code block.
"""
        return prompt

    def clean_json_response(self, text):
        """
        Clean the response text to handle potential JSON formatting issues.
        """
        # Remove any markdown code block indicators
        text = text.replace("```json", "").replace("```", "")
        
        # Trim whitespace
        text = text.strip()
        
        # If the text starts with a non-JSON character, try to find the start of the JSON
        if text and text[0] not in ['{', '[']:
            json_start = text.find('{')
            if json_start >= 0:
                text = text[json_start:]
        
        # If the text ends with a non-JSON character, try to find the end of the JSON
        if text and text[-1] not in ['}', ']']:
            json_end = text.rfind('}')
            if json_end >= 0:
                text = text[json_end+1:]
        
        # Remove any trailing commas before closing brackets (common JSON parsing error)
        text = text.replace(",}", "}")
        text = text.replace(",]", "]")
        
        # Remove any comments (which are not valid JSON)
        import re
        text = re.sub(r'//.*?\n', '\n', text)  # Remove single-line comments
        
        logging.debug(
            f"Cleaned JSON text: {text[:200]}..."
            if len(text) > 200
            else f"Cleaned JSON text: {text}"
        )
        return text

    def get_mitigations(self, prompt):
        """
        Get mitigations from LLM (OpenAI or Bedrock) using the unified get_completion().
        Returns the raw JSON string (same behavior as original code).
        """
        method = self.openai_handler.method
        logging.info(f"Generating mitigations using {method}")
        
        try:
            # System-style instructions; we embed them into a single prompt string
            base_system_message = """You are a helpful assistant that provides threat mitigation strategies in JSON format.
Your response MUST be valid, parseable JSON and MUST include a top-level key "mitigations"
containing an array of mitigation items. Each item should include the threat type, scenario,
and an array of mitigation strings."""
            
            if method == 'BEDROCK':
                base_system_message += """
Additional rules for Bedrock:
- Do NOT use markdown formatting or code fences.
- Output ONLY JSON, nothing before or after the JSON object.
"""

            # Combine into one prompt for the unified get_completion() API
            full_prompt = f"""SYSTEM INSTRUCTIONS:
{base_system_message}

USER + CONTEXT PROMPT:
{prompt}
"""

            # Call the handler's get_completion (works for OPENAI and BEDROCK)
            response_text = self.openai_handler.get_completion(full_prompt, max_tokens=8000)

            logging.info(f"Mitigation model response length: {len(response_text)}")
            logging.debug(
                f"Mitigation response preview: {response_text[:200]}..."
                if len(response_text) > 200
                else f"Mitigation response: {response_text}"
            )
            
            # Clean the response text to handle potential formatting issues
            cleaned_text = self.clean_json_response(response_text)
            return cleaned_text
            
        except Exception as e:
            logging.error(f"Error generating mitigations with {method}: {str(e)}")
            # Keep original fallback shape
            return """{
  "mitigations": [
    {
      "Threat Type": "Error",
      "Scenario": "Failed to generate mitigations",
      "Mitigations": ["Please try again"]
    }
  ]
}"""

    def generate_mitigations(self, threat_model_result, attack_tree_data, dread_data, assessment_id=None):
        """
        Generate mitigations for threats identified in the threat model, considering attack tree and DREAD data.
        (Same signature as original working version.)
        """
        logging.info("Generating mitigations")
        
        # Determine which methodology to use from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            methodology = self._get_methodology_from_details(assessment_id)
            logging.info(
                f"Using threat modeling methodology from details.json for mitigations processing: {methodology}"
            )
        
        # Create the prompt using all available data
        prompt = self.create_mitigations_prompt(
            threat_model_result,
            attack_tree_data,
            dread_data,
            assessment_id
        )
        
        # Get the mitigations
        mitigations_json_str = self.get_mitigations(prompt)
        
        try:
            # Parse the JSON response
            mitigations_data = json.loads(mitigations_json_str)
            
            # Validate the response structure
            if "mitigations" not in mitigations_data:
                logging.warning("Response missing 'mitigations' field, attempting to fix structure")
                if isinstance(mitigations_data, dict):
                    for key, value in mitigations_data.items():
                        if isinstance(value, list) and value:
                            logging.info(f"Found potential mitigations in key '{key}'")
                            mitigations_data = {"mitigations": value}
                            break
                    else:
                        mitigations_data = {"mitigations": []}
                else:
                    mitigations_data = {"mitigations": []}
            
            # Return only the raw JSON data (same as original)
            return {
                "raw_response": mitigations_data
            }

        except json.JSONDecodeError as e:
            logging.error(f"Error parsing mitigations JSON: {str(e)}")
            logging.error(f"Raw JSON string: {mitigations_json_str[:500]}...")
            # Return a fallback response
            return {
                "raw_response": {
                    "mitigations": [
                        {
                            "Threat Type": "Error",
                            "Scenario": "Failed to parse mitigations JSON",
                            "Mitigations": ["Please try again"]
                        }
                    ]
                }
            }
