import json
import logging
import os
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---- Shared storage root (Render disk or local) ----
DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")


class DreadHandler:
    def __init__(self, openai_handler):
        """
        openai_handler can be:
        - OpenAIHandler  (OpenAI)
        - BedrockHandler (AWS Bedrock Llama/Claude)
        Both expose: method, model, get_completion(prompt)
        """
        self.openai_handler = openai_handler
        self.method = openai_handler.method
        self.prompt_manager = PromptManager()

    # -------------------------------------------------------------------------
    # Build prompt
    # -------------------------------------------------------------------------
    def create_dread_assessment_prompt(self, threat_model_result, attack_tree_data, assessment_id=None):
        if not assessment_id:
            raise ValueError("Assessment ID is required to determine the threat modeling methodology")

        # Load methodology
        methodology = self._get_methodology_from_details(assessment_id)
        logging.info(f"Using threat modeling methodology from details.json for DREAD assessment: {methodology}")

        prompt_data = self.prompt_manager.get_prompt("dread_assessment")
        threats = threat_model_result.get('threat_model', [])

        # Build formatted threat descriptions
        threat_descriptions = []
        for t in threats:
            threat_descriptions.append(
                f"Threat Type: {t.get('Threat Type','')}\n"
                f"Scenario: {t.get('Scenario','')}\n"
                f"Potential Impact: {t.get('Potential Impact','')}"
            )
        formatted_threats = "\n\n".join(threat_descriptions)

        attack_tree_context = ""
        if attack_tree_data and "attack_tree" in attack_tree_data:
            attack_tree_context = f"\n\nAttack Tree Analysis:\n{json.dumps(attack_tree_data['attack_tree'], indent=2)}"

        # Bedrock needs VERY strict JSON enforcement
        json_instructions = ""
        if self.method == "BEDROCK":
            json_instructions = """
IMPORTANT: Respond ONLY with valid JSON. 
NO markdown. NO commentary. NO explanation.
Response MUST contain the key "Risk Assessment" as an array.
"""

        prompt = f"""
{json_instructions}
{prompt_data.system_context}
{prompt_data.task}

Below is the list of identified threats:

{formatted_threats}

{attack_tree_context}

{prompt_data.instructions}

Example of expected JSON response format:
{json.dumps(prompt_data.format.get("example", {}), indent=2)}
"""
        return prompt

    # -------------------------------------------------------------------------
    # Clean JSON for Bedrock / OpenAI
    # -------------------------------------------------------------------------
    def clean_json_response(self, text):
        text = text.replace("```json", "").replace("```", "").strip()

        # Try to cut leading junk
        if text and text[0] not in ["{", "["]:
            start = text.find("{")
            if start >= 0:
                text = text[start:]

        # Remove trailing junk
        end = text.rfind("}")
        if end > 0:
            text = text[: end + 1]

        # Fix trailing commas
        text = text.replace(",}", "}").replace(",]", "]")

        # Remove comments
        import re
        text = re.sub(r"//.*?\n", "\n", text)

        return text

    # -------------------------------------------------------------------------
    # Main LLM call (Unified API)
    # -------------------------------------------------------------------------
    def get_dread_assessment(self, prompt):
        """
        Call the LLM using the unified handler:
        - For OpenAI → get_completion() produces correct JSON (format enforced)
        - For Bedrock → get_completion() calls invoke_model and returns text
        """
        logging.info(f"Generating DREAD assessment using {self.method}")

        try:
            response_text = self.openai_handler.get_completion(prompt, max_tokens=8000)

            logging.info(f"Raw DREAD text length: {len(response_text)}")
            cleaned = self.clean_json_response(response_text)

            try:
                parsed = json.loads(cleaned)
                if "Risk Assessment" not in parsed:
                    parsed["Risk Assessment"] = []
                return parsed

            except json.JSONDecodeError as e:
                logging.error(f"JSON parse failed: {str(e)}")
                logging.error(f"Original response: {response_text}")
                return {
                    "Risk Assessment": [
                        {
                            "Threat Type": "Parsing Error",
                            "Scenario": f"Could not parse JSON: {str(e)}",
                            "Damage Potential": 0,
                            "Reproducibility": 0,
                            "Exploitability": 0,
                            "Affected Users": 0,
                            "Discoverability": 0
                        }
                    ]
                }

        except Exception as e:
            logging.error(f"Error generating DREAD assessment with {self.method}: {str(e)}")
            return {
                "Risk Assessment": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed calling provider {self.method}: {str(e)}",
                        "Damage Potential": 0,
                        "Reproducibility": 0,
                        "Exploitability": 0,
                        "Affected Users": 0,
                        "Discoverability": 0
                    }
                ]
            }

    # -------------------------------------------------------------------------
    def _get_methodology_from_details(self, assessment_id):
        details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
        logging.info(f"[DREAD] Looking for details.json at: {details_path}")

        if not os.path.exists(details_path):
            raise ValueError(f"details.json not found for assessment {assessment_id}")

        with open(details_path, "r") as f:
            details = json.load(f)

        methodology = details.get("threatModelingMethodology")
        if not methodology:
            raise ValueError(f"No threatModelingMethodology found in details.json for {assessment_id}")

        return methodology

    # -------------------------------------------------------------------------
    def json_to_markdown(self, dread_assessment, assessment_id=None):
        md = "\n\n## DREAD Risk Assessment\n\n"
        md += (
            "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | "
            "Affected Users | Discoverability | Risk Score |\n"
        )
        md += (
            "|-------------|----------|------------------|-----------------|----------------|"
            "----------------|-----------------|-------------|\n"
        )

        try:
            threats = dread_assessment.get("Risk Assessment", [])
            for t in threats:
                dp = t.get("Damage Potential", 0)
                rp = t.get("Reproducibility", 0)
                ep = t.get("Exploitability", 0)
                au = t.get("Affected Users", 0)
                dc = t.get("Discoverability", 0)

                score = (dp + rp + ep + au + dc) / 5

                md += (
                    f"| {t.get('Threat Type','N/A')} | {t.get('Scenario','N/A')} | "
                    f"{dp} | {rp} | {ep} | {au} | {dc} | {score:.2f} |\n"
                )

        except Exception as e:
            logging.error(f"Error converting to markdown: {str(e)}")

        return md

    # -------------------------------------------------------------------------
    def generate_dread_assessment(self, threat_model_result, attack_tree_data=None, assessment_id=None):
        logging.info("Generating DREAD assessment...")
        prompt = self.create_dread_assessment_prompt(threat_model_result, attack_tree_data, assessment_id)
        result = self.get_dread_assessment(prompt)
        return {"raw_response": result}
