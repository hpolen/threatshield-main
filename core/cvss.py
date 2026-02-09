import json
import logging
import os
from typing import Any, Dict, Optional

from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ---- Shared storage root (Render disk or local) ----
DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")


class CvssHandler:
    """
    CVSS v4.0 assessment handler.

    This mirrors DreadHandler but focuses on CVSS base scoring.
    It delegates actual scoring logic to the LLM via PromptManager prompts.

    The expected prompt key in PromptManager is: "cvss_assessment"
    and should define:
      - system_context
      - task
      - instructions
      - format.example   (example of JSON output)
    """

    def __init__(self, llm_handler):
        """
        llm_handler can be:
        - OpenAIHandler  (OpenAI)
        - BedrockHandler (AWS Bedrock Llama/Claude)
        Both expose: method, model, get_completion(prompt)
        """
        self.llm_handler = llm_handler
        self.method = llm_handler.method
        self.prompt_manager = PromptManager()

    # -------------------------------------------------------------------------
    # Build prompt
    # -------------------------------------------------------------------------
    def create_cvss_assessment_prompt(
        self,
        threat_model_result: Dict[str, Any],
        attack_tree_data: Optional[Dict[str, Any]] = None,
        assessment_id: Optional[str] = None,
        cvss_config: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not assessment_id:
            raise ValueError("Assessment ID is required to determine the threat modeling methodology")

        # Load methodology from details.json (same as DREAD does)
        methodology = self._get_methodology_from_details(assessment_id)
        logging.info(
            f"Using threat modeling methodology from details.json for CVSS assessment: {methodology}"
        )

        prompt_data = self.prompt_manager.get_prompt("cvss_assessment")
        threats = threat_model_result.get("threat_model", [])

        # Build formatted threat descriptions
        threat_descriptions = []
        for t in threats:
            threat_descriptions.append(
                f"Threat ID: {t.get('id', t.get('Threat ID', ''))}\n"
                f"Threat Type: {t.get('Threat Type', '')}\n"
                f"Scenario: {t.get('Scenario', '')}\n"
                f"Assets: {t.get('Assets', '')}\n"
                f"Potential Impact: {t.get('Potential Impact', '')}\n"
                f"STRIDE Category: {t.get('STRIDE Category', t.get('stride', ''))}"
            )

        formatted_threats = "\n\n".join(threat_descriptions)

        attack_tree_context = ""
        if attack_tree_data and "attack_tree" in attack_tree_data:
            attack_tree_context = (
                "\n\nAttack Tree Context (optional, use only if helpful for scoring):\n"
                f"{json.dumps(attack_tree_data['attack_tree'], indent=2)}"
            )

        # Config: cvss_config comes from settings.json; include it in the prompt so the
        # LLM understands org-specific scoring rules (severity bands, assumptions, etc.)
        config_context = ""
        if cvss_config:
            try:
                pretty_cfg = json.dumps(cvss_config, indent=2)
            except TypeError:
                pretty_cfg = str(cvss_config)

            config_context = f"""
Organization CVSS Configuration (from settings.json):

{pretty_cfg}

The model MUST honor these configuration values when computing CVSS metrics and severity.
"""

        # Bedrock needs VERY strict JSON enforcement
        json_instructions = ""
        if self.method == "BEDROCK":
            json_instructions = """
IMPORTANT: Respond ONLY with valid JSON.
NO markdown. NO commentary. NO explanation outside of JSON.
The response MUST be valid JSON that can be parsed by a strict JSON parser.
"""

        # Expected JSON example from prompt config
        example_json = "{}"
        try:
            example_json = json.dumps(self.prompt_manager.get_prompt("cvss_assessment").format.get("example", {}), indent=2)
        except Exception:
            pass

        prompt = f"""
{json_instructions}
{prompt_data.system_context}

You are performing CVSS v4.0 BASE scoring for threats in a threat model.
Threat modeling methodology in use: {methodology}

{config_context}

{prompt_data.task}

Below is the list of identified threats:

{formatted_threats}

{attack_tree_context}

{prompt_data.instructions}

Example of expected JSON response format:
{example_json}
"""
        return prompt

    # -------------------------------------------------------------------------
    # Clean JSON for Bedrock / OpenAI
    # -------------------------------------------------------------------------
    def clean_json_response(self, text: str) -> str:
        text = text.replace("```json", "").replace("```", "").strip()

        # Try to trim leading junk
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

        # Remove JS-style comments
        import re

        text = re.sub(r"//.*?\n", "\n", text)

        return text

    # -------------------------------------------------------------------------
    # Main LLM call (Unified API)
    # -------------------------------------------------------------------------
    def get_cvss_assessment(self, prompt: str) -> Dict[str, Any]:
        """
        Call the LLM using the unified handler:
        - For OpenAI → get_completion() produces correct JSON (format enforced)
        - For Bedrock → get_completion() calls invoke_model and returns text
        """
        logging.info(f"Generating CVSS assessment using {self.method}")

        try:
            response_text = self.llm_handler.get_completion(prompt, max_tokens=8000)

            logging.info(f"Raw CVSS text length: {len(response_text)}")
            cleaned = self.clean_json_response(response_text)

            try:
                parsed = json.loads(cleaned)

                # Normalize shape a bit so callers can rely on keys
                if "cvss_results" not in parsed and "threats" in parsed:
                    # If the prompt config uses 'threats', alias it to 'cvss_results'
                    parsed["cvss_results"] = parsed.get("threats", [])

                if "cvss_results" not in parsed:
                    parsed["cvss_results"] = []

                # Ensure CVSS version is always present
                parsed.setdefault("cvss_version", "4.0")

                return parsed

            except json.JSONDecodeError as e:
                logging.error(f"JSON parse failed for CVSS: {str(e)}")
                logging.error(f"Original response: {response_text}")
                return {
                    "cvss_version": "4.0",
                    "cvss_results": [
                        {
                            "threat_id": "PARSE_ERROR",
                            "title": "Parsing Error",
                            "scenario": f"Could not parse JSON: {str(e)}",
                            "cvss_vector": "",
                            "base_score": 0.0,
                            "severity": "None",
                            "metrics": {},
                            "rationale": "Fallback result when JSON parsing fails."
                        }
                    ]
                }

        except Exception as e:
            logging.error(f"Error generating CVSS assessment with {self.method}: {str(e)}")
            return {
                "cvss_version": "4.0",
                "cvss_results": [
                    {
                        "threat_id": "PROVIDER_ERROR",
                        "title": "Provider Error",
                        "scenario": f"Failed calling provider {self.method}: {str(e)}",
                        "cvss_vector": "",
                        "base_score": 0.0,
                        "severity": "None",
                        "metrics": {},
                        "rationale": "Fallback result when the LLM provider fails."
                    }
                ]
            }

    # -------------------------------------------------------------------------
    def _get_methodology_from_details(self, assessment_id: str) -> str:
        details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
        logging.info(f"[CVSS] Looking for details.json at: {details_path}")

        if not os.path.exists(details_path):
            raise ValueError(f"details.json not found for assessment {assessment_id}")

        with open(details_path, "r") as f:
            details = json.load(f)

        methodology = details.get("threatModelingMethodology")
        if not methodology:
            raise ValueError(f"No threatModelingMethodology found in details.json for {assessment_id}")

        return methodology

    # -------------------------------------------------------------------------
    def json_to_markdown(self, cvss_assessment: Dict[str, Any], assessment_id: Optional[str] = None) -> str:
        """
        Convert CVSS JSON results into a markdown table, similar in spirit to DREAD.
        """
        md = "\n\n## CVSS v4.0 Risk Assessment\n\n"
        md += (
            "| Threat ID | Title | Scenario | CVSS Vector | Base Score | Severity |\n"
        )
        md += (
            "|-----------|-------|----------|-------------|------------|----------|\n"
        )

        try:
            results = cvss_assessment.get("cvss_results", [])
            for r in results:
                md += (
                    f"| {r.get('threat_id', 'N/A')} | "
                    f"{r.get('title', 'N/A')} | "
                    f"{(r.get('scenario', 'N/A') or '').replace('|', '\\|')} | "
                    f"{r.get('cvss_vector', 'N/A')} | "
                    f"{r.get('base_score', 0)} | "
                    f"{r.get('severity', 'N/A')} |\n"
                )

        except Exception as e:
            logging.error(f"Error converting CVSS results to markdown: {str(e)}")

        return md

    # -------------------------------------------------------------------------
    def generate_cvss_assessment(
        self,
        threat_model_result: Dict[str, Any],
        attack_tree_data: Optional[Dict[str, Any]] = None,
        assessment_id: Optional[str] = None,
        cvss_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Top-level method used by app.py:
          - builds prompt
          - calls LLM
          - returns normalized result wrapped in { "raw_response": ... }
        """
        logging.info("Generating CVSS assessment...")
        prompt = self.create_cvss_assessment_prompt(
            threat_model_result,
            attack_tree_data,
            assessment_id=assessment_id,
            cvss_config=cvss_config,
        )
        result = self.get_cvss_assessment(prompt)
        return {"raw_response": result}
