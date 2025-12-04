import json
import logging
import os
from rag.rag_handler import PromptManager

# ---- Shared storage root (Render disk or local) ----
DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root-ish when local
)
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")

logger = logging.getLogger(__name__)


class DesignObjectiveAlignmentHandler:
    """
    Perform architecture review and design objective alignment.
    This is intentionally separate from ThreatShield's threat model / DREAD flows.
    It can be used standalone with its own artifacts (architecture diagrams, design notes, etc.).

    Works with BOTH:
    - OpenAI (method = 'OPENAI')
    - Bedrock (method = 'BEDROCK', via unified openai_handler.get_completion())
    """

    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.prompt_manager = PromptManager()
        self.last_generated_prompt = None

    # ---------------------------------------------------------------------
    # Defaults & helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _default_objectives():
        """
        Canonical six design objectives with default descriptions.
        These can be overridden/extended by the caller via objectives_config.
        """
        return {
            "Maintainability": {
                "description": "Ease of changing, debugging, and evolving the system over time.",
            },
            "Availability": {
                "description": "Uptime, resilience, and ability to withstand failures.",
            },
            "Scalability": {
                "description": "Ability to handle growth in traffic, data, or usage without major redesign.",
            },
            "Security": {
                "description": "Protection of confidentiality, integrity, and availability of data and services.",
            },
            "Data Integrity": {
                "description": "Accuracy, consistency, and correctness of data across components and over time.",
            },
            "System Integration": {
                "description": "How well components and external systems fit together, including interfaces and contracts.",
            },
        }

    def clean_json_response(self, text: str) -> str:
        """
        Clean the response text to handle potential JSON formatting issues.
        """
        # Remove markdown fences
        text = text.replace("```json", "").replace("```", "")

        # Trim whitespace
        text = text.strip()

        # If the text starts with a non-JSON character, try to find the start
        if text and text[0] not in ["{", "["]:
            json_start = text.find("{")
            if json_start >= 0:
                text = text[json_start:]

        # If the text ends with a non-JSON character, try to find the end
        if text and text[-1] not in ["}", "]"]:
            json_end = text.rfind("}")
            if json_end >= 0:
                text = text[: json_end + 1]

        # Remove trailing commas
        text = text.replace(",}", "}").replace(",]", "]")

        # Remove comments
        import re

        text = re.sub(r"//.*?\n", "\n", text)

        logger.debug(
            f"[DesignObjectives] Cleaned JSON text: {text[:200]}..."
            if len(text) > 200
            else f"[DesignObjectives] Cleaned JSON text: {text}"
        )
        return text

    # ---------------------------------------------------------------------
    # Prompt construction
    # ---------------------------------------------------------------------

    def create_alignment_prompt(
        self,
        architecture_context: str,
        objectives_config: dict | None = None,
        assessment_id: str | None = None,
    ) -> str:
        """
        Create the prompt for design objective alignment.

        architecture_context:
          - Textual description of the architecture (diagram summary, design notes, etc.)
        objectives_config:
          - Optional dict with overrides for objectives.
            Example:
              {
                "Maintainability": {
                  "importance": "High",
                  "success_criteria": "Must support weekly releases without downtime"
                },
                ...
              }
        assessment_id:
          - Used only for storage path alignment / logging context; not required for logic.
        """
        try:
            prompt_data = self.prompt_manager.get_prompt("design_objectives")
        except Exception as e:
            # Fallback if PromptManager doesn't have the new key yet
            logger.warning(
                "[DesignObjectives] Prompt 'design_objectives' not found in PromptManager. "
                "Using built-in default. Error: %s",
                e,
            )
            prompt_data = type("PromptStub", (), {})()
            prompt_data.system_context = (
                "You are a senior Enterprise Architect performing a structured architecture review."
            )
            prompt_data.task = (
                "Assess the architecture against six design objectives and produce a JSON scorecard."
            )
            prompt_data.instructions = (
                "For each objective, assign a rating, score, justification, risks, and recommendations."
            )
            prompt_data.format = {
                "example": {
                    "overall_summary": "Example summary",
                    "objectives": [],
                    "quick_scorecard": {},
                }
            }

        # Merge defaults + caller overrides
        defaults = self._default_objectives()
        objectives_config = objectives_config or {}
        merged = {}
        for name, meta in defaults.items():
            override = objectives_config.get(name, {})
            merged[name] = {
                "description": override.get("description", meta["description"]),
                "importance": override.get("importance", "Medium"),
                "success_criteria": override.get("success_criteria", ""),
            }

        # Human-readable objective description block
        objective_lines = []
        for name, meta in merged.items():
            objective_lines.append(f"- {name}:")
            objective_lines.append(f"  Description: {meta['description']}")
            objective_lines.append(f"  Importance: {meta['importance']}")
            if meta["success_criteria"]:
                objective_lines.append(f"  Success Criteria: {meta['success_criteria']}")
            objective_lines.append("")  # blank line

        objectives_block = "\n".join(objective_lines)

        # Example JSON from prompt
        example_json = json.dumps(prompt_data.format.get("example", {}), indent=2)

        # Extra JSON instructions for Bedrock
        json_instructions = ""
        if getattr(self.openai_handler, "method", "OPENAI") == "BEDROCK":
            json_instructions = """
IMPORTANT: You MUST respond with valid, properly formatted JSON.
Do NOT include any markdown, commentary, or text outside of the JSON object.
"""

        prompt = f"""
{json_instructions}
{prompt_data.system_context} {prompt_data.task}

{prompt_data.instructions}

ARCHITECTURE CONTEXT:
{architecture_context}

DESIGN OBJECTIVES (as provided/understood for this review):
{objectives_block}

The JSON structure MUST follow this format (you may extend with extra fields, but NOT remove required ones):

{example_json}

Only output JSON. No explanation text.
"""
        self.last_generated_prompt = prompt
        return prompt

    # ---------------------------------------------------------------------
    # Core LLM call + parsing
    # ---------------------------------------------------------------------

    def _normalize_alignment_response(self, response_content: dict) -> dict:
        """
        Normalize the JSON so downstream code can rely on a stable shape.
        """
        normalized = {
            "overall_summary": response_content.get("overall_summary", "").strip()
            or "No overall summary provided.",
            "objectives": [],
            "quick_scorecard": {},
        }

        # Normalize objectives list
        objectives = response_content.get("objectives", [])
        if not isinstance(objectives, list):
            logger.warning("[DesignObjectives] 'objectives' was not a list; normalizing")
            objectives = [objectives] if objectives else []

        # Put into a dict keyed by name so we can ensure all six exist
        by_name = {}

        for item in objectives:
            if not isinstance(item, dict):
                continue

            name = item.get("name") or item.get("objective") or "Unknown"
            rating = item.get("rating") or "Unknown"
            score = item.get("score")
            try:
                score = int(score) if score is not None else None
            except Exception:
                score = None

            justification = item.get("justification") or item.get("reason", "") or ""
            risks = item.get("risks") or item.get("risk") or []
            if isinstance(risks, str):
                risks = [risks]
            recommendations = (
                item.get("recommendations")
                or item.get("mitigations")
                or item.get("actions")
                or []
            )
            if isinstance(recommendations, str):
                recommendations = [recommendations]

            evidence = item.get("evidence") or ""

            by_name[name] = {
                "name": name,
                "rating": rating,
                "score": score,
                "justification": justification,
                "risks": risks,
                "recommendations": recommendations,
                "evidence": evidence,
            }

        # Ensure all six canonical objectives appear at least once
        for canonical in self._default_objectives().keys():
            if canonical not in by_name:
                by_name[canonical] = {
                    "name": canonical,
                    "rating": "Unknown",
                    "score": None,
                    "justification": "No explicit assessment was returned for this objective.",
                    "risks": [],
                    "recommendations": [],
                    "evidence": "",
                }

        # Rebuild list in canonical order
        normalized["objectives"] = [by_name[name] for name in self._default_objectives().keys()]

        # quick_scorecard
        quick = response_content.get("quick_scorecard", {})
        if not isinstance(quick, dict):
            quick = {}

        # Ensure quick_scorecard has all six
        for obj in normalized["objectives"]:
            name = obj["name"]
            rating = obj["rating"]
            if name not in quick:
                quick[name] = rating

        normalized["quick_scorecard"] = quick

        return normalized

    def json_to_markdown(self, alignment: dict) -> str:
        """
        Convert the normalized alignment JSON to a Markdown summary
        for the UI / reports.
        """
        lines = []

        # Overall summary
        overall = alignment.get("overall_summary", "")
        if overall:
            lines.append("## Overall Architecture Summary\n")
            lines.append(overall.strip())
            lines.append("")

        # Quick scorecard
        lines.append("## Design Objective Scorecard\n")
        lines.append("| Objective | Rating | Score (1–5) |")
        lines.append("|-----------|--------|-------------|")

        quick = alignment.get("quick_scorecard", {})
        objs = alignment.get("objectives", [])

        score_lookup = {o["name"]: o.get("score") for o in objs}

        for name in self._default_objectives().keys():
            rating = quick.get(name, "Unknown")
            score = score_lookup.get(name)
            score_str = str(score) if score is not None else "-"
            lines.append(f"| {name} | {rating} | {score_str} |")

        lines.append("")

        # Detailed sections
        lines.append("## Detailed Objective Analysis\n")

        for obj in objs:
            name = obj["name"]
            rating = obj["rating"]
            score = obj["score"]
            justification = obj.get("justification", "")
            risks = obj.get("risks", []) or []
            recs = obj.get("recommendations", []) or []
            evidence = obj.get("evidence", "")

            lines.append(f"### {name}")
            lines.append(f"**Rating:** {rating}  \n**Score:** {score if score is not None else '-'}\n")
            if justification:
                lines.append(f"**Justification:** {justification}\n")
            if risks:
                lines.append("**Key Risks:**")
                for r in risks:
                    lines.append(f"- {r}")
            if recs:
                lines.append("**Recommendations:**")
                for rec in recs:
                    lines.append(f"- {rec}")
            if evidence:
                lines.append(f"**Evidence / References:** {evidence}")
            lines.append("")

        return "\n".join(lines)

    def get_alignment(self, prompt: str) -> dict:
        """
        Call the unified LLM handler and parse/normalize the JSON response.
        """
        method = getattr(self.openai_handler, "method", "OPENAI")
        logger.info(f"[DesignObjectives] Generating alignment via {method}")

        try:
            system_message = """You are a senior Enterprise Architect.
You produce architecture reviews in STRICT JSON format.

Your response MUST be a single JSON object with:
- overall_summary: string
- objectives: array of objects (one per design objective)
- quick_scorecard: object mapping objective name -> rating

Rules:
- Output ONLY JSON. No markdown, no prose.
- Use double quotes for all keys and string values.
- Do NOT include comments.
"""

            full_prompt = f"""SYSTEM INSTRUCTIONS:
{system_message}

USER + CONTEXT PROMPT:
{prompt}
"""

            response_text = self.openai_handler.get_completion(full_prompt, max_tokens=4000)
            logger.info(f"[DesignObjectives] Raw model response length: {len(response_text)}")

            cleaned_text = self.clean_json_response(response_text)

            try:
                response_content = json.loads(cleaned_text)
            except json.JSONDecodeError as je:
                logger.error(f"[DesignObjectives] Alignment JSON failed to parse: {je}")
                logger.error(
                    "[DesignObjectives] Cleaned response text (first 500 chars): %s",
                    cleaned_text[:500],
                )
                raise ValueError(f"Alignment JSON failed to parse: {je}") from je

            normalized = self._normalize_alignment_response(response_content)
            normalized["raw_response"] = response_content
            return normalized

        except Exception as e:
            logger.error(f"[DesignObjectives] Error generating alignment with {method}: {str(e)}")
            return {
                "overall_summary": "Failed to generate design objective alignment.",
                "objectives": [
                    {
                        "name": "Maintainability",
                        "rating": "Unknown",
                        "score": None,
                        "justification": f"Error: {str(e)}",
                        "risks": [],
                        "recommendations": [],
                        "evidence": "",
                    }
                ],
                "quick_scorecard": {},
                "raw_response": {},
            }

    # ---------------------------------------------------------------------
    # Public entrypoint
    # ---------------------------------------------------------------------

    def generate_alignment(
        self,
        architecture_context: str,
        objectives_config: dict | None = None,
        assessment_id: str | None = None,
    ) -> dict:
        """
        High-level method used by the API / UI.

        Returns:
        {
          "overall_summary": str,
          "objectives": [...],
          "quick_scorecard": {...},
          "raw_response": {...},
          "markdown": "human readable report"
        }
        """
        logger.info("[DesignObjectives] Generating design objective alignment")

        prompt = self.create_alignment_prompt(
            architecture_context=architecture_context,
            objectives_config=objectives_config,
            assessment_id=assessment_id,
        )
        result = self.get_alignment(prompt)

        markdown = self.json_to_markdown(result)
        result["markdown"] = markdown

        # Persist artifacts alongside other assessment data (if assessment_id provided)
        if assessment_id:
            try:
                folder = os.path.join(STORAGE_ROOT, assessment_id)
                os.makedirs(folder, exist_ok=True)

                json_path = os.path.join(folder, "design_objectives.json")
                md_path = os.path.join(folder, "design_objectives.md")

                with open(json_path, "w") as f:
                    json.dump(result, f, indent=2)

                with open(md_path, "w") as f:
                    f.write(markdown)

                logger.info(
                    "[DesignObjectives] Saved alignment artifacts to %s and %s",
                    json_path,
                    md_path,
                )
            except Exception as e:
                logger.error(f"[DesignObjectives] Failed to save artifacts: {e}")

        return result
