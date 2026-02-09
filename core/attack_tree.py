# attack_tree.py

import json
import logging
import os
import re
from typing import Any, Dict, Optional

from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ---- Shared storage root (Render disk or local) ----
# In Render: DATA_DIR=/data (disk mount)
# Locally: falls back to project root
DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # project root-ish
)
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")


class AttackTreeHandler:
    """
    Generates an attack tree JSON + Mermaid from an existing threat model.

    FIX INCLUDED:
      - Your UI error: "'BedrockRuntime' object has no attribute 'chat'"
        happens because boto3's bedrock-runtime client does NOT support:
            client.chat.completions.create(...)
        So for BEDROCK we call:
            client.invoke_model(...)
        and parse the provider response.

    OpenAI path still uses:
      client.chat.completions.create(...)
    """

    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()

    # ---------------------------
    # Details.json methodology
    # ---------------------------

    def _get_methodology_from_details(self, assessment_id: str) -> str:
        details_path = os.path.join(STORAGE_ROOT, assessment_id, "details.json")
        logging.info(f"[AttackTree] Looking for details.json at: {details_path}")

        if not os.path.exists(details_path):
            raise ValueError(f"details.json not found for assessment {assessment_id}")

        try:
            with open(details_path, "r") as f:
                details = json.load(f)
            methodology = details.get("threatModelingMethodology")
            if not methodology:
                raise ValueError(
                    f"No threat modeling methodology found in details.json for assessment {assessment_id}"
                )
            return methodology
        except Exception as e:
            raise ValueError(f"Error reading methodology from details.json: {str(e)}")

    # ---------------------------
    # Prompt creation
    # ---------------------------

    def create_attack_tree_prompt(
        self, threat_model_result: Dict[str, Any], assessment_id: Optional[str] = None
    ) -> str:
        if not assessment_id:
            raise ValueError("Assessment ID is required to determine the threat modeling methodology")

        methodology = self._get_methodology_from_details(assessment_id)
        logging.info(f"Using threat modeling methodology from details.json for attack tree: {methodology}")

        prompt_data = self.prompt_manager.get_prompt("attack_tree")

        threats = threat_model_result.get("threat_model", [])

        threat_types: Dict[str, list] = {}
        for threat in threats:
            ttype = threat.get("Threat Type", "") or "Uncategorized"
            threat_types.setdefault(ttype, []).append(threat)

        threat_descriptions = []
        for threat_type, type_threats in threat_types.items():
            threat_descriptions.append(f"## {threat_type} Threats:")
            for threat in type_threats:
                scenario = threat.get("Scenario", "")
                impact = threat.get("Potential Impact", "")
                threat_descriptions.append(f"- Scenario: {scenario}\n  Impact: {impact}")

        formatted_threats = "\n\n".join(threat_descriptions) if threat_descriptions else "No threats provided."

        structure_instructions = """
You are designing a detailed ATTACK TREE.

You MUST output a single JSON object with this exact structure:

{
  "nodes": [
    {
      "id": "goal1",
      "type": "goal",
      "label": "High-level attack objective",
      "children": [
        {
          "id": "attack1",
          "type": "attack",
          "label": "Specific attack path or step",
          "children": [
            {
              "id": "vuln1",
              "type": "vulnerability",
              "label": "Concrete technical or process vulnerability exploited in this step"
            }
          ]
        }
      ]
    }
  ]
}

RULES:
- Every node MUST have: "id", "type", and "label".
- "type" MUST be one of: "goal", "attack", "vulnerability".
- There MUST be at least one "goal" node.
- Under each "goal" node, create one or more "attack" nodes that represent distinct attack paths or steps.
- Under EACH "attack" node, create AT LEAST ONE "vulnerability" child node.
- IDs should be unique (e.g., "goal1", "attack1", "vuln1", "attack2", "vuln2a", etc.).
"""

        example = {}
        try:
            if isinstance(prompt_data.format, dict):
                example = prompt_data.format.get("example", {}) or {}
        except Exception:
            example = {}

        prompt = f"""
{prompt_data.system_context} {prompt_data.task}

The JSON structure should follow this format (example):
{json.dumps(example, indent=2)}

{structure_instructions}

{prompt_data.instructions}

Below are the identified threats to consider when designing the attack tree:
{formatted_threats}

IMPORTANT:
- Your response must be ONLY valid JSON, with no additional text or explanation.
- Ensure all JSON strings are properly escaped and the structure is valid.
- Use commas between all properties and array elements.
"""
        return prompt

    # ---------------------------
    # Mermaid conversion
    # ---------------------------

    def convert_tree_to_mermaid(self, tree_data: Dict[str, Any]) -> str:
        mermaid_lines = ["graph LR"]
        mermaid_lines.append("    %% Configuration for better spacing and layout")
        mermaid_lines.append("    graph [rankdir=LR nodesep=100 ranksep=150]")

        mermaid_lines.extend(
            [
                "    %% Node styling",
                "    classDef goal fill:#ffd7d7 stroke:#ff9999 color:#cc0000 stroke-width:2px padding:15px margin:10px",
                "    classDef attack fill:#fff3d7 stroke:#ffd699 color:#cc7700 stroke-width:2px padding:10px margin:10px",
                "    classDef vulnerability fill:#d7e9ff stroke:#99c2ff color:#0052cc stroke-width:2px padding:8px margin:10px",
            ]
        )

        link_count = 0
        link_styles = []

        def process_node(node: Dict[str, Any], parent_id: Optional[str] = None):
            nonlocal link_count
            node_id = node["id"]
            node_label = str(node["label"]).replace('"', '\\"')
            node_type = node["type"]

            if node_type == "goal":
                mermaid_lines.append(f'    {node_id}(["{node_label}"])')
            elif node_type == "attack":
                mermaid_lines.append(f"    {node_id}{{{{{node_label}}}}}")
            else:
                mermaid_lines.append(f'    {node_id}["{node_label}"]')

            mermaid_lines.append(f"    class {node_id} {node_type}")

            if parent_id:
                mermaid_lines.append(f"    {parent_id} -->|{node_type}| {node_id}")
                link_styles.append(f"    linkStyle {link_count} stroke:#333333 stroke-width:2px fill:none")
                link_count += 1

            for child in node.get("children", []) or []:
                process_node(child, node_id)

        for root_node in tree_data.get("nodes", []):
            process_node(root_node)

        mermaid_lines.extend(link_styles)
        return "\n".join(mermaid_lines)

    # ---------------------------
    # Normalization + validation
    # ---------------------------

    def _normalize_node_types(self, tree_data: Dict[str, Any]) -> Dict[str, Any]:
        type_map = {
            "goal": "goal",
            "attack": "attack",
            "vulnerability": "vulnerability",
            "vuln": "vulnerability",
            "vulnerability_node": "vulnerability",
            "weakness": "vulnerability",
            "issue": "vulnerability",
        }

        def normalize_nodes(nodes):
            for node in nodes:
                t = str(node.get("type", "")).lower().strip()
                if t in type_map:
                    node["type"] = type_map[t]
                else:
                    node["type"] = "vulnerability" if not node.get("children") else "attack"

                if node.get("children"):
                    normalize_nodes(node["children"])

        if isinstance(tree_data, dict) and "nodes" in tree_data:
            normalize_nodes(tree_data["nodes"])
        return tree_data

    def _get_all_nodes(self, nodes):
        all_nodes = []

        def collect(node_list):
            for n in node_list:
                all_nodes.append(n)
                if n.get("children"):
                    collect(n["children"])

        collect(nodes)
        return all_nodes

    def validate_tree_structure(self, tree_data: Dict[str, Any]) -> bool:
        try:
            if not isinstance(tree_data, dict) or "nodes" not in tree_data:
                logging.error("Tree data missing 'nodes' array")
                return False

            if not tree_data["nodes"] or not isinstance(tree_data["nodes"], list):
                logging.error("Tree data has empty or invalid 'nodes' array")
                return False

            for node in self._get_all_nodes(tree_data["nodes"]):
                if not all(k in node for k in ["id", "type", "label"]):
                    logging.error(f"Node missing required fields: {node}")
                    return False
                if node["type"] not in ["goal", "attack", "vulnerability"]:
                    logging.error(f"Invalid node type: {node['type']}")
                    return False

            return True
        except Exception as e:
            logging.error(f"Error validating tree structure: {str(e)}")
            return False

    def fix_tree_structure(self, tree_data: Dict[str, Any]) -> Dict[str, Any]:
        fixed_nodes = []

        root_exists = any(node.get("type") == "goal" for node in tree_data.get("nodes", []))
        if not root_exists:
            fixed_nodes.append({"id": "goal1", "type": "goal", "label": "Security Threats", "children": []})

        for node in tree_data.get("nodes", []):
            if "id" not in node:
                node["id"] = f"node_{len(fixed_nodes) + 1}"
            if "type" not in node:
                node["type"] = "attack"
            if "label" not in node:
                node["label"] = "Unnamed Node"
            fixed_nodes.append(node)

        return {"nodes": fixed_nodes}

    # ---------------------------
    # Provider call (OpenAI vs Bedrock)
    # ---------------------------

    def _call_llm(self, system_message: str, user_prompt: str) -> str:
        """
        Returns raw model text.

        OPENAI:
          client.chat.completions.create(...)

        BEDROCK:
          client.invoke_model(...) using a prompt payload.
          This fixes: BedrockRuntime has no attribute 'chat'
        """
        method = (getattr(self.openai_handler, "method", "OPENAI") or "OPENAI").upper().strip()
        model_id = getattr(self.openai_handler, "model", None)

        if not model_id:
            raise ValueError("openai_handler.model is missing (needed for OpenAI or Bedrock invocation).")

        # --- OpenAI / OpenAI-compatible client ---
        if method == "OPENAI":
            params: Dict[str, Any] = {
                "model": model_id,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 8000,
                "response_format": {"type": "json_object"},
            }
            resp = self.client.chat.completions.create(**params)
            return resp.choices[0].message.content.strip()

        # --- Bedrock boto3 runtime client ---
        if method == "BEDROCK":
            # We will build a single prompt string that includes system + user content.
            # (Meta Llama 3 on Bedrock expects a "prompt" style input.)
            combined_prompt = (
                f"{system_message.strip()}\n\n"
                f"USER:\n{user_prompt.strip()}\n\n"
                f"ASSISTANT:\n"
            )

            body = {
                "prompt": combined_prompt,
                "max_gen_len": 8000,
                "temperature": 0.3,
                "top_p": 0.9,
            }

            # Bedrock expects bytes
            resp = self.client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body).encode("utf-8"),
            )

            raw = resp.get("body")
            raw_bytes = raw.read() if hasattr(raw, "read") else raw
            raw_text = raw_bytes.decode("utf-8") if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes)

            # Different providers return different JSON shapes.
            # For Llama3 on Bedrock, commonly: {"generation": "..."}
            try:
                payload = json.loads(raw_text)
                if isinstance(payload, dict):
                    if "generation" in payload and isinstance(payload["generation"], str):
                        return payload["generation"].strip()
                    if "outputText" in payload and isinstance(payload["outputText"], str):
                        return payload["outputText"].strip()
                    if "results" in payload and isinstance(payload["results"], list) and payload["results"]:
                        # Some models: {"results":[{"outputText":"..."}]}
                        r0 = payload["results"][0]
                        if isinstance(r0, dict) and isinstance(r0.get("outputText"), str):
                            return r0["outputText"].strip()
                # If it's not a dict, just return text form
                return raw_text.strip()
            except Exception:
                return raw_text.strip()

        # Unknown method fallback
        raise ValueError(f"Unsupported LLM method: {method}")

    # ---------------------------
    # Core generation
    # ---------------------------

    def _tree(self, prompt: str) -> Dict[str, Any]:
        """
        Calls the LLM and returns:
          { "attack_tree": <json>, "markdown": <mermaid>, "total_paths": <int> }
        """
        method = (getattr(self.openai_handler, "method", "OPENAI") or "OPENAI").upper().strip()
        logging.info(f"Generating attack tree using {method}")

        system_message = """You are a Security Architect and expert. Create an attack tree structure in JSON format.

Your response MUST be a single valid JSON object with:
- A top-level key "nodes": an array of nodes.
- Each node MUST have: "id", "type", "label".
- "type" MUST be one of: "goal", "attack", "vulnerability".
- "goal" nodes represent high-level attacker objectives.
- "attack" nodes represent concrete attack steps or sub-goals.
- "vulnerability" nodes represent specific technical or process weaknesses exploited by an attack step.

STRUCTURE RULES:
- There MUST be at least one "goal" node.
- Under each "goal" node, create one or more "attack" nodes that represent distinct attack paths or steps.
- Under EACH "attack" node, create AT LEAST ONE "vulnerability" child node describing concrete weaknesses.

Your response must be ONLY valid JSON, with no additional text, markdown, or explanation.
"""

        if method == "BEDROCK":
            system_message += """
BEDROCK RULES:
- Do NOT wrap your JSON in markdown code fences.
- Do NOT include any commentary, explanation, or prose outside the JSON object.
"""

        try:
            response_content = self._call_llm(system_message=system_message, user_prompt=prompt)
        except Exception as e:
            logging.error(f"Error generating attack tree: {str(e)}")
            error_message = str(e)
            error_tree = {
                "nodes": [
                    {"id": "error", "type": "goal", "label": f"Error generating attack tree: {error_message}"}
                ]
            }
            return {
                "attack_tree": error_tree,
                "markdown": f'graph TD\n    error["{error_message}"]',
                "total_paths": 0,
            }

        # Parse JSON (with cleaning/fallback)
        try:
            fixed_content = response_content.strip()
            fixed_content = fixed_content.replace("```json", "").replace("```", "").strip()

            # If the model returned extra text, try to extract the first {...} JSON object.
            # (Bedrock models sometimes prepend/append text.)
            if not fixed_content.startswith("{"):
                match = re.search(r"\{.*\}", fixed_content, flags=re.DOTALL)
                if match:
                    fixed_content = match.group(0).strip()

            try:
                tree_data = json.loads(fixed_content)
            except json.JSONDecodeError:
                logging.warning("Initial JSON parsing failed, attempting fixes")

                fixed2 = fixed_content
                fixed2 = re.sub(r'"\s*\n\s*"', '",\n"', fixed2)
                fixed2 = re.sub(r"}\s*\n\s*{", "},\n{", fixed2)
                fixed2 = re.sub(r"\}\s*\n\s*\{", "}, {", fixed2)
                fixed2 = re.sub(r"\]\s*\n\s*\[", "], [", fixed2)

                try:
                    tree_data = json.loads(fixed2)
                except json.JSONDecodeError as e:
                    logging.error(f"JSON parsing still failed after fixes: {str(e)}")
                    logging.error(f"Fixed content: {fixed2[:800]}...")

                    # Last-resort valid tree
                    tree_data = {
                        "nodes": [
                            {
                                "id": "goal1",
                                "type": "goal",
                                "label": "Security Threats",
                                "children": [
                                    {
                                        "id": "attack1",
                                        "type": "attack",
                                        "label": "Generic attack path",
                                        "children": [
                                            {
                                                "id": "vuln1",
                                                "type": "vulnerability",
                                                "label": "Concrete vulnerability for this attack step",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }

            if "nodes" not in tree_data:
                tree_data = {"nodes": tree_data.get("nodes", []) if isinstance(tree_data, dict) else []}

            tree_data = self._normalize_node_types(tree_data)

            if not self.validate_tree_structure(tree_data):
                logging.warning("Invalid tree structure received, attempting to fix...")
                tree_data = self.fix_tree_structure(tree_data)
                tree_data = self._normalize_node_types(tree_data)

            # Ensure total_paths exists (count leaf paths)
            def count_paths(node: Dict[str, Any]) -> int:
                if not node.get("children"):
                    return 1
                return sum(count_paths(c) for c in node.get("children", []) or [])

            total_paths = 0
            for root in tree_data.get("nodes", []) or []:
                total_paths += count_paths(root)

            tree_data["total_paths"] = total_paths
            mermaid_diagram = self.convert_tree_to_mermaid(tree_data)

            return {"attack_tree": tree_data, "markdown": mermaid_diagram, "total_paths": total_paths}

        except Exception as e:
            logging.error(f"Error parsing attack tree JSON: {str(e)}")
            error_message = str(e)
            error_tree = {
                "nodes": [{"id": "error", "type": "goal", "label": f"Error parsing attack tree: {error_message}"}]
            }
            return {
                "attack_tree": error_tree,
                "markdown": f'graph TD\n    error["{error_message}"]',
                "total_paths": 0,
            }

    # Backwards-compatible public method
    def get_attack_tree(self, prompt: str) -> Dict[str, Any]:
        return self._tree(prompt)

    def generate_attack_tree(
        self, threat_model_result: Dict[str, Any], assessment_id: Optional[str] = None
    ) -> Dict[str, Any]:
        logging.info("Generating attack tree")
        prompt = self.create_attack_tree_prompt(threat_model_result, assessment_id=assessment_id)
        result = self.get_attack_tree(prompt)

        if isinstance(result, str):
            return {"markdown": f"mermaid\n{result}\n"}

        return result
