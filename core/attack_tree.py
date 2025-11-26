import json
import logging
import os
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---- Shared storage root (Render disk or local) ----
# In Render: DATA_DIR=/data (disk mount)
# Locally: falls back to project root
DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root-ish
)
STORAGE_ROOT = os.path.join(DATA_DIR, "storage")


class AttackTreeHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()

    def _get_methodology_from_details(self, assessment_id):
        """
        Get the methodology from details.json for the given assessment_id.
        Raises an error if details.json doesn't exist or doesn't contain the methodology.
        """
        details_path = os.path.join(STORAGE_ROOT, assessment_id, 'details.json')
        logging.info(f"[AttackTree] Looking for details.json at: {details_path}")

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

    def create_attack_tree_prompt(self, threat_model_result, assessment_id=None):
        """
        Create prompt for generating attack tree using threat model data.
        The attack tree MUST have:
          - One or more root 'goal' nodes
          - 'attack' nodes under each goal
          - 'vulnerability' leaf nodes under each attack
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(
                    f"Using threat modeling methodology from details.json for attack tree: {methodology}"
                )
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)

        # Get the attack tree prompt template
        prompt_data = self.prompt_manager.get_prompt("attack_tree")

        # Extract relevant information from threat model
        threats = threat_model_result.get('threat_model', [])

        # Group threats by type for better organization
        threat_types = {}
        for threat in threats:
            threat_type = threat.get('Threat Type', '')
            if threat_type not in threat_types:
                threat_types[threat_type] = []
            threat_types[threat_type].append(threat)

        # Format threats for attack tree analysis
        threat_descriptions = []
        for threat_type, type_threats in threat_types.items():
            threat_descriptions.append(f"## {threat_type} Threats:")
            for threat in type_threats:
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')
                threat_descriptions.append(
                    f"- Scenario: {scenario}\n  Impact: {impact}"
                )

        formatted_threats = "\n\n".join(threat_descriptions)

        # Extra explicit instructions for vulnerabilities + structure
        structure_instructions = """
You are designing a detailed ATTACK TREE.

You MUST output a single JSON object with this exact structure:

{
  "nodes": [
    {
      "id": "root",
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
  These "vulnerability" nodes should describe concrete weaknesses, misconfigurations, missing controls, or process gaps.
- Use multiple levels where appropriate (attack steps can have vulnerability children, and attacks can be grouped under high-level goals).
- IDs should be unique (e.g., "goal1", "attack1", "vuln1", "attack2", "vuln2a", etc.).
"""

        prompt = f"""
{prompt_data.system_context} {prompt_data.task}

The JSON structure should follow this format:
{json.dumps(prompt_data.format.get("example", {}), indent=2)}

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

    def convert_tree_to_mermaid(self, tree_data):
        """
        Convert JSON tree structure to Mermaid diagram syntax with styled nodes based on type.
        Uses left-to-right layout for better visualization.
        """
        # Use LR (left-to-right) layout instead of TD (top-down) for better spacing
        mermaid_lines = ["graph LR"]

        # Add configuration for better layout
        mermaid_lines.append("    %% Configuration for better spacing and layout")
        mermaid_lines.append("    graph [rankdir=LR nodesep=100 ranksep=150]")

        # Add style definitions
        mermaid_lines.extend([
            "    %% Node styling",
            "    classDef goal fill:#ffd7d7 stroke:#ff9999 color:#cc0000 stroke-width:2px padding:15px margin:10px",
            "    classDef attack fill:#fff3d7 stroke:#ffd699 color:#cc7700 stroke-width:2px padding:10px margin:10px",
            "    classDef vulnerability fill:#d7e9ff stroke:#99c2ff color:#0052cc stroke-width:2px padding:8px margin:10px"
        ])

        # Track link count for styling
        link_count = 0
        link_styles = []

        def process_node(node, parent_id=None):
            nonlocal link_count
            node_id = node["id"]
            node_label = node["label"]
            node_type = node["type"]

            # Use different shapes based on node type
            if node_type == "goal":
                mermaid_lines.append(f'    {node_id}(["{node_label}"])')
            elif node_type == "attack":
                mermaid_lines.append(f'    {node_id}{{{{{node_label}}}}}')
            else:
                mermaid_lines.append(f'    {node_id}["{node_label}"]')

            # Apply style class based on node type
            mermaid_lines.append(f'    class {node_id} {node_type}')

            # Add connection to parent if exists
            if parent_id:
                mermaid_lines.append(f'    {parent_id} -->|{node_type}| {node_id}')
                link_styles.append(
                    f"    linkStyle {link_count} stroke:#333333 stroke-width:2px fill:none"
                )
                link_count += 1

            # Process children
            if "children" in node:
                for child in node["children"]:
                    process_node(child, node_id)

        # Process root node(s)
        for root_node in tree_data["nodes"]:
            process_node(root_node)

        mermaid_lines.extend(link_styles)
        return "\n".join(mermaid_lines)

    def _normalize_node_types(self, tree_data):
        """
        Normalize node 'type' values so that slight variations from the model
        (e.g., 'vuln', 'weakness') are mapped into canonical types.
        """
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
                    # If the model invents some type, try to infer:
                    # treat leaf-ish nodes as vulnerabilities by default
                    if not node.get("children"):
                        node["type"] = "vulnerability"
                    else:
                        node["type"] = "attack"

                if "children" in node and node["children"]:
                    normalize_nodes(node["children"])

        if isinstance(tree_data, dict) and "nodes" in tree_data:
            normalize_nodes(tree_data["nodes"])

        return tree_data

    def get_attack_tree(self, prompt):
        """
        Get attack tree from LLM with improved error handling and JSON parsing.
        """
        method = self.openai_handler.method
        logging.info(f"Generating attack tree using {method}")

        try:
            # System message with explicit schema + vulnerability requirement
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
Ensure all JSON strings are properly escaped and the structure is valid.
Always use commas between properties and array elements."""

            # Stronger JSON-only variant for Bedrock
            if method == 'BEDROCK':
                system_message = system_message + """

BEDROCK RULES:
- Do NOT wrap your JSON in markdown code fences.
- Do NOT include any commentary, explanation, or prose outside the JSON object.
"""

            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.5,  # Lower temp for consistency
                "max_tokens": 8000
            }

            # Add provider-specific parameters
            if method == 'OPENAI':
                params["response_format"] = {"type": "json_object"}  # Enforce JSON response
                logging.info("Using OpenAI-specific parameters")
            elif method == 'BEDROCK':
                logging.info("Using Bedrock-compatible parameters")

            # Make the API call
            logging.info(f"Sending request to {method} with model {self.openai_handler.model}")
            response = self.client.chat.completions.create(**params)

            response_content = response.choices[0].message.content.strip()

            # Additional JSON validation and cleaning
            try:
                fixed_content = response_content

                try:
                    # Try parsing as-is first
                    tree_data = json.loads(fixed_content)

                    # Ensure total_paths exists, calculate if not provided
                    if 'total_paths' not in tree_data:
                        def count_paths(node):
                            if not node.get('children'):
                                return 1
                            total = 0
                            for child in node.get('children', []):
                                total += count_paths(child)
                            return total

                        total_paths = 0
                        for root_node in tree_data.get('nodes', []):
                            total_paths += count_paths(root_node)
                        tree_data['total_paths'] = total_paths
                except json.JSONDecodeError:
                    # If parsing fails, try fixing the JSON
                    logging.warning("Initial JSON parsing failed, attempting fixes")

                    import re

                    fixed_content = re.sub(r'"\s*\n\s*"', '",\n"', fixed_content)
                    fixed_content = re.sub(r'}\s*\n\s*{', '},\n{', fixed_content)

                    fixed_content = re.sub(
                        r'"([^"]+)"\s*:\s*("[^"]+"|\{[^}]+\}|\[[^\]]+\]|\w+)\s*\n\s*"',
                        r'"\1": \2,\n"',
                        fixed_content,
                    )

                    fixed_content = re.sub(r'\}\s*\n\s*\{', '}, {', fixed_content)
                    fixed_content = re.sub(r'\]\s*\n\s*\[', '], [', fixed_content)

                    fixed_content = re.sub(
                        r'(\s*"[^"]+"\s*:\s*(?:"[^"]*"|{[^}]*}|\[[^\]]*\]|\w+))\s*\n\s*(?=")',
                        r'\1,\n',
                        fixed_content,
                    )

                    fixed_content = re.sub(
                        r'"([^"]+)"\s*:\s*([^,\n]+)\s*\n\s*"', r'"\1": \2,\n"', fixed_content
                    )

                    # Last resort - manually construct valid JSON
                    if '"id":' in fixed_content and '"type":' in fixed_content:
                        try:
                            id_matches = re.findall(r'"id"\s*:\s*"([^"]+)"', fixed_content)
                            type_matches = re.findall(r'"type"\s*:\s*"([^"]+)"', fixed_content)
                            label_matches = re.findall(r'"label"\s*:\s*"([^"]+)"', fixed_content)

                            if len(id_matches) > 0 and len(type_matches) > 0 and len(label_matches) > 0:
                                logging.warning("Constructing minimal valid tree from extracted properties")

                                root_node = {
                                    "id": "root",
                                    "type": "goal",
                                    "label": "Security Threats",
                                    "children": []
                                }

                                threat_types = set()
                                for i, type_val in enumerate(type_matches):
                                    if type_val == "attack" and i < len(label_matches):
                                        threat_type = (
                                            label_matches[i].split()[0]
                                            if len(label_matches[i].split()) > 0
                                            else "Unknown"
                                        )
                                        if threat_type not in threat_types:
                                            threat_types.add(threat_type)
                                            attack_node = {
                                                "id": f"attack{len(threat_types)}",
                                                "type": "attack",
                                                "label": label_matches[i],
                                                "children": [
                                                    {
                                                        "id": f"vuln{len(threat_types)}",
                                                        "type": "vulnerability",
                                                        "label": "Concrete vulnerability for this attack step"
                                                    }
                                                ],
                                            }
                                            root_node["children"].append(attack_node)

                                tree_data = {"nodes": [root_node]}
                                tree_data['total_paths'] = len(root_node["children"])
                                tree_data = self._normalize_node_types(tree_data)
                                return {
                                    "attack_tree": tree_data,
                                    "markdown": self.convert_tree_to_mermaid(tree_data),
                                    "total_paths": tree_data.get('total_paths', 0),
                                }
                        except Exception as e:
                            logging.error(f"Failed to construct minimal valid tree: {str(e)}")

                    try:
                        tree_data = json.loads(fixed_content)
                    except json.JSONDecodeError as e:
                        logging.error(f"JSON parsing still failed after fixes: {str(e)}")
                        logging.error(f"Fixed content: {fixed_content[:200]}...")

                        # Default tree with at least one vulnerability
                        tree_data = {
                            "nodes": [
                                {
                                    "id": "root",
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
                                                    "label": "Authentication vulnerabilities"
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "total_paths": 1,
                        }

                # Ensure the basic structure exists
                if "nodes" not in tree_data:
                    tree_data = {"nodes": []}

                # Normalize node types (map 'vuln', 'weakness', etc. -> 'vulnerability')
                tree_data = self._normalize_node_types(tree_data)

                # Validate and fix the tree structure
                if not self.validate_tree_structure(tree_data):
                    logging.warning("Invalid tree structure received, attempting to fix...")
                    tree_data = self.fix_tree_structure(tree_data)
                    tree_data = self._normalize_node_types(tree_data)

                # Convert to Mermaid diagram
                mermaid_diagram = self.convert_tree_to_mermaid(tree_data)

                return {
                    "attack_tree": tree_data,
                    "markdown": mermaid_diagram,
                    "total_paths": tree_data.get('total_paths', 0),
                }

            except json.JSONDecodeError as json_err:
                logging.error(f"JSON parsing error: {str(json_err)}")
                logging.error(f"Response content: {response_content[:200]}...")
                raise ValueError(f"Failed to parse OpenAI response as JSON: {str(json_err)}")

        except Exception as e:
            logging.error(f"Error generating attack tree: {str(e)}")
            error_message = str(e)
            error_tree = {
                "nodes": [
                    {
                        "id": "error",
                        "type": "goal",
                        "label": f"Error generating attack tree: {error_message}",
                    }
                ]
            }
            error_mermaid = f"graph TD\n    error[\"{error_message}\"]"
            return {
                "attack_tree": error_tree,
                "markdown": error_mermaid,
                "total_paths": 0,
            }

    def fix_tree_structure(self, tree_data):
        """
        Attempt to fix invalid tree structures by ensuring proper node hierarchy.
        """
        fixed_nodes = []

        # Create a root node if none exists
        root_exists = any(node.get("type") == "goal" for node in tree_data.get("nodes", []))
        if not root_exists:
            fixed_nodes.append({
                "id": "root",
                "type": "goal",
                "label": "Security Threats",
                "children": []
            })

        # Process existing nodes
        for node in tree_data.get("nodes", []):
            if "id" not in node:
                node["id"] = f"node_{len(fixed_nodes)}"
            if "type" not in node:
                node["type"] = "attack"  # Default to attack type
            if "label" not in node:
                node["label"] = "Unnamed Node"
            fixed_nodes.append(node)

        return {"nodes": fixed_nodes}

    def validate_tree_structure(self, tree_data):
        """
        Validate the tree structure to ensure it meets the frontend requirements.
        """
        try:
            if not isinstance(tree_data, dict) or "nodes" not in tree_data:
                logging.error("Tree data missing 'nodes' array")
                return False

            if not tree_data["nodes"] or not isinstance(tree_data["nodes"], list):
                logging.error("Tree data has empty or invalid 'nodes' array")
                return False

            for node in self._get_all_nodes(tree_data["nodes"]):
                if not all(key in node for key in ["id", "type", "label"]):
                    logging.error(f"Node missing required fields: {node}")
                    return False

                if node["type"] not in ["goal", "attack", "vulnerability"]:
                    logging.error(f"Invalid node type: {node['type']}")
                    return False

            return True

        except Exception as e:
            logging.error(f"Error validating tree structure: {str(e)}")
            return False

    def _get_all_nodes(self, nodes):
        """
        Helper method to get all nodes in the tree recursively.
        """
        all_nodes = []

        def collect_nodes(node_list):
            for node in node_list:
                all_nodes.append(node)
                if "children" in node and node["children"]:
                    collect_nodes(node["children"])

        collect_nodes(nodes)
        return all_nodes

    def generate_attack_tree(self, threat_model_result, assessment_id=None):
        """
        Generate attack tree based on threat model results.
        """
        logging.info("Generating attack tree")

        # Create the prompt using threat model results
        prompt = self.create_attack_tree_prompt(threat_model_result, assessment_id)

        # Get the attack tree data
        result = self.get_attack_tree(prompt)

        # Check if result is a string (error message) or a dictionary
        if isinstance(result, str):
            return {
                "markdown": f"mermaid\n{result}\n"
            }

        return result
