# llm/bedrock_handler.py

import os
import json
import logging
import boto3
from botocore.exceptions import ClientError


class BedrockHandler:
    """
    Thin wrapper around AWS Bedrock that exposes a similar interface to OpenAIHandler:

    - .method            -> "BEDROCK"
    - .model             -> model_id used on Bedrock
    - get_completion()   -> main entry point
    - send_prompt()      -> convenience wrapper

    Supports:
    - Meta Llama (e.g., meta.llama3-1-*, inference profiles that include llama/meta)
    - Anthropic Claude (e.g., us.anthropic.claude-*, inference profiles that include claude/anthropic)
    """

    def __init__(
        self,
        model_id: str | None = None,
        region: str | None = None,
        default_max_tokens: int | None = None,
        default_temperature: float | None = None,
    ):
        self.method = "BEDROCK"

        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.model_id = (model_id or os.getenv("BEDROCK_MODEL_ID", "")).strip()

        if not self.model_id:
            raise ValueError(
                "BEDROCK_MODEL_ID is not set. "
                "Set it in your environment or pass model_id= when creating BedrockHandler."
            )

        self.default_max_tokens = default_max_tokens or int(os.getenv("BEDROCK_MAX_TOKENS", "1200"))
        self.default_temperature = (
            float(default_temperature)
            if default_temperature is not None
            else float(os.getenv("BEDROCK_TEMPERATURE", "0.2"))
        )

        # Bedrock runtime client
        self.client = boto3.client("bedrock-runtime", region_name=self.region)

        logging.info(f"Initialized BedrockHandler with model_id={self.model_id} region={self.region}")

    # --- Small helpers -----------------------------------------------------

    @property
    def model(self) -> str:
        """For parity with OpenAIHandler.model"""
        return self.model_id

    def _is_llama(self) -> bool:
        """Heuristic: Llama models usually include 'llama' / 'meta' in their ID."""
        mid = self.model_id.lower()
        return ("llama" in mid) or ("meta." in mid) or ("meta/" in mid)

    def _is_claude(self) -> bool:
        """Heuristic: Claude models usually include 'claude' / 'anthropic' in their ID."""
        mid = self.model_id.lower()
        return ("claude" in mid) or ("anthropic" in mid)

    # --- Request body builders --------------------------------------------

    def _build_llama_body(self, prompt: str, max_tokens: int, temperature: float) -> dict:
        # ✅ Llama 3.1 style body on Bedrock Runtime
        return {
            "prompt": prompt,
            "max_gen_len": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
        }

    def _build_claude_body(self, prompt: str, max_tokens: int, temperature: float) -> dict:
        # ✅ Claude Messages API style body on Bedrock Runtime
        return {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": prompt}],
                }
            ],
        }

    # --- Response parsers --------------------------------------------------

    def _parse_llama_text(self, payload: dict) -> str:
        """
        Llama on Bedrock commonly returns:
        - {"generation": "..."}   OR
        - {"outputs":[{"text":"..."}], ...}
        """
        text = None

        if isinstance(payload.get("generation"), str):
            text = payload["generation"]
        elif isinstance(payload.get("outputs"), list) and payload["outputs"]:
            first = payload["outputs"][0]
            if isinstance(first, dict) and isinstance(first.get("text"), str):
                text = first["text"]

        if not text:
            logging.error(f"Unexpected Llama Bedrock response format: {payload}")
            raise RuntimeError("Unexpected Llama Bedrock response format (no text found)")

        return text.strip()

    def _parse_claude_text(self, payload: dict) -> str:
        """
        Claude on Bedrock may return EITHER:

        A) Newer/common schema (what you showed in logs):
           {
             "type":"message",
             "role":"assistant",
             "content":[{"type":"text","text":"..."}],
             ...
           }

        B) Older/wrapped schema (some integrations):
           {
             "output": {
               "message": { "content":[{"type":"text","text":"..."}] }
             }
           }
        """
        text_parts: list[str] = []

        # A) Top-level content list
        content = payload.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    text_parts.append(part["text"])

        # B) Wrapped output.message.content list
        if not text_parts:
            out = payload.get("output")
            if isinstance(out, dict):
                msg = out.get("message")
                if isinstance(msg, dict):
                    content2 = msg.get("content")
                    if isinstance(content2, list):
                        for part in content2:
                            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                                text_parts.append(part["text"])

        if not text_parts:
            logging.error(f"Unexpected Claude Bedrock response format: {payload}")
            raise RuntimeError("Unexpected Claude Bedrock response format (no text found)")

        return "\n".join(text_parts).strip()

    # --- Core completion method -------------------------------------------

    def get_completion(
        self,
        prompt: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """
        Generate a completion using the configured Bedrock model.

        Supports:
        - Llama 3.x style models using `prompt` format
        - Anthropic Claude-style models using `anthropic_version/messages`
        """
        max_tokens = int(max_tokens or self.default_max_tokens)
        temperature = float(self.default_temperature if temperature is None else temperature)

        logging.info(
            f"Calling Bedrock get_completion() with model_id={self.model_id}, "
            f"max_tokens={max_tokens}, temperature={temperature}"
        )

        # ---- Build request body depending on model family ----
        if self._is_llama():
            body = self._build_llama_body(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
        elif self._is_claude():
            body = self._build_claude_body(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
        else:
            raise RuntimeError(
                f"Unknown Bedrock model type for model_id={self.model_id}. "
                "Expected a Llama or Claude model/inference profile."
            )

        # ---- Call Bedrock ----
        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
        except ClientError as e:
            logging.error(f"Bedrock invoke_model failed: {e}")
            raise RuntimeError(f"Bedrock invoke_model failed: {e}") from e

        raw_body = response["body"].read()
        try:
            payload = json.loads(raw_body)
        except Exception as e:
            logging.error(f"Failed to parse Bedrock response body as JSON: {raw_body!r}")
            raise RuntimeError(f"Failed to parse Bedrock response JSON: {e}") from e

        # ---- Extract text depending on the model family ----
        try:
            if self._is_llama():
                return self._parse_llama_text(payload)
            if self._is_claude():
                return self._parse_claude_text(payload)

            # Should never hit due to earlier guard
            raise RuntimeError(f"No parser implemented for model_id={self.model_id}")

        except Exception as e:
            logging.error(f"Error extracting text from Bedrock response: {payload}")
            raise RuntimeError(f"Error extracting text from Bedrock response: {e}") from e

    # --- Parity helper with OpenAIHandler ---------------------------------

    def send_prompt(self, prompt: str) -> str:
        """Compatibility helper: mirror OpenAIHandler.send_prompt."""
        return self.get_completion(prompt, max_tokens=150)
