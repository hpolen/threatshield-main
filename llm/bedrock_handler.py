# llm/bedrock_handler.py

import os
import json
import logging
import boto3
from botocore.exceptions import ClientError


class BedrockHandler:
    """
    Thin wrapper around AWS Bedrock that exposes a similar interface to OpenAIHandler:

    - .method            -> "BEDROCK" (for logging / branching)
    - .model             -> model_id used on Bedrock
    - get_completion()   -> main entry point
    - send_prompt()      -> small convenience wrapper
    """

    def __init__(
        self,
        model_id: str | None = None,
        region: str | None = None,
        default_max_tokens: int | None = None,
        default_temperature: float | None = None,
    ):
        # For compatibility with the rest of the app
        self.method = "BEDROCK"

        # Region & model configuration
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.model_id = (model_id or os.getenv("BEDROCK_MODEL_ID", "")).strip()

        if not self.model_id:
            raise ValueError(
                "BEDROCK_MODEL_ID is not set. "
                "Set it in your environment or pass model_id= when creating BedrockHandler."
            )

        # Defaults can be overridden via env or constructor
        self.default_max_tokens = default_max_tokens or int(
            os.getenv("BEDROCK_MAX_TOKENS", "1200")
        )
        self.default_temperature = (
            default_temperature
            if default_temperature is not None
            else float(os.getenv("BEDROCK_TEMPERATURE", "0.2"))
        )

        # Bedrock runtime client
        self.client = boto3.client("bedrock-runtime", region_name=self.region)

        logging.info(
            f"Initialized BedrockHandler with model_id={self.model_id} region={self.region}"
        )

    # --- Small helpers -----------------------------------------------------

    @property
    def model(self) -> str:
        """For parity with OpenAIHandler.model"""
        return self.model_id

    def _is_llama(self) -> bool:
        """Heuristic: Llama models usually include 'llama' / 'meta' in their ID."""
        mid = self.model_id.lower()
        return "llama" in mid or "meta." in mid

    def _is_claude(self) -> bool:
        mid = self.model_id.lower()
        return "claude" in mid or "anthropic" in mid

    # --- Core completion method -------------------------------------------

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
        - Llama 3.x style models (meta.llama3-1-*) using the new `prompt` format
        - Anthropic Claude-style models via anthropic_version/messages
        """
        max_tokens = max_tokens or self.default_max_tokens
        temperature = (
            self.default_temperature if temperature is None else float(temperature)
        )

        logging.info(
            f"Calling Bedrock get_completion() with model_id={self.model_id}, "
            f"max_tokens={max_tokens}, temperature={temperature}"
        )

        # ---- Build the request body depending on model family ----
        if self._is_llama():
            # ✅ Llama 3.1 request format (no inputText / textGenerationConfig)
            body = {
                "prompt": prompt,
                "max_gen_len": max_tokens,
                "temperature": temperature,
                "top_p": 0.9,
            }

        elif self._is_claude():
            # Anthropic-on-Bedrock style request body
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt}
                        ],
                    }
                ],
            }

        else:
            # If you ever add other models, branch here
            raise RuntimeError(
                f"Unknown Bedrock model type for model_id={self.model_id} – "
                f"update BedrockHandler.get_completion to support it."
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
            logging.error(
                f"Failed to parse Bedrock response body as JSON: {raw_body!r}"
            )
            raise RuntimeError(f"Failed to parse Bedrock response JSON: {e}") from e

        # ---- Extract the text depending on the model family ----
        try:
            if self._is_llama():
                # Llama 3.x on Bedrock typically returns a top-level "generation"
                text = None

                if isinstance(payload, dict):
                    # Preferred key
                    if isinstance(payload.get("generation"), str):
                        text = payload["generation"]
                    # Some variants may wrap in "outputs"
                    elif isinstance(payload.get("outputs"), list) and payload["outputs"]:
                        first = payload["outputs"][0]
                        if isinstance(first, dict) and isinstance(first.get("text"), str):
                            text = first["text"]

                if not text:
                    logging.error(f"Unexpected Llama Bedrock response format: {payload}")
                    raise RuntimeError("Unexpected Llama Bedrock response format")

                return text.strip()

            elif self._is_claude():
                # Anthropic-on-Bedrock standard structure
                text = payload["output"]["message"]["content"][0]["text"]
                return text.strip()

            else:
                # Should not hit here because of earlier guard
                raise RuntimeError(
                    f"No parser implemented for model_id={self.model_id}"
                )

        except Exception as e:
            logging.error(f"Error extracting text from Bedrock response: {payload}")
            raise RuntimeError(f"Error extracting text from Bedrock response: {e}") from e


    # --- Parity helper with OpenAIHandler ---------------------------------

    def send_prompt(self, prompt: str) -> str:
        """Compatibility helper: mirror OpenAIHandler.send_prompt."""
        return self.get_completion(prompt, max_tokens=150)
