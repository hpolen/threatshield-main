from openai import OpenAI
from utils.config import get_openai_api_key
import logging


class OpenAIHandler:
    """
    Thin wrapper around the OpenAI client.

    IMPORTANT:
    - This handler is ONLY for the real OpenAI API.
    - Bedrock is handled separately by BedrockHandler.
    """

    def __init__(self, model: str | None = None):
        self.method = "OPENAI"

        self.api_key = get_openai_api_key()
        if not self.api_key:
            logging.error("OpenAI API key not found")
            raise ValueError("OpenAI API key not found")

        # Default model – tweak if you want
        self.model = model or "gpt-4o"

        self._client = self._initialize_openai_client()

    @property
    def client(self) -> OpenAI:
        """Return the OpenAI client instance."""
        return self._client

    def _initialize_openai_client(self) -> OpenAI:
        try:
            logging.info("Initializing OpenAI client")

            client = OpenAI(api_key=self.api_key)

            # Optional: lightweight connectivity check
            logging.info("Testing OpenAI connection...")
            try:
                models = client.models.list()
                logging.info(
                    f"OpenAI connection successful. Available models: {len(models.data)}"
                )
            except Exception as e:
                logging.warning(f"Could not list OpenAI models: {str(e)}")
                logging.warning(
                    "Continuing with initialization, but subsequent API calls may fail"
                )

            return client

        except Exception as e:
            error_msg = f"Failed to initialize OpenAI client: {str(e)}"
            logging.error(error_msg)
            raise ConnectionError(error_msg)

    def send_prompt(self, prompt: str, max_tokens: int = 150) -> str:
        """
        Simple helper for short prompts (legacy usage).
        """
        try:
            logging.info(f"Sending prompt to OPENAI using model {self.model}")
            logging.debug(
                f"Prompt content: {prompt[:100]}..."
                if len(prompt) > 100
                else f"Prompt content: {prompt}"
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
            )

            logging.info("Successfully received response from OPENAI")
            return response.choices[0].message.content.strip()

        except Exception as e:
            error_msg = f"Error sending prompt to OPENAI: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def create_chat_template(self, template_name: str) -> str:
        """
        Placeholder helper – your code was just returning a string.
        """
        try:
            logging.info(
                f"Creating chat template '{template_name}' using OPENAI (placeholder)"
            )
            result = f"Chat template for {template_name} created"
            logging.info(f"Successfully created chat template '{template_name}'")
            return result
        except Exception as e:
            error_msg = f"Error creating chat template '{template_name}': {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def get_completion(self, prompt: str, max_tokens: int = 1000) -> str:
        """
        Main entry point used by the rest of the app for completions.
        """
        try:
            logging.info(
                f"Getting completion from OPENAI using model {self.model} "
                f"(max_tokens={max_tokens})"
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
            )

            logging.info("Successfully received completion from OPENAI")
            return response.choices[0].message.content.strip()

        except Exception as e:
            error_msg = f"Error getting completion from OPENAI: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)
