# rag/embeddings_factory.py

import os
import logging
from langchain_core.embeddings import Embeddings
from langchain_community.embeddings.bedrock import BedrockEmbeddings


def build_embeddings(method: str = "BEDROCK") -> Embeddings:
    """
    Bedrock-only embeddings factory.

    This intentionally does NOT support OpenAI embeddings and will NEVER fall back
    to OpenAI embeddings.

    Env vars:
      - AWS_REGION (default: us-east-1)
      - BEDROCK_EMBEDDING_MODEL_ID (default: amazon.titan-embed-text-v2:0)
    """
    method = (method or "").upper().strip()
    if method != "BEDROCK":
        raise ValueError(
            f"Embeddings provider must be BEDROCK (got '{method}'). "
            f"Set EMBEDDINGS_METHOD=BEDROCK."
        )

    region = os.getenv("AWS_REGION", "us-east-1")
    model_id = os.getenv("BEDROCK_EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0")

    logging.info(f"[Embeddings] Using BEDROCK embeddings only. region={region}, model_id={model_id}")

    return BedrockEmbeddings(
        region_name=region,
        model_id=model_id,
    )
