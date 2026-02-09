# rag/rag_handler.py

import os
import uuid
import json
import base64
import logging
import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma

from llm.openai_module import OpenAIHandler
from utils.config import get_llm_method
from utils.storage import StorageHandler

# ✅ Bedrock-only embeddings factory
from rag.embeddings_factory import build_embeddings

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


@dataclass
class Prompt:
    system_context: str
    task: str
    query: Optional[str] = None
    format: Optional[Any] = None
    example: Optional[str] = None
    instructions: Optional[str] = None


class PromptManager:
    def __init__(self, prompt_file: str = "rag/prompts.json"):
        self.prompts: Dict[str, Prompt] = {}
        self._load_prompts(prompt_file)

    def _load_prompts(self, prompt_file: str) -> None:
        try:
            with open(prompt_file, "r") as f:
                data = json.load(f)
                self.prompts = {key: Prompt(**value) for key, value in data.items()}
        except Exception as e:
            logging.error(f"Error loading prompts: {e}")
            raise

    def get_prompt(self, key: str, **kwargs) -> Prompt:
        prompt = self.prompts.get(key)
        if not prompt:
            raise ValueError(f"Prompt '{key}' not found")

        # NOTE: Mutates prompt (existing behavior). If prompts “stick”, clone per call.
        if kwargs:
            prompt.task = prompt.task.format(**kwargs)
            if prompt.query:
                prompt.query = prompt.query.format(**kwargs)
        return prompt


class RAGHandler:
    def __init__(
        self,
        openai_handler: OpenAIHandler,
        persist_dir: str,
        assessment_id: str,
        table_name: str = "docs",
    ):
        self.openai_handler = openai_handler
        self.persist_dir = str(Path(persist_dir) / str(uuid.uuid4()))
        self.table_name = table_name

        self.prompt_manager = PromptManager()
        self.client = openai_handler.client

        # LLM provider (chat/completions)
        self.method = get_llm_method()

        # ✅ Embeddings provider (independent of LLM provider)
        # You said: no OpenAI embeddings ever → default to BEDROCK
        self.embeddings_method = os.getenv("EMBEDDINGS_METHOD", "BEDROCK").upper().strip()

        self.storage_handler = StorageHandler()
        self.assessment_id = assessment_id

        logging.info(f"Initializing RAG with LLM={self.method} for assessment {assessment_id}")
        logging.info(f"Initializing embeddings with provider={self.embeddings_method}")

        # ✅ Bedrock embeddings only
        self.embeddings = build_embeddings(self.embeddings_method)

        self.vectordb: Optional[Chroma] = None

    def get_completion(self, prompt: str, max_tokens: int = 1000) -> str:
        """Get completion from the LLM (still OpenAI in your case)."""
        try:
            logging.info(f"Getting completion from {self.method} using model {self.openai_handler.model}")

            params = {
                "model": self.openai_handler.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
            }

            if self.method == "OPENAI":
                params["temperature"] = 0.1

            response = self.client.chat.completions.create(**params)
            return response.choices[0].message.content.strip()
        except Exception as e:
            logging.error(f"Error getting completion from {self.method}: {str(e)}")
            raise RuntimeError(f"Error getting completion from {self.method}: {str(e)}")

    def split_documents(self, documents: List[Any]) -> List[Any]:
        if not documents:
            print("[DEBUG] ERROR: Empty document list provided to split_documents")
            raise ValueError("Empty document list provided")

        print(f"[DEBUG] split_documents: Processing {len(documents)} documents")

        for i, doc in enumerate(documents):
            content = doc.page_content if hasattr(doc, "page_content") else str(doc)
            content_length = len(content)
            logging.info(f"Document {i+1} content length: {content_length}")
            print(f"[DEBUG] Document {i+1} content length: {content_length}")

            if content_length > 0:
                sample = content[:100] + "..." if content_length > 100 else content
                print(f"[DEBUG] Document {i+1} first 100 chars: {sample}")
            else:
                print(f"[DEBUG] WARNING: Document {i+1} is empty")

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=2000,
            chunk_overlap=100,
            separators=["\n\n", "\n", ".", " ", ""],
            keep_separator=True,
        )
        print("[DEBUG] Using text splitter with chunk_size=2000, chunk_overlap=100")

        all_splits = []
        for i, doc in enumerate(documents):
            try:
                text = doc.page_content if hasattr(doc, "page_content") else str(doc)
                if not text.strip():
                    print(f"[DEBUG] WARNING: Document {i+1} contains only whitespace")
                    continue

                print(f"[DEBUG] Splitting document {i+1} with length {len(text)}")

                text_chunks = text_splitter.split_text(text)
                if not text_chunks:
                    print(f"[DEBUG] WARNING: Document {i+1} generated no text chunks")
                    continue

                doc_chunks = []
                for j, chunk in enumerate(text_chunks):
                    if chunk.strip():
                        doc_chunks.append(
                            {
                                "page_content": chunk,
                                "metadata": {
                                    "source": f"document_{i+1}",
                                    "chunk": j + 1,
                                    "total_chunks": len(text_chunks),
                                },
                            }
                        )

                if doc_chunks:
                    all_splits.extend(doc_chunks)

            except Exception as e:
                logging.error(f"Error splitting document {i+1}: {str(e)}")
                print(f"[DEBUG] ERROR splitting document {i+1}: {str(e)}")
                continue

        if not all_splits:
            raise ValueError("No valid chunks were generated from the documents.")

        logging.info(f"Total: Created {len(all_splits)} chunks from {len(documents)} documents")
        return all_splits

    def create_vector_db(self, documents: List[Any]) -> Chroma:
        logging.info(f"Creating or loading vector database for {self.persist_dir}")
        print(f"[DEBUG] Creating or loading vector database for {self.persist_dir}")

        if not documents:
            raise ValueError("No documents provided for vector database creation")

        from langchain_core.documents import Document

        processed_docs = []
        for doc in documents:
            if isinstance(doc, dict):
                processed_docs.append(Document(page_content=doc["page_content"], metadata=doc.get("metadata", {})))
            else:
                processed_docs.append(doc)

        if os.path.exists(self.persist_dir):
            db = Chroma(
                persist_directory=self.persist_dir,
                embedding_function=self.embeddings,
                collection_name=self.table_name,
            )
            return db

        db = Chroma.from_documents(
            documents=processed_docs,
            embedding=self.embeddings,
            persist_directory=self.persist_dir,
            collection_metadata={"hnsw:space": "cosine"},
            collection_name=self.table_name,
        )
        return db

    def setup_documents(self, documents: List[Any]) -> None:
        if not documents:
            raise ValueError("Documents list is empty")

        splits = self.split_documents(documents)
        self.vectordb = self.create_vector_db(splits)
        print(f"[DEBUG] Vector database created with {self.vectordb._collection.count()} documents")

    def get_context(self, query: str) -> str:
        if not self.vectordb:
            raise RuntimeError("Vector database is not initialized. Call setup_documents() first.")

        collection_size = self.vectordb._collection.count()
        k = min(10, collection_size)

        retriever = self.vectordb.as_retriever(search_type="similarity", search_kwargs={"k": k})
        docs = retriever.get_relevant_documents(query)

        context = "".join(doc.page_content for doc in docs)
        return context

    def ask_ai(self, prompt_key: str, context: str, **kwargs) -> str:
        try:
            prompt_data = self.prompt_manager.get_prompt(prompt_key, **kwargs)

            system_template = f"{prompt_data.system_context}\nONLY use provided context = {context} to answer."
            if prompt_data.format:
                if isinstance(prompt_data.format, list):
                    system_template += f"\n\nRequired format:\n" + "\n".join(prompt_data.format)
                else:
                    system_template += f"\n\nRequired format: {prompt_data.format}"

            if prompt_data.example:
                system_template += f"\n\nExample: {prompt_data.example}"

            messages = [
                {"role": "system", "content": system_template},
                {"role": "user", "content": f"{prompt_data.task}\n<question>{prompt_data.task}</question>"},
            ]

            params = {
                "model": self.openai_handler.model,
                "messages": messages,
                "max_tokens": 2000,
            }

            if self.method == "OPENAI":
                params["temperature"] = 0.1

            response = self.client.chat.completions.create(**params)
            return response.choices[0].message.content.strip()

        except Exception as e:
            logging.error(f"Error in ask_ai: {str(e)}")
            raise RuntimeError(f"Error in ask_ai: {str(e)}")

    def process_section(self, section_key: str, **kwargs) -> str:
        prompt_data = self.prompt_manager.get_prompt(section_key)
        if not prompt_data.query:
            return self.ask_ai(section_key, "", **kwargs)

        context = self.get_context(prompt_data.query)
        return self.ask_ai(section_key, context, **kwargs)

    # -------------------------
    # ✅ Image fixes (OpenAI format)
    # -------------------------

    def encode_image(self, image_path: str) -> Dict[str, str]:
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")

        ext = os.path.splitext(image_path)[1].lower()
        if ext == ".png":
            mime = "image/png"
        elif ext in [".jpg", ".jpeg"]:
            mime = "image/jpeg"
        elif ext == ".webp":
            mime = "image/webp"
        else:
            mime = "image/png"

        with open(image_path, "rb") as image_file:
            b64 = base64.b64encode(image_file.read()).decode("utf-8")

        return {"mime": mime, "b64": b64}

    def analyze_architecture_diagram(self, encoded_image_b64: str, mime: str = "image/png") -> Dict[str, Any]:
        try:
            prompt_data = self.prompt_manager.get_prompt("architecture_analysis")
            system_message = f"{prompt_data.system_context} \n Required output format: {prompt_data.format}"
            image_data_url = f"data:{mime};base64,{encoded_image_b64}"

            messages = [
                {"role": "system", "content": system_message},
                {
                    "role": "user",
                    "content": [
                        # ✅ Correct OpenAI schema: image_url must be an object with url
                        {"type": "image_url", "image_url": {"url": image_data_url}},
                        {"type": "text", "text": prompt_data.task},
                    ],
                },
            ]

            params = {
                "model": self.openai_handler.model,
                "messages": messages,
                "max_tokens": 2000,
            }

            if self.method == "OPENAI":
                params["temperature"] = 0.1
                params["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**params)
            services = response.choices[0].message.content.strip()

            cleaned_json = services.replace("```json", "").replace("```", "").strip()
            json_services = json.loads(cleaned_json)

            # Validate format strictly
            if not isinstance(json_services, dict) or "services" not in json_services:
                raise ValueError("Response must be a JSON object with key 'services'")
            if not isinstance(json_services["services"], list) or not json_services["services"]:
                raise ValueError("'services' must be a non-empty array")
            if not all(isinstance(s, dict) and "Name" in s and isinstance(s["Name"], str) for s in json_services["services"]):
                raise ValueError("Each service must be an object containing a string field 'Name'")

            os.makedirs("files", exist_ok=True)
            self.save_to_file("files/microservices.json", json_services)
            return json_services

        except Exception as e:
            logging.error(f"Error in architecture diagram analysis: {e}")
            raise

    def rag_image(self, path: str) -> Dict[str, Any]:
        payload = self.encode_image(path)
        return self.analyze_architecture_diagram(payload["b64"], payload["mime"])

    # -------------------------
    # File output helpers
    # -------------------------

    def save_to_file(self, filepath: str, content: Any, mode: str = "w") -> None:
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, mode, encoding="utf-8") as f:
                if isinstance(content, dict):
                    json.dump(content, f, indent=4)
                else:
                    f.write(f"{content}\n")
        except Exception as e:
            logging.error(f"Error saving to file: {e}")
            raise

    def append_to_file(self, content: str) -> None:
        self.save_to_file("files/outputreport.txt", content, mode="a")

    def rag_main(self, documents: List[Any]) -> str:
        logging.info("Starting RAG main process")
        print(f"[DEBUG] rag_main: Starting RAG process with {len(documents)} documents")

        self.setup_documents(documents)
        prompt = ""

        collection_size = self.vectordb._collection.count() if self.vectordb else 0
        if collection_size == 0:
            raise ValueError("No documents were successfully processed and embedded")

        sections = ["introduction", "functional_flows", "third_party_integrations"]
        section_contexts = {}
        section_results = {}

        for section in sections:
            prompt_data = self.prompt_manager.get_prompt(section)
            if prompt_data.query:
                section_contexts[section] = self.get_context(prompt_data.query)

        for section in sections:
            section_header = f"\n# {section.replace('_', ' ').title()}\n"
            self.append_to_file(section_header)
            prompt += section_header

            context = section_contexts.get(section, "")
            result = self.ask_ai(section, context)

            if section in ["functional_flows", "third_party_integrations"]:
                clean_result = result.replace(f"# {section.replace('_', ' ').title()}\n", "")
                clean_result = clean_result.replace(f"# {section.replace('_', ' ').title()}", "")
                section_results[section] = clean_result.strip()
            else:
                section_results[section] = result

            self.append_to_file(result)
            prompt += result

        # Update additionalinfo.json
        try:
            additional_info_path = os.path.join("storage", self.assessment_id, "additionalinfo.json")

            if os.path.exists(additional_info_path):
                with open(additional_info_path, "r") as f:
                    enhanced_info = json.load(f)
            else:
                enhanced_info = {}

            enhanced_info["functional_flows"] = section_results.get("functional_flows")
            enhanced_info["third_party_integrations"] = section_results.get("third_party_integrations")

            os.makedirs(os.path.dirname(additional_info_path), exist_ok=True)
            with open(additional_info_path, "w") as f:
                json.dump(enhanced_info, f, indent=2)

        except Exception as e:
            logging.error(f"Error updating additionalinfo.json for assessment {self.assessment_id}: {str(e)}")

        # Microservice summaries
        ms_header = "\n# Microservice Summaries\n"
        self.append_to_file(ms_header)
        prompt += ms_header

        with open("files/microservices.json", "r", encoding="utf-8") as f:
            services = json.load(f)
            service_names = [service["Name"] for service in services["services"]]

        service_contexts = {}
        for service in service_names:
            prompt_data = self.prompt_manager.get_prompt("microservice_summary")
            if prompt_data.query:
                query = prompt_data.query.format(service=service)
                service_contexts[service] = self.get_context(query)

        for service in service_names:
            service_header = f"\n## {service} Microservice\n"
            self.append_to_file(service_header)
            prompt += service_header

            context = service_contexts.get(service, "")
            result = self.ask_ai("microservice_summary", context, service=service)

            self.append_to_file(result)
            prompt += result

        logging.info("RAG main process completed")
        return prompt
