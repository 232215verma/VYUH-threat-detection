"""
NetGraph Sentinel — Phase 8: RAG-based Alert Explanation

Retrieval-Augmented Generation layer. Does NOT detect threats — the graph,
rules, and ML layers (Phase 2/3) already do that. This sits AFTER
detection and turns a raw alert into a clear, human-readable explanation.

Pipeline:
    1. Embed the alert + retrieve the most relevant knowledge base entries
       (sentence-transformers + FAISS, both fully local/offline)
    2. Feed alert + retrieved knowledge to a LOCAL LLM via Ollama
    3. If Ollama isn't running, fall back to a template-built explanation
       using the retrieved knowledge directly (no LLM needed) — so this
       optional layer never breaks the rest of the system.

Requires (separately installed, not via pip):
    - Ollama running locally: https://ollama.com
    - A pulled model, e.g.: `ollama pull llama3.2`
"""

import json
import requests
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss

from knowledge_base import KNOWLEDGE_BASE

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

_embedder = None
_index = None
_kb_texts = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _embedder


def _build_index():
    """Build the FAISS index over the knowledge base once, lazily."""
    global _index, _kb_texts
    if _index is not None:
        return

    embedder = _get_embedder()
    _kb_texts = [entry["text"] for entry in KNOWLEDGE_BASE]
    embeddings = embedder.encode(_kb_texts, convert_to_numpy=True)
    embeddings = embeddings.astype("float32")

    dimension = embeddings.shape[1]
    _index = faiss.IndexFlatL2(dimension)
    _index.add(embeddings)


def retrieve_context(alert: dict, top_k: int = 2) -> list[dict]:
    """Return the top_k most relevant knowledge base entries for this alert."""
    _build_index()
    embedder = _get_embedder()

    query = f"{alert['type']} attack. " + " ".join(alert.get("evidence", []))
    query_vec = embedder.encode([query], convert_to_numpy=True).astype("float32")

    distances, indices = _index.search(query_vec, top_k)
    return [KNOWLEDGE_BASE[i] for i in indices[0] if i < len(KNOWLEDGE_BASE)]


def _template_explanation(alert: dict, entries: list[dict]) -> str:
    """No-LLM fallback: build a readable explanation directly from the KB."""
    if not entries:
        return f"No additional context available for this {alert['type']} alert."

    primary = entries[0]
    lines = [
        f"This matches MITRE technique {primary['mitre_id']} ({primary['mitre_name']}).",
        primary["text"],
        f"Recommended: {primary['recommended_action']}",
    ]
    return " ".join(lines)


def _call_ollama(prompt: str, timeout: int = 15) -> str | None:
    """Call the local Ollama server. Returns None if unreachable/unavailable."""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception:
        return None


def explain_alert(alert: dict) -> dict:
    """
    Main entry point. Returns:
        {
            "explanation": str,
            "mitre_id": str | None,
            "mitre_name": str | None,
            "recommended_action": str | None,
            "source": "ollama" | "template",
        }
    """
    entries = retrieve_context(alert)
    primary = entries[0] if entries else None

    context_text = "\n".join(
        f"- {e['mitre_id']} ({e['mitre_name']}): {e['text']} Recommended action: {e['recommended_action']}"
        for e in entries
    )

    prompt = f"""You are a security analyst assistant. Explain the following network alert to another analyst in 2-3 clear sentences, then give one recommended next step. Be concise and factual.

Alert type: {alert['type']}
Source: {alert.get('source')}
Target: {alert.get('target')}
Confidence: {alert.get('confidence')}
Evidence: {'; '.join(alert.get('evidence', []))}

Relevant knowledge:
{context_text}

Respond in plain text, no headers or markdown."""

    llm_response = _call_ollama(prompt)

    if llm_response:
        return {
            "explanation": llm_response,
            "mitre_id": primary["mitre_id"] if primary else None,
            "mitre_name": primary["mitre_name"] if primary else None,
            "recommended_action": primary["recommended_action"] if primary else None,
            "source": "ollama",
        }

    return {
        "explanation": _template_explanation(alert, entries),
        "mitre_id": primary["mitre_id"] if primary else None,
        "mitre_name": primary["mitre_name"] if primary else None,
        "recommended_action": primary["recommended_action"] if primary else None,
        "source": "template",
    }