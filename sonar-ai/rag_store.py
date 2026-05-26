"""
SonarAI — RAG Store  (Iteration 2 + semantic deduplication)
ChromaDB-backed vector store for prior fix retrieval.

Workflow:
  1. After a successful fix, store_fix() embeds the fix context and saves it.
  2. Before planning, retrieve_similar_fixes() fetches the top-k most similar
     prior fixes by rule_key + method context embedding.
  3. The Planner prompt includes the retrieved examples as few-shot context.

Embeddings: VertexAI text-embedding-005 (768-dim) via langchain-google-vertexai.
Storage: ChromaDB persisted to disk at settings.chroma_persist_dir.

Deduplication (new in Iteration 2+):
  • Write-time: store_fix() skips storing if a near-identical fix already exists
    (cosine similarity >= DEDUP_THRESHOLD).
  • Read-time: retrieve_similar_fixes() applies Maximal Marginal Relevance (MMR)
    to ensure no two returned fixes are too similar to each other
    (pairwise similarity must stay below MMR_DIVERSITY_THRESHOLD).

Graceful degradation: if ChromaDB or Vertex embeddings are unavailable,
all public functions return empty results and log a warning — the pipeline
continues without RAG context.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Optional

import numpy as np
from loguru import logger

# Lazy imports so missing chromadb doesn't crash the entire pipeline
_chroma_client = None
_collection = None
_embed_fn = None

COLLECTION_NAME = "sonar_ai_fixes"
TOP_K = 3

# ── Deduplication thresholds ───────────────────────────────────────────────────
# Write-time: skip storing if nearest neighbour is already this similar.
DEDUP_THRESHOLD = 0.92

# Read-time MMR: drop a candidate if it's this similar to any already-selected result.
MMR_DIVERSITY_THRESHOLD = 0.80

# Fetch this many raw candidates from ChromaDB before MMR; must be >= top_k.
MMR_FETCH_MULTIPLIER = 3


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_embed_fn():
    """Return a VertexAIEmbeddings callable, cached."""
    global _embed_fn
    if _embed_fn is not None:
        return _embed_fn
    try:
        from langchain_google_vertexai import VertexAIEmbeddings
        from config import settings
        _embed_fn = VertexAIEmbeddings(
            model_name=settings.embedding_model,
            project=settings.gcp_project,
            location=settings.gcp_location,
        )
        logger.info(f"[RAG] Embeddings initialised: {settings.embedding_model}")
    except Exception as exc:
        logger.warning(f"[RAG] Could not initialise VertexAI embeddings: {exc}")
        _embed_fn = None
    return _embed_fn


def _get_collection():
    """Return (or create) the ChromaDB collection, cached."""
    global _chroma_client, _collection
    if _collection is not None:
        return _collection
    try:
        import chromadb
        from config import settings
        persist_dir = settings.chroma_persist_dir
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=persist_dir)
        _collection = _chroma_client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            f"[RAG] ChromaDB collection '{COLLECTION_NAME}' ready "
            f"({_collection.count()} documents) at {persist_dir}"
        )
    except Exception as exc:
        logger.warning(f"[RAG] ChromaDB unavailable: {exc}")
        _collection = None
    return _collection


def _embed(text: str) -> Optional[list[float]]:
    """Embed text using VertexAI; return None on any failure."""
    fn = _get_embed_fn()
    if fn is None:
        return None
    try:
        result = fn.embed_query(text)
        return result
    except Exception as exc:
        logger.warning(f"[RAG] Embedding failed: {exc}")
        return None


def _make_doc_id(rule_key: str, patch_hunks: str) -> str:
    """Stable SHA-based ID for a fix document."""
    content = f"{rule_key}:{patch_hunks}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _build_embed_text(rule_key: str, method_context: str, message: str) -> str:
    """Concatenate the fields most useful for similarity search."""
    return f"Rule: {rule_key}\nMessage: {message}\n\n{method_context[:1500]}"


def _cosine_sim(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two embedding vectors."""
    va, vb = np.array(a, dtype=np.float32), np.array(b, dtype=np.float32)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    return float(np.dot(va, vb) / denom) if denom > 0.0 else 0.0


def _mmr_deduplicate(
    candidates: list[dict[str, Any]],
    embeddings: list[list[float]],
    diversity_threshold: float = MMR_DIVERSITY_THRESHOLD,
) -> list[dict[str, Any]]:
    """
    Greedy Maximal Marginal Relevance pass.

    Iterates through candidates (already sorted by relevance, highest first) and
    keeps a result only if its maximum cosine similarity to every already-selected
    result is below `diversity_threshold`.  This ensures the returned set is both
    relevant and diverse — no two fixes are near-duplicates of each other.

    Args:
        candidates:          Fix dicts, sorted by descending similarity.
        embeddings:          Parallel list of embedding vectors for each candidate.
        diversity_threshold: Maximum allowed pairwise similarity (0–1).
                             Lower → more diverse; higher → more permissive.

    Returns:
        Deduplicated subset of candidates preserving input order.
    """
    selected: list[dict[str, Any]] = []
    selected_embeddings: list[list[float]] = []

    for i, (fix, emb) in enumerate(zip(candidates, embeddings)):
        if not selected_embeddings:
            # Always keep the top-relevance result.
            selected.append(fix)
            selected_embeddings.append(emb)
            continue

        max_sim = max(_cosine_sim(emb, sel_emb) for sel_emb in selected_embeddings)
        if max_sim < diversity_threshold:
            selected.append(fix)
            selected_embeddings.append(emb)
        else:
            logger.debug(
                f"[RAG] MMR dropped candidate #{i} (rule={fix.get('rule_key', '?')}, "
                f"file={fix.get('file_name', '?')}, "
                f"max_sim_to_selected={max_sim:.3f} >= threshold={diversity_threshold})"
            )

    return selected


# ── Public API ─────────────────────────────────────────────────────────────────

def retrieve_similar_fixes(
    rule_key: str,
    method_context: str,
    message: str,
    top_k: int = TOP_K,
) -> list[dict[str, Any]]:
    """
    Return up to top_k semantically diverse prior fixes from ChromaDB.

    Pipeline:
      1. Embed the query (rule_key + method_context + message).
      2. Fetch up to top_k * MMR_FETCH_MULTIPLIER raw candidates from ChromaDB,
         filtered by rule_key where possible.
      3. Apply a relevance floor (similarity >= 0.3).
      4. Apply MMR deduplication to eliminate near-identical results.
      5. Return at most top_k results.

    Each result dict has:
      patch_hunks  : str
      reasoning    : str
      confidence   : float
      file_name    : str
      rule_key     : str
      similarity   : float  (1 - cosine distance, rounded to 3 dp)

    Returns [] on any error or if ChromaDB / embeddings are unavailable.
    """
    collection = _get_collection()
    if collection is None:
        return []

    embed_text = _build_embed_text(rule_key, method_context, message)
    embedding = _embed(embed_text)
    if embedding is None:
        return []

    # Fetch more candidates than needed so MMR has room to select diverse results.
    total_docs = collection.count()
    if total_docs == 0:
        return []
    fetch_k = min(top_k * MMR_FETCH_MULTIPLIER, total_docs)

    try:
        where_filter = {"rule_key": {"$eq": rule_key}}
        try:
            result = collection.query(
                query_embeddings=[embedding],
                n_results=fetch_k,
                where=where_filter,
                include=["documents", "metadatas", "distances", "embeddings"],
            )
        except Exception:
            # Fewer docs than requested or no matching rule — retry without filter.
            result = collection.query(
                query_embeddings=[embedding],
                n_results=max(1, fetch_k),
                include=["documents", "metadatas", "distances", "embeddings"],
            )

        docs     = result.get("documents",  [[]])[0]
        metas    = result.get("metadatas",  [[]])[0]
        dists    = result.get("distances",  [[]])[0]
        embeds   = result.get("embeddings", [[]])[0]

        # Step 1 — relevance floor: drop results that are too dissimilar to be useful.
        candidates: list[dict[str, Any]] = []
        cand_embeddings: list[list[float]] = []

        for _doc, meta, dist, emb in zip(docs, metas, dists, embeds):
            similarity = max(0.0, 1.0 - dist)  # cosine: dist=0 → similarity=1
            if similarity < 0.3:
                continue
            candidates.append({
                "patch_hunks": meta.get("patch_hunks", ""),
                "reasoning":   meta.get("reasoning", ""),
                "confidence":  float(meta.get("confidence", 0.5)),
                "file_name":   meta.get("file_name", ""),
                "rule_key":    meta.get("rule_key", rule_key),
                "similarity":  round(similarity, 3),
            })
            cand_embeddings.append(emb)

        # Step 2 — MMR diversity pass: eliminate near-duplicate fixes.
        fixes = _mmr_deduplicate(candidates, cand_embeddings)[:top_k]

        logger.info(
            f"[RAG] Retrieved {len(fixes)} diverse fix(es) for rule={rule_key} "
            f"(from {len(candidates)} relevant candidates out of {fetch_k} fetched; "
            f"top similarity={fixes[0]['similarity'] if fixes else 'N/A'})"
        )
        return fixes

    except Exception as exc:
        logger.warning(f"[RAG] Query failed: {exc}")
        return []


def store_fix(
    rule_key: str,
    method_context: str,
    message: str,
    patch_hunks: str,
    reasoning: str,
    confidence: float,
    file_name: str,
) -> bool:
    """
    Embed and persist a successful fix to ChromaDB.

    Write-time deduplication: if the nearest existing fix has cosine similarity
    >= DEDUP_THRESHOLD the new fix is considered a near-duplicate and silently
    skipped (returns True — idempotent success).

    Returns True on success or skip, False on any hard error.
    Silently skips if ChromaDB or embeddings are unavailable.
    """
    collection = _get_collection()
    if collection is None:
        return False

    embed_text = _build_embed_text(rule_key, method_context, message)
    embedding = _embed(embed_text)
    if embedding is None:
        return False

    # ── Write-time dedup guard ─────────────────────────────────────────────────
    if collection.count() > 0:
        try:
            near = collection.query(
                query_embeddings=[embedding],
                n_results=1,
                include=["distances"],
            )
            top_dist = near["distances"][0][0] if near["distances"] else 1.0
            top_sim = max(0.0, 1.0 - top_dist)
            if top_sim >= DEDUP_THRESHOLD:
                logger.info(
                    f"[RAG] Skipping store — near-duplicate already exists "
                    f"(similarity={top_sim:.3f} >= threshold={DEDUP_THRESHOLD}) "
                    f"for rule={rule_key} file={file_name}"
                )
                return True  # idempotent: not an error
        except Exception as exc:
            logger.warning(f"[RAG] Dedup pre-check failed (proceeding to store): {exc}")
    # ── End dedup guard ────────────────────────────────────────────────────────

    doc_id = _make_doc_id(rule_key, patch_hunks)

    # Truncate for metadata storage (ChromaDB has a 512-byte limit per metadata value).
    patch_preview     = patch_hunks[:400]  if patch_hunks  else ""
    reasoning_preview = reasoning[:300]    if reasoning    else ""

    try:
        collection.upsert(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[embed_text],
            metadatas=[{
                "rule_key":    rule_key,
                "patch_hunks": patch_preview,
                "reasoning":   reasoning_preview,
                "confidence":  str(confidence),
                "file_name":   file_name,
                "message":     message[:200],
            }],
        )
        logger.info(
            f"[RAG] Stored fix for rule={rule_key} file={file_name} "
            f"(id={doc_id}, total_docs={collection.count()})"
        )
        return True
    except Exception as exc:
        logger.warning(f"[RAG] Failed to store fix: {exc}")
        return False


def collection_stats() -> dict[str, Any]:
    """Return basic stats about the ChromaDB collection."""
    collection = _get_collection()
    if collection is None:
        return {"available": False, "count": 0}
    try:
        return {
            "available": True,
            "count":     collection.count(),
            "name":      COLLECTION_NAME,
            "dedup_threshold":      DEDUP_THRESHOLD,
            "mmr_diversity_threshold": MMR_DIVERSITY_THRESHOLD,
        }
    except Exception:
        return {"available": False, "count": 0}