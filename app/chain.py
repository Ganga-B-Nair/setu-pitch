"""Tamper-evident hash chain over worker records.

Each worker has their own chain of blocks. A block commits to the
SHA-256 hash of a record's PLAINTEXT content (computed before
encryption) plus the hash of the previous block, so:

  - editing a record's stored ciphertext without going through the API
    changes what it decrypts to, which changes the recomputed
    record_hash, which no longer matches the hash committed in its
    block (detects tampering with the data itself)
  - editing/deleting/reordering a chain_blocks row breaks the
    prev_hash -> block_hash linkage to its neighbors (detects
    tampering with the chain itself)
"""

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import crypto
from app.models import ChainBlock

GENESIS_PREV_HASH = "0" * 64


def compute_record_hash(record_content: dict) -> str:
    canonical = json.dumps(record_content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_block_hash(worker_token: str, record_hash: str, prev_hash: str, timestamp: str) -> str:
    payload = f"{worker_token}{record_hash}{prev_hash}{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()


def append_block(db: Session, worker_token: str, record_hash: str, event_type: str) -> ChainBlock:
    last_block = (
        db.query(ChainBlock)
        .filter(ChainBlock.worker_token == worker_token)
        .order_by(ChainBlock.id.desc())
        .first()
    )
    prev_hash = last_block.block_hash if last_block else GENESIS_PREV_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    block_hash = compute_block_hash(worker_token, record_hash, prev_hash, timestamp)

    block = ChainBlock(
        worker_token=worker_token,
        record_hash=record_hash,
        prev_hash=prev_hash,
        block_hash=block_hash,
        event_type=event_type,
        timestamp=timestamp,
    )
    db.add(block)
    db.commit()
    db.refresh(block)
    return block


def _worker_content(worker) -> dict:
    name = crypto.decrypt_with_dek(crypto.unwrap_dek(worker.name_dek), worker.name_ciphertext)
    return {
        "name": name,
        "age": worker.age,
        "gender": worker.gender,
        "origin_state": worker.origin_state,
    }


def _record_content(record) -> dict:
    notes = crypto.decrypt_with_dek(crypto.unwrap_dek(record.notes_dek), record.notes_ciphertext)
    return {
        "visit_type": record.visit_type,
        "notes": notes,
        "visit_date": record.visit_date,
        "facility_id": record.facility_id,
    }


def verify_chain(db: Session, worker) -> dict:
    blocks = (
        db.query(ChainBlock)
        .filter(ChainBlock.worker_token == worker.token)
        .order_by(ChainBlock.id.asc())
        .all()
    )
    records = list(worker.records)

    if not blocks:
        return {"status": "FAILED", "broken_at_block_id": None, "reason": "no chain blocks found for worker"}

    record_idx = 0
    expected_prev = GENESIS_PREV_HASH

    for block in blocks:
        if block.prev_hash != expected_prev:
            return {
                "status": "FAILED",
                "broken_at_block_id": block.id,
                "reason": "chain linkage broken: prev_hash does not match the previous block's block_hash",
            }

        try:
            if block.event_type == "WORKER_REGISTERED":
                content = _worker_content(worker)
            else:
                if record_idx >= len(records):
                    return {
                        "status": "FAILED",
                        "broken_at_block_id": block.id,
                        "reason": "chain has more blocks than records exist for this worker",
                    }
                content = _record_content(records[record_idx])
                record_idx += 1
        except Exception:
            return {
                "status": "FAILED",
                "broken_at_block_id": block.id,
                "reason": "could not decrypt data referenced by this block (ciphertext or DEK corrupted)",
            }

        actual_record_hash = compute_record_hash(content)
        if actual_record_hash != block.record_hash:
            return {
                "status": "FAILED",
                "broken_at_block_id": block.id,
                "reason": "record hash mismatch: underlying data does not match the hash committed in this block (data was tampered with)",
            }

        expected_block_hash = compute_block_hash(block.worker_token, block.record_hash, block.prev_hash, block.timestamp)
        if expected_block_hash != block.block_hash:
            return {
                "status": "FAILED",
                "broken_at_block_id": block.id,
                "reason": "block hash mismatch: this block's stored hash does not match its own contents (block row was tampered with)",
            }

        expected_prev = block.block_hash

    return {"status": "VERIFIED", "broken_at_block_id": None, "reason": None}
