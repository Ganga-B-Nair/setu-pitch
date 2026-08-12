import json

import pytest

from app import crypto
from app.models import Worker

VALID_WORKER_PAYLOAD = {
    "name": "Ramesh Patel",
    "age": 41,
    "gender": "male",
    "origin_state": "Rajasthan",
    "aadhaar_number": "123456789012",
}


def _register(client, auth_headers, **overrides):
    payload = {**VALID_WORKER_PAYLOAD, **overrides}
    return client.post("/worker", json=payload, headers=auth_headers)


def test_register_with_valid_unique_aadhaar_succeeds(client, auth_headers, db_session_factory):
    resp = _register(client, auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "token" in body
    assert "qr_code_base64" in body

    db = db_session_factory()
    try:
        worker = db.query(Worker).filter(Worker.token == body["token"]).one()
        assert worker.aadhaar_hash == crypto.hash_identifier("123456789012")
        assert worker.aadhaar_ciphertext != "123456789012"
    finally:
        db.close()


@pytest.mark.parametrize(
    "bad_aadhaar",
    [
        "12345",  # too short
        "1234567890123",  # too long
        "12345678901a",  # non-numeric
        "",  # empty
    ],
)
def test_register_with_malformed_aadhaar_returns_422(client, auth_headers, bad_aadhaar):
    resp = _register(client, auth_headers, aadhaar_number=bad_aadhaar)
    assert resp.status_code == 422


def test_register_with_missing_aadhaar_returns_422(client, auth_headers):
    payload = {k: v for k, v in VALID_WORKER_PAYLOAD.items() if k != "aadhaar_number"}
    resp = client.post("/worker", json=payload, headers=auth_headers)
    assert resp.status_code == 422


def test_register_duplicate_aadhaar_returns_409_no_duplicate_row(client, auth_headers, db_session_factory):
    first = _register(client, auth_headers, name="Ramesh Patel")
    assert first.status_code == 200

    second = _register(client, auth_headers, name="A Different Name Entirely")
    assert second.status_code == 409
    assert "already registered" in second.json()["detail"].lower()

    db = db_session_factory()
    try:
        matching = db.query(Worker).filter(Worker.aadhaar_hash == crypto.hash_identifier("123456789012")).all()
        assert len(matching) == 1
    finally:
        db.close()


def test_aadhaar_hash_duplicate_check_never_calls_decrypt(client, auth_headers, monkeypatch):
    first = _register(client, auth_headers)
    assert first.status_code == 200

    def boom(*args, **kwargs):
        raise AssertionError("decrypt_with_dek must not be called by the duplicate-check path")

    monkeypatch.setattr(crypto, "decrypt_with_dek", boom)

    # If the duplicate check ever decrypted stored Aadhaar numbers to
    # compare them, `boom` above would fire and this request would blow
    # up instead of cleanly returning 409.
    second = _register(client, auth_headers, name="Someone Else")
    assert second.status_code == 409


def test_full_aadhaar_number_never_appears_in_any_response(client, auth_headers):
    aadhaar = "987654321098"
    register_resp = _register(client, auth_headers, aadhaar_number=aadhaar)
    assert register_resp.status_code == 200
    assert aadhaar not in register_resp.text

    token = register_resp.json()["token"]

    get_resp = client.get(f"/worker/{token}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert aadhaar not in get_resp.text

    body = get_resp.json()
    assert aadhaar not in json.dumps(body)
    assert body["aadhaar_number"] == "XXXX-XXXX-1098"


def test_aadhaar_never_reaches_chain_blocks(client, auth_headers, db_session_factory):
    from app.models import ChainBlock

    aadhaar = "111122223333"
    resp = _register(client, auth_headers, aadhaar_number=aadhaar)
    assert resp.status_code == 200
    token = resp.json()["token"]

    db = db_session_factory()
    try:
        blocks = db.query(ChainBlock).filter(ChainBlock.worker_token == token).all()
        assert blocks, "expected a genesis chain block to be created"
        for block in blocks:
            assert aadhaar not in block.record_hash
            assert aadhaar not in block.block_hash
            assert crypto.hash_identifier(aadhaar) != block.record_hash
    finally:
        db.close()
