import base64
import io
import os

import qrcode
from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app import auth, chain, crypto
from app.database import Base, SessionLocal, engine, get_db
from app.models import ChainBlock, Record, User, Worker
from app.schemas import (
    LoginRequest,
    LoginResponse,
    RecordCreate,
    RecordOut,
    VerifyResponse,
    WorkerCreate,
    WorkerCreateResponse,
    WorkerOut,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Setu (fallback demo)")

# Demo-scope CORS: the Next.js dev server runs on a different origin.
# Tighten allow_origins before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000"),
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def seed_user():
    db = SessionLocal()
    try:
        username = os.environ.get("SEED_USERNAME", "clinic1")
        password = os.environ.get("SEED_PASSWORD", "changeme123")
        existing = db.query(User).filter(User.username == username).first()
        if not existing:
            # Single clinic_staff role seeded here. Full Setu seeds
            # clinic_staff / camp_official / health_admin accounts with
            # distinct scopes — see the role-check note in app/auth.py.
            db.add(User(username=username, hashed_password=auth.hash_password(password), role="clinic_staff"))
            db.commit()
    finally:
        db.close()


def _worker_or_404(db: Session, token: str) -> Worker:
    worker = db.query(Worker).filter(Worker.token == token).first()
    if worker is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Worker not found")
    return worker


def _make_qr_base64(data: str) -> str:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


@app.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not auth.verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = auth.create_access_token(user.username, user.role)
    return LoginResponse(access_token=token)


@app.post("/worker", response_model=WorkerCreateResponse)
def register_worker(
    body: WorkerCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user),
):
    dek = crypto.generate_dek()
    name_ciphertext = crypto.encrypt_with_dek(dek, body.name)
    name_dek = crypto.wrap_dek(dek)

    worker = Worker(
        name_ciphertext=name_ciphertext,
        name_dek=name_dek,
        age=body.age,
        gender=body.gender,
        origin_state=body.origin_state,
    )
    db.add(worker)
    db.commit()
    db.refresh(worker)

    record_hash = chain.compute_record_hash(
        {"name": body.name, "age": body.age, "gender": body.gender, "origin_state": body.origin_state}
    )
    chain.append_block(db, worker.token, record_hash, event_type="WORKER_REGISTERED")

    qr_b64 = _make_qr_base64(worker.token)
    return WorkerCreateResponse(token=worker.token, qr_code_base64=qr_b64)


@app.get("/worker/{token}", response_model=WorkerOut)
def get_worker(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user),
):
    worker = _worker_or_404(db, token)
    name = crypto.decrypt_with_dek(crypto.unwrap_dek(worker.name_dek), worker.name_ciphertext)

    records_out = []
    for r in worker.records:
        notes = crypto.decrypt_with_dek(crypto.unwrap_dek(r.notes_dek), r.notes_ciphertext)
        records_out.append(
            RecordOut(
                id=r.id,
                visit_type=r.visit_type,
                notes=notes,
                visit_date=r.visit_date,
                facility_id=r.facility_id,
                created_at=r.created_at.isoformat(),
            )
        )

    return WorkerOut(
        token=worker.token,
        name=name,
        age=worker.age,
        gender=worker.gender,
        origin_state=worker.origin_state,
        created_at=worker.created_at.isoformat(),
        records=records_out,
    )


@app.post("/worker/{token}/record", response_model=RecordOut)
def add_record(
    token: str,
    body: RecordCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user),
):
    worker = _worker_or_404(db, token)

    record_hash = chain.compute_record_hash(
        {
            "visit_type": body.visit_type,
            "notes": body.notes,
            "visit_date": body.visit_date,
            "facility_id": body.facility_id,
        }
    )

    dek = crypto.generate_dek()
    notes_ciphertext = crypto.encrypt_with_dek(dek, body.notes)
    notes_dek = crypto.wrap_dek(dek)

    record = Record(
        worker_id=worker.id,
        visit_type=body.visit_type,
        notes_ciphertext=notes_ciphertext,
        notes_dek=notes_dek,
        visit_date=body.visit_date,
        facility_id=body.facility_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    chain.append_block(db, worker.token, record_hash, event_type="RECORD_ADDED")

    return RecordOut(
        id=record.id,
        visit_type=record.visit_type,
        notes=body.notes,
        visit_date=record.visit_date,
        facility_id=record.facility_id,
        created_at=record.created_at.isoformat(),
    )


@app.get("/worker/{token}/verify", response_model=VerifyResponse)
def verify_worker_chain(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user),
):
    worker = _worker_or_404(db, token)
    result = chain.verify_chain(db, worker)
    return VerifyResponse(**result)


@app.post("/worker/{token}/simulate-tamper")
def simulate_tamper(token: str, db: Session = Depends(get_db)):
    """DEV ONLY. No auth check — deliberately overwrites the most recent
    record's ciphertext with different re-encrypted content, without
    touching the chain, so /verify can be demoed catching it live.
    """
    worker = _worker_or_404(db, token)
    if not worker.records:
        raise HTTPException(status_code=400, detail="Worker has no records to tamper with")

    record = worker.records[-1]
    dek = crypto.generate_dek()
    tampered_text = "TAMPERED: " + os.urandom(4).hex()
    record.notes_ciphertext = crypto.encrypt_with_dek(dek, tampered_text)
    record.notes_dek = crypto.wrap_dek(dek)
    db.commit()

    return {"detail": "record tampered", "record_id": record.id, "new_plaintext": tampered_text}
