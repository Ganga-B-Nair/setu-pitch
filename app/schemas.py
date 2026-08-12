from typing import Optional, List

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class WorkerCreate(BaseModel):
    name: str
    age: int
    gender: str
    origin_state: str


class WorkerCreateResponse(BaseModel):
    token: str
    qr_code_base64: str


class RecordCreate(BaseModel):
    visit_type: str
    notes: str
    visit_date: str
    facility_id: str


class RecordOut(BaseModel):
    id: int
    visit_type: str
    notes: str
    visit_date: str
    facility_id: str
    created_at: str


class WorkerOut(BaseModel):
    token: str
    name: str
    age: int
    gender: str
    origin_state: str
    created_at: str
    records: List[RecordOut]


class VerifyResponse(BaseModel):
    status: str
    broken_at_block_id: Optional[int]
    reason: Optional[str]
