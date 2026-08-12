import re
from typing import Optional, List

from pydantic import BaseModel, field_validator

AADHAAR_PATTERN = re.compile(r"^\d{12}$")


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
    aadhaar_number: str

    @field_validator("aadhaar_number")
    @classmethod
    def validate_aadhaar_number(cls, value: str) -> str:
        if not AADHAAR_PATTERN.match(value):
            raise ValueError("Aadhaar number must be exactly 12 digits")
        return value


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
    aadhaar_number: str  # always masked, e.g. "XXXX-XXXX-1234"
    created_at: str
    records: List[RecordOut]


class VerifyResponse(BaseModel):
    status: str
    broken_at_block_id: Optional[int]
    reason: Optional[str]
