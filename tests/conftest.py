import os

from cryptography.fernet import Fernet

# Must be set before `app.main` (and anything it imports) is loaded, since
# app.crypto/app.auth read these lazily from os.environ.
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("KEK_SECRET", Fernet.generate_key().decode())
os.environ.setdefault("SEED_USERNAME", "clinic1")
os.environ.setdefault("SEED_PASSWORD", "changeme123")
os.environ.setdefault("FRONTEND_ORIGIN", "http://localhost:3000")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth
from app.database import Base, get_db
from app.models import User
import app.main as main_module


@pytest.fixture()
def db_session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture()
def client(db_session_factory):
    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    main_module.app.dependency_overrides[get_db] = override_get_db

    db = db_session_factory()
    db.add(
        User(
            username="clinic1",
            hashed_password=auth.hash_password("changeme123"),
            role="clinic_staff",
        )
    )
    db.commit()
    db.close()

    with TestClient(main_module.app) as test_client:
        yield test_client

    main_module.app.dependency_overrides.clear()


@pytest.fixture()
def auth_headers():
    token = auth.create_access_token("clinic1", "clinic_staff")
    return {"Authorization": f"Bearer {token}"}
