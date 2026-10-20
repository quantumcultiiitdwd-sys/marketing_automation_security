import os
import tempfile
import uuid

# TEST_DATABASE_URL runs the suite against Postgres (CI); default is a throwaway SQLite file.
_db = os.getenv("TEST_DATABASE_URL") or f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'test.db')}"
os.environ.update(DATABASE_URL=_db, APP_ENV="test", DEMO_ENABLED="true", RATE_LIMIT_PER_MINUTE="100000")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def client():
    return TestClient(app)


class Tenant:
    def __init__(self, client, name="Acme"):
        self.client = client
        r = client.post("/v1/auth/register", json={"email": f"{uuid.uuid4().hex[:8]}@example.com", "password": "correct-horse-1",
                                                   "organization_name": name})
        assert r.status_code == 201, r.text
        self.token = r.json()["token"]
        self.org_id = r.json()["organizations"][0]["id"]
        self.h = {"Authorization": f"Bearer {self.token}", "X-Org-Id": self.org_id}

    def get(self, path, **kw):
        return self.client.get(path, headers=self.h, **kw)

    def post(self, path, json=None, **kw):
        return self.client.post(path, headers=self.h, json=json, **kw)

    def patch(self, path, json=None):
        return self.client.patch(path, headers=self.h, json=json)

    def seed(self):
        r = self.post("/v1/demo/seed")
        assert r.status_code == 200, r.text
        return r.json()

    def agent_headers(self, key):
        return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def tenant(client):
    return Tenant(client)
