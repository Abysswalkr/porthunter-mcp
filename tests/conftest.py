import os
import pytest
from pathlib import Path

@pytest.fixture(scope="session", autouse=True)
def _env_setup():
    # Token y sandbox para que el server acepte llamadas
    os.environ["PORT_HUNTER_TOKEN"] = "TEST_TOKEN"
    # En CI: usar el workspace. En local: raíz del repo
    repo_root = Path(__file__).resolve().parents[1]
    allowed = os.getenv("GITHUB_WORKSPACE", str(repo_root))
    os.environ["PORT_HUNTER_ALLOWED_DIR"] = allowed
