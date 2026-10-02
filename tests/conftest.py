import pytest
from pathlib import Path
import assessment.session as session_mod


@pytest.fixture(autouse=True)
def default_test_authorization(tmp_path_factory, monkeypatch):
    """
    Ensure the test suite has an isolated, valid authorization scope
    pointing to a dedicated test CSV file rather than any runtime file.
    Tests specifically testing missing, empty, or malformed authorization
    can pass auth_file or override session_mod.AUTH_FILE.
    """
    test_auth_dir = tmp_path_factory.mktemp("test_scope")
    test_auth_file = test_auth_dir / "authorized_networks.csv"
    test_auth_file.write_text(
        "ssid,bssid,authorization_ref,scope\n"
        "LAB-NET,02:00:00:00:00:01,LAB-001,Controlled laboratory assessment\n"
        "LAB-NETWORK,02:00:00:00:00:02,EXAMPLE-001,Controlled laboratory assessment\n"
        "LAB-GUEST,02:00:00:00:00:03,EXAMPLE-001,Controlled laboratory assessment\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(session_mod, "AUTH_FILE", test_auth_file)
