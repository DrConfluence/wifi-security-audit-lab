from assessment.session import create_session, is_in_scope


def test_authorized_session():
    session = create_session(
        "LAB-NET",
        "02:00:00:00:00:01",
        "LAB-001",
    )

    assert session["scope_status"] == "AUTHORIZED"
    assert is_in_scope(session)


def test_missing_authorization_is_out_of_scope():
    session = create_session("LAB-NET")

    assert session["scope_status"] == "UNAUTHORIZED"
    assert not is_in_scope(session)


def test_missing_ssid_is_out_of_scope():
    session = create_session(None, None, "LAB-001")

    assert not is_in_scope(session)
