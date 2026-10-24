from websec_audit.checks.active_injection import _with_param


def test_with_param_preserves_other_params_and_sets_target_param():
    url = "https://example.com/search?q=test&page=1"
    out = _with_param(url, "q", "payload")
    assert "page=1" in out
    assert "payload" in out


def test_with_param_no_existing_query():
    url = "https://example.com/search"
    out = _with_param(url, "q", "payload")
    assert "q=payload" in out
