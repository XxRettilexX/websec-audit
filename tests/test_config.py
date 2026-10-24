import pytest

from websec_audit.config import ConfigError, build_single_target


def test_passive_target_does_not_require_authorization():
    t = build_single_target("https://example.com", active=False, i_own_this_target=False)
    assert t.mode == "passive"


def test_active_target_requires_authorization_flag():
    with pytest.raises(ConfigError):
        build_single_target("https://example.com", active=True, i_own_this_target=False)


def test_active_target_with_authorization_flag_is_accepted():
    t = build_single_target("https://example.com", active=True, i_own_this_target=True)
    assert t.mode == "active"
    assert t.authorized is True
