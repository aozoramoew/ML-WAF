"""Tests for app.policy — allow/blocklist logic and policy persistence."""

import json
import pytest

from app import policy


@pytest.fixture(autouse=True)
def isolated_policy(tmp_path, monkeypatch):
    """Point the policy module at a throwaway file and reset in-memory state."""
    policy_file = tmp_path / 'policy.json'
    monkeypatch.setattr(policy, 'POLICY_PATH', policy_file)
    policy._policy = {}
    policy._compiled_rules = {}
    policy.load()
    yield
    policy._policy = {}
    policy._compiled_rules = {}


def _req(ip='198.51.100.1', url='/'):
    return {'ip': ip, 'url': url}


# ── Defaults ────────────────────────────────────────────────────────────────

def test_default_policy_allows_normal_request():
    result = policy.check_request(_req())
    assert result['block'] is False
    assert result['action'] == 'prevent'  # default mode


def test_load_creates_policy_file_with_defaults(tmp_path):
    assert policy.POLICY_PATH.exists()
    with open(policy.POLICY_PATH) as f:
        data = json.load(f)
    assert data['mode'] == 'prevent'
    assert data['rules']['ip_blocklist'] == []


# ── IP allow/blocklist ──────────────────────────────────────────────────────

def test_ip_blocklist_blocks_in_prevent_mode():
    policy.add_rule('ip_blocklist', '203.0.113.66')
    result = policy.check_request(_req(ip='203.0.113.66'))
    assert result['block'] is True
    assert result['action'] == 'block'
    assert '203.0.113.66' in result['reason']


def test_ip_allowlist_overrides_blocklist():
    policy.add_rule('ip_blocklist', '203.0.113.66')
    policy.add_rule('ip_allowlist', '203.0.113.66')
    result = policy.check_request(_req(ip='203.0.113.66'))
    assert result['block'] is False
    assert result['action'] == 'allow'


def test_ip_blocklist_in_monitor_mode_does_not_block():
    policy.update_policy({'mode': 'monitor'})
    policy.add_rule('ip_blocklist', '203.0.113.66')
    result = policy.check_request(_req(ip='203.0.113.66'))
    assert result['block'] is False
    assert result['action'] == 'monitor'


# ── Path allow/blocklist ─────────────────────────────────────────────────────

def test_path_blocklist_blocks_matching_regex():
    policy.add_rule('path_blocklist', r'^/admin')
    result = policy.check_request(_req(url='/admin/users'))
    assert result['block'] is True
    assert result['action'] == 'block'


def test_path_blocklist_does_not_block_non_matching_path():
    policy.add_rule('path_blocklist', r'^/admin')
    result = policy.check_request(_req(url='/products'))
    assert result['block'] is False


def test_path_allowlist_overrides_path_blocklist():
    policy.add_rule('path_blocklist', r'^/api')
    policy.add_rule('path_allowlist', r'^/api/health')
    result = policy.check_request(_req(url='/api/health'))
    assert result['block'] is False
    assert result['action'] == 'allow'

    # Non-allowlisted /api path is still blocked.
    result2 = policy.check_request(_req(url='/api/users'))
    assert result2['block'] is True


def test_path_query_string_is_ignored_for_matching():
    policy.add_rule('path_blocklist', r'^/admin$')
    result = policy.check_request(_req(url='/admin?token=abc'))
    assert result['block'] is True


# ── Rule management ──────────────────────────────────────────────────────────

def test_add_rule_is_idempotent():
    policy.add_rule('ip_blocklist', '203.0.113.5')
    policy.add_rule('ip_blocklist', '203.0.113.5')
    assert policy.get_policy()['rules']['ip_blocklist'].count('203.0.113.5') == 1


def test_remove_rule():
    policy.add_rule('ip_blocklist', '203.0.113.5')
    policy.remove_rule('ip_blocklist', '203.0.113.5')
    result = policy.check_request(_req(ip='203.0.113.5'))
    assert result['block'] is False


def test_add_rule_invalid_type_raises():
    with pytest.raises(ValueError):
        policy.add_rule('not_a_real_rule_type', 'value')


def test_add_rules_bulk_adds_multiple_and_dedupes():
    policy.add_rule('ip_blocklist', '203.0.113.5')
    added, skipped, updated = policy.add_rules_bulk(
        'ip_blocklist',
        ['203.0.113.5', '203.0.113.6', '203.0.113.7', '  ', '203.0.113.6'],
    )
    assert added == 2
    assert skipped == 2
    assert set(updated['rules']['ip_blocklist']) == {
        '203.0.113.5', '203.0.113.6', '203.0.113.7',
    }


def test_add_rules_bulk_invalid_type_raises():
    with pytest.raises(ValueError):
        policy.add_rules_bulk('not_a_real_rule_type', ['value'])


# ── Thresholds / persistence ─────────────────────────────────────────────────

def test_get_thresholds_returns_defaults():
    thresholds = policy.get_thresholds()
    assert thresholds['ml_block_score'] == 0.50
    assert thresholds['combined_block_score'] == 0.65


def test_update_policy_persists_to_disk():
    policy.update_policy({'thresholds': {'ml_block_score': 0.8}})
    with open(policy.POLICY_PATH) as f:
        data = json.load(f)
    assert data['thresholds']['ml_block_score'] == 0.8
    # Other thresholds remain untouched (deep merge).
    assert data['thresholds']['combined_block_score'] == 0.65
