# tests/test_privacy.py
"""Unit tests for the privacy masking module (Phase 11)."""

from tinysocs.agent.privacy import (
    mask_email,
    coarse_mask,
    mask_entities,
    extract_tokens,
)


# ---------------------------------------------------------------------------
# mask_email
# ---------------------------------------------------------------------------
def test_mask_email_basic():
    s = "Contact me at alice@example.com or bob.smith@corp.co.uk"
    m = mask_email(s)
    # Full local part should be masked (only first char + ***)
    assert "alice@" not in m
    assert "bob.smith@" not in m
    # Domain is preserved
    assert "example.com" in m
    assert "corp.co.uk" in m
    # Masked format: first_char***@domain
    assert "a***@example.com" in m
    assert "b***@corp.co.uk" in m


def test_mask_email_no_emails():
    s = "No emails here"
    assert mask_email(s) == s


# ---------------------------------------------------------------------------
# coarse_mask (email + IPv4 masking)
# ---------------------------------------------------------------------------
def test_coarse_mask_ipv4():
    s = "src=192.168.1.42 dst=10.0.0.5"
    m = coarse_mask(s)
    assert "192.168.1.42" not in m
    assert "192.168.1.0/24" in m
    assert "10.0.0.5" not in m
    assert "10.0.0.0/24" in m


def test_coarse_mask_email_and_ip():
    s = "user alice@example.com from 10.1.2.3"
    m = coarse_mask(s)
    assert "alice@" not in m
    assert "10.1.2.3" not in m
    assert "10.1.2.0/24" in m


def test_coarse_mask_empty():
    assert coarse_mask("") == ""


# ---------------------------------------------------------------------------
# mask_entities
# ---------------------------------------------------------------------------
def test_mask_entities_from_exemplars():
    evidences = [
        {
            "summary": {"top_users": ["admin"]},
            "exemplars": [
                {
                    "fields": {"user.name": "jdoe", "host": "DC01.corp.local"},
                    "message": "Login from user=jdoe at 10.0.0.1",
                }
            ],
        }
    ]
    result = mask_entities(evidences)
    assert "users" in result
    assert "hosts" in result
    assert len(result["users"]) > 0
    assert len(result["hosts"]) > 0


def test_mask_entities_empty():
    result = mask_entities([])
    assert result == {"users": [], "hosts": []}


# ---------------------------------------------------------------------------
# extract_tokens
# ---------------------------------------------------------------------------
def test_extract_tokens_processes():
    evidences = [
        {
            "exemplars": [
                {
                    "fields": {"process.name": "powershell.exe"},
                    "message": "Connection from 172.16.0.5 to 10.0.0.1",
                }
            ]
        }
    ]
    result = extract_tokens(evidences)
    assert "powershell.exe" in result["process_names"]
    assert any("/24" in n for n in result["networks"])


def test_extract_tokens_empty():
    result = extract_tokens([])
    assert result == {"process_names": [], "networks": []}
