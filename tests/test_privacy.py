# tests/test_privacy.py
import os
from tinysocs.agent.privacy import mask_ip, mask_email, hash_stable, truncate_cmdline, scrub_record

def test_mask_email_basic():
    s = "Contact me at alice@example.com or bob.smith@corp.co.uk"
    m = mask_email(s)
    assert "example.com" not in m and "corp.co.uk" not in m
    assert "<email:" in m

def test_mask_ip_v4_and_v6():
    s = "src=192.168.1.42 dst=2001:db8:abcd:0012:0000:0000:0000:0001"
    m = mask_ip(s)
    assert "192.168.1.42" not in m
    assert "192.168.1.0/24" in m
    assert "/64" in m  # ipv6 coarsened

def test_hash_stable_salt_changes():
    os.environ["PRIVACY_SALT"] = "saltA"
    a = hash_stable("secret")
    os.environ["PRIVACY_SALT"] = "saltB"
    b = hash_stable("secret")
    assert a != b
    # same salt -> same token
    os.environ["PRIVACY_SALT"] = "saltA"
    a2 = hash_stable("secret")
    assert a == a2

def test_truncate_cmdline_preserves_edges():
    s = "A" * 300 + " ZZZ " + "B" * 300
    t = truncate_cmdline(s, max_len=120)
    assert len(t) <= 120
    assert t.startswith("A")
    assert "ZZZ" in t
    assert t.endswith("B" * 5) or t.endswith("B"*1)  # tail preserved in some form

def test_scrub_record_recursive():
    rec = {
        "user": "alice@example.com",
        "src_ip": "10.1.2.3",
        "process": {"commandLine": "python /tmp/very/long/path " + "x"*400}
    }
    out = scrub_record(rec)
    assert "example.com" not in str(out)
    assert "10.1.2.3" not in str(out)
    assert "/24" in str(out)  # v4 coarsened
    # cmdline truncated
    assert len(out["process"]["commandLine"]) <= 200
