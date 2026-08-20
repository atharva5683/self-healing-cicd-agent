"""
Test script for redact_secrets() function.
Validates that common secret patterns are properly scrubbed from logs.
"""
import sys
import os

# Add agent directory to path so we can import the function
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

from self_healing_agent import redact_secrets

# ── Test Logs with Embedded Fake Secrets ──────────────────────────
FAKE_LOG = """
PIPELINE STEP STATUS
INSTALL_STATUS=failure
LINT_STATUS=success
TEST_STATUS=failure
DOCKER_STATUS=success

===== INSTALL LOGS =====
Collecting flask
  Using cached Flask-3.0.0.tar.gz
ERROR: Could not find a version that satisfies the requirement nonexistent-pkg==99.0
Setting ANTHROPIC_API_KEY=sk-ant-abcdef1234567890ABCDEF1234567890abcdef
export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

===== TEST LOGS =====
FAILED tests/test_app.py::test_login - AssertionError
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.dummysignaturevalue
database_url=postgres://admin:supersecretpass@db.example.com:5432/mydb
password="mySuperSecretPassword123"
token: 'xoxb-1234567890-abcdefghij-ABCDEFGH'
API_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890abcdef
FAKEKEYDATA==
-----END RSA PRIVATE KEY-----

npm_token=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab

===== DOCKER LOGS =====
Successfully built abc123def456
"""

EXPECTED_REDACTIONS = [
    "sk-ant-",           # Anthropic key should be gone
    "ghp_",              # GitHub token should be gone
    "AKIAIOSFODNN",      # AWS access key should be gone
    "supersecretpass",   # password in connection string
    "mySuperSecretPassword123",  # password value
    "BEGIN RSA PRIVATE KEY",      # private key block
    "AIzaSy",            # Google API key
]

EXPECTED_PRESENT = [
    "[REDACTED_",         # Replacement labels should be present
    "INSTALL_STATUS=failure",  # Non-secret metadata should survive
    "TEST_STATUS=failure",
    "FAILED tests/test_app.py",  # Actual error info should survive
    "===== INSTALL LOGS =====",
    "===== TEST LOGS =====",
]


def test_redaction():
    result = redact_secrets(FAKE_LOG)

    print("=" * 60)
    print("REDACTED OUTPUT:")
    print("=" * 60)
    print(result)
    print("=" * 60)

    passed = 0
    failed = 0

    # Check that secrets are GONE
    for secret_fragment in EXPECTED_REDACTIONS:
        if secret_fragment in result:
            print(f"  FAIL: '{secret_fragment}' still present in output!")
            failed += 1
        else:
            print(f"  PASS: '{secret_fragment}' successfully redacted.")
            passed += 1

    # Check that non-secret content is PRESERVED
    for expected in EXPECTED_PRESENT:
        if expected in result:
            print(f"  PASS: '{expected}' correctly preserved.")
            passed += 1
        else:
            print(f"  FAIL: '{expected}' was accidentally removed!")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed} checks.")

    if failed > 0:
        sys.exit(1)
    else:
        print("All redaction tests passed!")


if __name__ == "__main__":
    test_redaction()
