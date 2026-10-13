import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_PATH))

from services import security_service as service


def test_ml_blocking():
    test_ip = "192.0.2.123"
    test_username = "ml_test_user"

    # Preserve existing security state.
    original_blocked_ips = service.blocked_ips.copy()
    original_threat_scores = service.threat_scores.copy()

    try:
        service.threat_scores[test_ip] = 50

        result = service.block_ip(
            client_ip=test_ip,
            username=test_username,
            reason="ML_SUSPICIOUS_ACTIVITY",
            message="ML blocking test passed.",
        )

        assert test_ip in service.blocked_ips
        assert (
            service.blocked_ips[test_ip]["reason"]
            == "ML_SUSPICIOUS_ACTIVITY"
        )
        assert result["status"] == "blocked"

        print("PASS: Security service blocks the test IP.")
        print("PASS: Blocking reason is recorded correctly.")
        print("PASS: Block response is returned correctly.")

    finally:
        service.blocked_ips.clear()
        service.blocked_ips.update(original_blocked_ips)

        service.threat_scores.clear()
        service.threat_scores.update(original_threat_scores)


if __name__ == "__main__":
    test_ml_blocking()