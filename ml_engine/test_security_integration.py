import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_PATH))

from services import security_service as service


def test_process_login_rate_limiting():

    test_ip = "192.0.2.123"
    test_username = "integration_test_user"

    # Preserve the existing state.
    state_dicts = {
        "blocked_ips": service.blocked_ips,
        "failed_attempts": service.failed_attempts,
        "threat_scores": service.threat_scores,
        "request_logs": service.request_logs,
        "username_logs": service.username_logs,
    }

    snapshots = {
        name: dictionary.pop(test_ip, None)
        for name, dictionary in state_dicts.items()
    }

    try:
        # Disable ML blocking for this test so we can test
        # the rate limiter independently.
        with patch.object(
            service,
            "save_attack_log",
        ), patch.object(
            service,
            "verify_user",
            return_value=False,
        ), patch.object(
            service,
            "log_security_event",
        ), patch.object(
            service,
            "predict_suspicious_activity",
            return_value=("NORMAL", 0.0),
        ):

            results = []

            for _ in range(6):
                result = service.process_login(
                    username=test_username,
                    password="test-only-invalid-password",
                    client_ip=test_ip,
                )
                results.append(result)

        # Verify the rate-limiting behavior.
        assert all(
            result["status"] != "blocked"
            for result in results[:5]
        ), "A request was blocked before the sixth request."

        assert results[5]["status"] == "blocked", (
            "The sixth request did not trigger rate limiting."
        )

        assert (
            service.blocked_ips[test_ip]["reason"]
            == "TRAFFIC_SPIKE"
        ), "The blocking reason is incorrect."

        print("PASS: First five requests were not rate-limited.")
        print("PASS: Sixth request triggered the rate limiter.")
        print("PASS: Blocking reason is TRAFFIC_SPIKE.")

    finally:
        # Restore the original state for this IP.
        for name, dictionary in state_dicts.items():
            dictionary.pop(test_ip, None)

            original_value = snapshots[name]

            if original_value is not None:
                dictionary[test_ip] = original_value


if __name__ == "__main__":
    test_process_login_rate_limiting()