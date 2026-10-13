import sys
from pathlib import Path
from unittest.mock import patch

# Allow importing the backend security service
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from services import security_service as service


def test_self_healing():
    test_ip = "192.0.2.123"
    current_time = 1000.0

    # Preserve any existing test-IP state
    previous_state = {}

    state_dicts = {
        "blocked_ips": service.blocked_ips,
        "failed_attempts": service.failed_attempts,
        "threat_scores": service.threat_scores,
    }

    for name, dictionary in state_dicts.items():
        previous_state[name] = dictionary.pop(test_ip, None)

    try:
        # Simulate an IP that was blocked 31 seconds ago
        service.blocked_ips[test_ip] = {
            "blocked_at": current_time - 31,
            "reason": "TEST_THREAT",
        }

        service.failed_attempts[test_ip] = 5
        service.threat_scores[test_ip] = 80

        with (
            patch.object(service, "track_request",
                         return_value=(1, 1, 0.1)),
            patch.object(service, "save_attack_log"),
            patch.object(service, "log_security_event"),
            patch.object(service, "verify_user", return_value=True),
            patch.object(service, "predict_suspicious_activity",
                         return_value=("NORMAL", 0.0)),
        ):
            result = service.process_login(
                username="self_healing_test_user",
                password="test_password",
                client_ip=test_ip,
            )

        assert test_ip not in service.blocked_ips, (
            "Expired IP block was not removed."
        )

        assert service.failed_attempts[test_ip] == 0, (
            "Failed-attempt counter was not reset."
        )

        assert service.threat_scores[test_ip] == 0, (
            "Threat score was not reset."
        )

        assert result["status"] != "blocked", (
            "IP remained blocked after expiration."
        )

        print("PASS: Expired IP block was removed.")
        print("PASS: Failed-attempt counter was reset.")
        print("PASS: Threat score was reset.")
        print("PASS: Login was no longer rejected by the expired block.")

    finally:
        for name, dictionary in state_dicts.items():
            dictionary.pop(test_ip, None)

            old_value = previous_state[name]
            if old_value is not None:
                dictionary[test_ip] = old_value


if __name__ == "__main__":
    test_self_healing()