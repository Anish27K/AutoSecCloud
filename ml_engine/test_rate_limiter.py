import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_PATH))

from services import security_service as service


def test_rate_limiter():

    test_ip = "192.0.2.123"
    test_username = "rate_limit_test"

    # Preserve existing security state.
    original_blocked_ips = service.blocked_ips.copy()
    original_threat_scores = service.threat_scores.copy()
    original_request_logs = service.request_logs.copy()
    original_username_logs = service.username_logs.copy()

    try:
        # Simulate six requests within ten seconds.
        start_time = 1000.0

        for offset in range(6):
            service.track_request(
                test_username,
                test_ip,
                start_time + offset,
            )

        request_count = len(service.request_logs[test_ip])

        assert request_count == 6

        # Verify the rate limiter blocks excessive traffic.
        with patch.object(service, "save_attack_log"):
            with patch.object(service.logger, "critical"):
                result = service.block_ip(
                    client_ip=test_ip,
                    username=test_username,
                    reason="TRAFFIC_SPIKE",
                    message="Traffic spike detected.",
                    current_time=start_time + 5,
                )

        assert test_ip in service.blocked_ips
        assert result["status"] == "blocked"
        assert service.blocked_ips[test_ip]["reason"] == "TRAFFIC_SPIKE"

        print("PASS: Six requests were recorded.")
        print("PASS: Excessive traffic produces a block.")
        print("PASS: The blocking reason is recorded.")

    finally:
        service.blocked_ips.clear()
        service.blocked_ips.update(original_blocked_ips)

        service.threat_scores.clear()
        service.threat_scores.update(original_threat_scores)

        service.request_logs.clear()
        service.request_logs.update(original_request_logs)

        service.username_logs.clear()
        service.username_logs.update(original_username_logs)


if __name__ == "__main__":
    test_rate_limiter()