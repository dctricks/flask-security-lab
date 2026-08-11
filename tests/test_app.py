import unittest
from unittest.mock import patch

from app import app


class FlaskSecurityLabTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_home_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Flask Security Lab", response.data)

    def test_ping_requires_host(self):
        response = self.client.get("/ping")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Missing host")

    def test_ping_rejects_excessively_long_host(self):
        host = "a" * 254

        with patch("app.subprocess.run") as mock_run:
            response = self.client.get("/ping", query_string={"host": host})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Host is too long")
        mock_run.assert_not_called()

    def test_ping_rejects_shell_injection_payload(self):
        payload = "127.0.0.1;echo INJECTION_TEST"

        with patch("app.subprocess.run") as mock_run:
            response = self.client.get("/ping", query_string={"host": payload})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Invalid host")
        mock_run.assert_not_called()

    @patch("app.subprocess.run")
    def test_ping_passes_arguments_without_shell_command_construction(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "PING 127.0.0.1"
        mock_run.return_value.stderr = ""

        response = self.client.get("/ping", query_string={"host": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(
            ["ping", "-c", "4", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("app.subprocess.run")
    def test_ping_handles_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["ping", "-c", "4", "127.0.0.1"],
            timeout=10,
        )

        response = self.client.get("/ping", query_string={"host": "127.0.0.1"})

        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.get_json()["error"], "Ping timed out")


if __name__ == "__main__":
    unittest.main()
