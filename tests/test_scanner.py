import socket
import unittest
from unittest.mock import patch

import scanner


class ScannerTests(unittest.TestCase):
    def test_validate_target_accepts_ipv4(self):
        self.assertTrue(scanner.validate_target("127.0.0.1"))

    def test_validate_target_accepts_hostname(self):
        self.assertTrue(scanner.validate_target("localhost"))

    def test_validate_target_rejects_invalid_target(self):
        with patch("scanner.socket.getaddrinfo", side_effect=socket.gaierror):
            self.assertFalse(scanner.validate_target("not-a-real-target"))

    def test_get_service_known_port(self):
        self.assertEqual(scanner.get_service(22), "SSH")
        self.assertEqual(scanner.get_service(80), "HTTP")
        self.assertEqual(scanner.get_service(443), "HTTPS")

    def test_get_service_unknown_port(self):
        with patch("scanner.socket.getservbyport", side_effect=OSError):
            self.assertEqual(scanner.get_service(65000), "unknown")

    def test_scan_port_reports_open_port(self):
        with patch("scanner.socket.socket") as mock_socket_class:
            mock_socket = mock_socket_class.return_value
            mock_socket.connect_ex.return_value = 0

            self.assertTrue(scanner.scan_port("127.0.0.1", 5000))
            mock_socket.settimeout.assert_called_once_with(0.5)
            mock_socket.connect_ex.assert_called_once_with(("127.0.0.1", 5000))
            mock_socket.close.assert_called_once()

    def test_scan_port_reports_closed_port(self):
        with patch("scanner.socket.socket") as mock_socket_class:
            mock_socket = mock_socket_class.return_value
            mock_socket.connect_ex.return_value = 1

            self.assertFalse(scanner.scan_port("127.0.0.1", 5001))
            mock_socket.close.assert_called_once()

    def test_scan_port_handles_socket_error(self):
        with patch("scanner.socket.socket") as mock_socket_class:
            mock_socket = mock_socket_class.return_value
            mock_socket.connect_ex.side_effect = socket.error("connection failed")

            self.assertFalse(scanner.scan_port("127.0.0.1", 5002))
            mock_socket.close.assert_called_once()

    def test_detect_http_returns_status_and_reason(self):
        with patch("scanner.http.client.HTTPConnection") as mock_connection_class:
            mock_connection = mock_connection_class.return_value
            mock_response = mock_connection.getresponse.return_value
            mock_response.status = 200
            mock_response.reason = "OK"

            status, reason = scanner.detect_http("127.0.0.1", 5000)

            self.assertEqual(status, 200)
            self.assertEqual(reason, "OK")
            mock_connection.request.assert_called_once_with("GET", "/")
            mock_connection.close.assert_called_once()

    def test_detect_http_handles_connection_error(self):
        with patch(
            "scanner.http.client.HTTPConnection",
            side_effect=ConnectionError("connection failed"),
        ):
            status, reason = scanner.detect_http("127.0.0.1", 5000)

            self.assertIsNone(status)
            self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
