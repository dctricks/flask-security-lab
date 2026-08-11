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


    @patch("scanner.scan_port")
    @patch("scanner.detect_http")
    @patch("scanner.get_service")
    def test_scan_ports_reports_http_service(
        self, mock_get_service, mock_detect_http, mock_scan_port
    ):
        mock_scan_port.side_effect = [True, False]
        mock_detect_http.return_value = (200, "OK")

        scanner.scan_ports("127.0.0.1", 5000, 5001)

        mock_get_service.assert_not_called()

    @patch("scanner.scan_port")
    @patch("scanner.detect_http")
    @patch("scanner.get_service")
    def test_scan_ports_reports_non_http_service(
        self, mock_get_service, mock_detect_http, mock_scan_port
    ):
        mock_scan_port.return_value = True
        mock_detect_http.return_value = (None, None)
        mock_get_service.return_value = "SSH"

        scanner.scan_ports("127.0.0.1", 22, 22)

        mock_get_service.assert_called_once_with(22)

    @patch("scanner.scan_ports")
    @patch("scanner.validate_target")
    def test_main_accepts_valid_arguments(
        self, mock_validate_target, mock_scan_ports
    ):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "127.0.0.1",
            "5000",
            "5005",
        ]):
            scanner.main()

        mock_validate_target.assert_called_once_with("127.0.0.1")
        mock_scan_ports.assert_called_once_with(
            "127.0.0.1", 5000, 5005
        )

    def test_main_help(self):
        with patch("scanner.sys.argv", ["scanner.py", "--help"]):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 0)

    def test_main_rejects_wrong_argument_count(self):
        with patch("scanner.sys.argv", ["scanner.py"]):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

    def test_main_rejects_invalid_target(self):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "not-a-real-target",
            "1",
            "10",
        ]), patch("scanner.validate_target", return_value=False):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

    def test_main_rejects_non_numeric_ports(self):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "127.0.0.1",
            "abc",
            "10",
        ]), patch("scanner.validate_target", return_value=True):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

    def test_main_rejects_invalid_start_port(self):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "127.0.0.1",
            "0",
            "10",
        ]), patch("scanner.validate_target", return_value=True):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

    def test_main_rejects_invalid_end_port(self):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "127.0.0.1",
            "1",
            "65536",
        ]), patch("scanner.validate_target", return_value=True):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

    def test_main_rejects_reversed_port_range(self):
        with patch("scanner.sys.argv", [
            "scanner.py",
            "127.0.0.1",
            "5005",
            "5000",
        ]), patch("scanner.validate_target", return_value=True):
            with self.assertRaises(SystemExit) as context:
                scanner.main()

        self.assertEqual(context.exception.code, 1)

if __name__ == "__main__":
    unittest.main()
