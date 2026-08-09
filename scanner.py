import socket
import sys
import ipaddress
import http.client

def validate_target(target):
    """Return True if target is a valid IP address or hostname."""

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        socket.getaddrinfo(target, None)
        return True
    except socket.gaierror:
        return False


def scan_port(target, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        return sock.connect_ex((target, port)) == 0
    except socket.error:
        return False
    finally:
        sock.close()


def get_service(port):
    common_services = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-alt",
        8443: "HTTPS-alt",
    }

    if port in common_services:
        return common_services[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def detect_http(target, port, timeout=1):
    try:
        connection = http.client.HTTPConnection(
            target,
            port,
            timeout=timeout
        )

        connection.request("GET", "/")
        response = connection.getresponse()

        connection.close()

        return response.status, response.reason

    except (OSError, ConnectionError):
        return None, None

def scan_ports(target, start_port, end_port):
    print(f"Scanning {target}...")
    print(f"Ports: {start_port}-{end_port}")
    print()

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(target, port):
            print(f"[+] Port {port} is OPEN")

            status, reason = detect_http(target, port)

            if status is not None:
                service = "HTTP"
            else:
                service = get_service(port)

            print(f"    Service: {service}")

            if status is not None:
                print(f"    HTTP: detected ({status} {reason})")

            open_ports.append(port)

    print()
    print(f"Scan complete. Open ports: {open_ports}")


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python scanner.py <target> <start_port> <end_port>")
        print()
        print("Examples:")
        print("  python scanner.py localhost 4995 5005")
        print("  python scanner.py 127.0.0.1 1 100")
        sys.exit(0)

    if len(sys.argv) != 4:
        print("Usage: python scanner.py <target> <start_port> <end_port>")
        sys.exit(1)

    target = sys.argv[1]

    if not validate_target(target):
        print("Error: target must be a valid IP address or hostname.")
        sys.exit(1)

    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("Error: ports must be numbers.")
        sys.exit(1)

    if not 1 <= start_port <= 65535:
        print("Error: start port must be between 1 and 65535.")
        sys.exit(1)

    if not 1 <= end_port <= 65535:
        print("Error: end port must be between 1 and 65535.")
        sys.exit(1)

    if start_port > end_port:
        print("Error: start port cannot be greater than end port.")
        sys.exit(1)

    scan_ports(target, start_port, end_port)


if __name__ == "__main__":
    main()
