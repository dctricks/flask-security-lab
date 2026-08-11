Flask Security Lab

A Python and Flask security-learning project focused on secure command execution, input validation, TCP port scanning, and HTTP service detection in a controlled local environment.

This project demonstrates practical defensive programming techniques and basic network-security tooling using Python's standard library and Flask.

🚀 Features

Flask Security Application

- Flask web application with a "/ping" endpoint
- Validates IPv4/IPv6 addresses and DNS hostnames
- Rejects missing and excessively long input
- Uses "subprocess.run()" with an argument list instead of shell command construction
- Applies a command timeout to prevent indefinitely running processes
- Returns structured JSON responses

Network Scanner

- TCP port scanning using Python sockets
- Configurable target and port range
- Validates target addresses and port ranges
- Detects common network services
- Performs HTTP detection on open ports
- Reports HTTP status codes and response reasons
- Clean command-line output

🔐 Security Focus

A major goal of this project is demonstrating the difference between unsafe shell command execution and safer subprocess usage.

The Flask application does not construct a shell command from user-controlled input.

Instead, it uses an argument list:

subprocess.run(
    ["ping", "-c", "4", host],
    capture_output=True,
    text=True,
    timeout=10
)

This avoids invoking a shell and significantly reduces the risk of shell-injection vulnerabilities compared with approaches such as:

os.system(user_input)

The application also validates the supplied host before executing the command.

«This project is intended for defensive security education and authorized testing in controlled environments.»

🧰 Technologies

- Python 3
- Flask
- Python "subprocess"
- Python "socket"
- Python "http.client"
- Git / GitHub
- Linux / Termux

📁 Project Structure

flask-security-lab/
├── app.py
├── scanner.py
├── README.md
├── requirements.txt
├── .gitignore
├── tests/
└── screenshots/

⚙️ Installation

Clone the repository:

git clone git@github.com:dctricks/flask-security-lab.git
cd flask-security-lab

Create a Python virtual environment:

python -m venv venv

Activate it:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

▶️ Run the Flask Application

Start the application:

python app.py

The development server listens locally on:

http://127.0.0.1:5000

Test the home page:

curl http://127.0.0.1:5000/

Test the ping endpoint:

curl "http://127.0.0.1:5000/ping?host=127.0.0.1"

🔎 Run the Port Scanner

Example:

python scanner.py localhost 4995 5005

Example output:

Scanning localhost...
Ports: 4995-5005

[+] Port 5000 is OPEN
    Service: HTTP
    HTTP: detected (200 OK)

Scan complete. Open ports: [5000]

🧪 Validation and Testing

The project uses Python's bytecode compiler to catch syntax and indentation errors before execution:

python -m py_compile app.py scanner.py

The scanner can also be tested against the locally running Flask application.

🛡️ Security Considerations

This project is intentionally designed as a learning laboratory.

Important defensive practices demonstrated include:

- Avoiding "shell=True" for user-controlled input
- Avoiding "os.system()" for command execution
- Validating network targets
- Limiting input length
- Restricting valid port ranges
- Applying subprocess timeouts
- Handling socket and connection errors
- Keeping development files such as virtual environments out of Git

For production deployment, additional controls would be required, including authentication, authorization, logging, rate limiting, secure configuration, and a production WSGI server.

🎯 Learning Goals

This project was created to practice:

1. Secure Python programming
2. Flask application development
3. Command-injection prevention
4. Network programming with sockets
5. Basic service detection
6. HTTP protocol interaction
7. Linux and Termux development
8. Git and GitHub workflows
9. SSH-based Git authentication

📌 Project Status

Current status: Working prototype / security-learning project.

Future improvements may include:

- Automated unit tests
- Better service fingerprinting
- Structured scan results
- Logging
- Configuration management
- Improved Flask error handling
- Additional security tests
- Portfolio screenshots

👨‍💻 Author

Dennis

GitHub: "dctricks" (https://github.com/dctricks)

This project is part of my practical learning portfolio in Python, web development, and cybersecurity.
