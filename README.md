# xPhiltrate

A lightweight educational **Man-in-the-Middle (MITM) reverse proxy** built with mitmproxy for web authentication flow analysis.

xPhiltrate demonstrates pre-encryption data capture, session cookie extraction, and authentication traffic inspection in a controlled lab environment.

## Features

- Transparent reverse proxy using mitmproxy
- Pre-encryption form field and crypto operation capture via JavaScript injection
- Session cookie extraction and hijack demonstration
- Structured credential logging with noise filtering
- Clean console output with session replay instructions
- JSON logging for captured events
- Site-specific credential mapping (`site_mapping.json`)

## Demo video 
[![Watch Demo](https://img.shields.io/badge/Demo-Video-blue?style=for-the-badge&logo=github)](https://github.com/user-attachments/assets/097a8c46-4e06-428d-8640-9b3ce4aed67c)

Here is a walk-through of the MITM setup in a test environment and the expected output. All credentials presented are epheremal.

## Requirements

- Python 3.12+
- mitmproxy

## Installation

```bash
git clone https://github.com/jeflecias/xphiltrate.git
cd xphiltrate
pip install -r requirements.txt
```

## Usage

```bash
# Start xPhiltrate
python xphiltrate.py --target https://example.com --port 8080
```

### Examples

1. Target a login page:

```bash
python xphiltrate.py --target https://login.company.com
```

2. Targeted Extraction: `site_mapping.json`: The system uses the json file to define which sensitive cookies or keys to hunt for on specific domains. The proxy matches the incoming **Host** header against this file.

**Example Configuration:**

```json
{
    "internal-login.local": ["auth_token"],
    "example.com": ["target"]
}
```

* **Keys:** Exact domain/hostname (no `https://`)
* **Values:** List of cookie names or payload keys to prioritize

## Browser Setup

Set your browser’s HTTP proxy to:

```
127.0.0.1:8080
```

(Optional) Expose the proxy using ngrok:

```bash
ngrok http 8080
```

## Output

The system generates a JSON file named:

```bash
creds_<timestamp>.json
````

Each entry represents a captured event during the session. Logs are structured for easy parsing and analysis.

### What to Expect

* Captured form inputs (e.g., username, password)
* Session cookies (`Set-Cookie`)
* Fetch/XHR payload data
* Pre-encryption values (from injected JavaScript)

### Sample Output

```json
{
    {
    "timestamp": "2026-04-05T08:15:09Z",
    "victim_ip": "<IP of the user>",
    "event_type": "SET_COOKIE_CAPTURE",
    "method": "SET-COOKIE",
    "target_url": "https://<target website>",
    "captured_credentials": {
        "session_id": "2ce2cd4501322363ee5ea0ea4e828f560e7720a04cef4faa..."
    }
}
```

## Note

This project serves as a base module for simulated MITM environments. Accuracy depends heavily on proper site mapping and manual reconnaissance, not solely on the python script above. It's recommend to start the manual recon first before using the system

## Limitations

* JavaScript injection may be blocked by strong CSP policies
* Does not bypass advanced anti-bot or fingerprinting protections
* Injection is global and may break complex SPAs
* Client-side encrypted payloads are only partially captured
* Limited to a single target at a time
* No built-in multi-target or phishlet support
* Effectiveness depends on target implementation

## Legal & Ethical Disclaimer

For educational use, security research, and authorized testing only.

Do not use this tool without explicit permission. Users are responsible for complying with all applicable laws and regulations. The author assumes no liability for misuse or damage.
