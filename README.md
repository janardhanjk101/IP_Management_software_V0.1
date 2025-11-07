# Network Monitoring Dashboard (Flask)

A Flask dashboard that pings configured devices (Switches, CCTV, Access Points) and displays reachability and latency.

## Features
- Background pinger thread that runs every N seconds (default 10s)
- Cross-platform ping (Windows/macOS/Linux)
- Add/remove hosts at runtime via API/UI
- Minimal, modern dashboard that auto-refreshes

## Prerequisites
- Python 3.10+
- Windows PowerShell (or any shell)

## Setup (Windows PowerShell)
```powershell
# 1) Navigate to project
cd "C:\Users\HP\Desktop\ip ping"

# 2) Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) Install dependencies
pip install -r requirements.txt

# 4) Optional: configure environment variables
$env:PING_INTERVAL_SECONDS = "10"         # how often to ping
$env:PING_IPS = "1.1.1.1,8.8.8.8,8.8.4.4" # default hosts to monitor

# 5) Create or edit device lists (format: IP or IP:Name)
notepad .\switch.txt         # switches
notepad .\cctv.txt           # CCTV cameras
notepad .\accesspoints.txt   # Wi‑Fi APs
notepad .\cctv_servers.txt   # CCTV servers (recorders, NVRs, VMS)

# 6) Run the app
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## API
- GET `/api/status` → returns current status maps and counts
- GET `/health` → health check

## Notes
- Device lists are loaded from `switch.txt`, `cctv.txt`, `accesspoints.txt`, and `cctv_servers.txt` automatically. Files are re-read when modified.
- On Windows, `ping` uses `-n 1 -w 1000` (1s timeout). On Linux/macOS the flags are adjusted accordingly.
- Latency parsing depends on typical `ping` output. If parsing fails, latency may show as `—` but reachability still works.