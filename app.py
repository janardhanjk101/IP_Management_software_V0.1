import os
import platform
import re
import subprocess
import threading
import time
from typing import Dict, List, Tuple

from flask import Flask, jsonify, render_template, request


def create_app() -> Flask:
    app = Flask(__name__)

    # Configuration
    app.config.setdefault("PING_INTERVAL_SECONDS", int(os.getenv("PING_INTERVAL_SECONDS", "10")))
    # Default paths (can be overridden via env)
    app.config.setdefault("IP_FILE_PATH", os.getenv("IP_FILE_PATH", r"C:\\Users\\Administrator\\Desktop\\ip\\switch.txt"))
    app.config.setdefault("CCTV_FILE_PATH", os.getenv("CCTV_FILE_PATH", r"C:\\Users\\Administrator\\Desktop\\ip\\cctv.txt"))
    app.config.setdefault("AP_FILE_PATH", os.getenv("AP_FILE_PATH", r"C:\\Users\\Administrator\\Desktop\ip\\accesspoints.txt"))
    app.config.setdefault("CCTV_SERVER_FILE_PATH", os.getenv("CCTV_SERVER_FILE_PATH", r"C:\\Users\\Administrator\\Desktop\\ip\\cctv_servers.txt"))

    def read_ips_from_file(path: str) -> List[Tuple[str, str]]:
        if not os.path.exists(path):
            return []
        ips: List[Tuple[str, str]] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    # Support format: "IP:Name" or just "IP"
                    if ":" in value:
                        ip, name = value.split(":", 1)
                        ips.append((ip.strip(), name.strip()))
                    else:
                        ips.append((value, value))  # Use IP as name if no name provided
        except Exception:
            return []
        # de-duplicate while preserving order
        seen = set()
        deduped: List[Tuple[str, str]] = []
        for ip, name in ips:
            if ip not in seen:
                seen.add(ip)
                deduped.append((ip, name))
        return deduped

    # Switch IPs (previously Servers)
    monitored_ips_data: List[Tuple[str, str]] = read_ips_from_file(app.config["IP_FILE_PATH"]) or [
        ("1.1.1.1", "Cloudflare DNS"),
        ("8.8.8.8", "Google DNS"),
        ("8.8.4.4", "Google DNS Alt"),
    ]
    monitored_ips: List[str] = [ip for ip, name in monitored_ips_data]

    # CCTV IPs
    cctv_ips_data: List[Tuple[str, str]] = read_ips_from_file(app.config["CCTV_FILE_PATH"]) or []
    cctv_ips: List[str] = [ip for ip, name in cctv_ips_data]
    
    # Access Point IPs
    ap_ips_data: List[Tuple[str, str]] = read_ips_from_file(app.config["AP_FILE_PATH"]) or []
    ap_ips: List[str] = [ip for ip, name in ap_ips_data]
    
    # CCTV Server IPs
    cctv_server_ips_data: List[Tuple[str, str]] = read_ips_from_file(app.config["CCTV_SERVER_FILE_PATH"]) or []
    cctv_server_ips: List[str] = [ip for ip, name in cctv_server_ips_data]

    # Shared state
    status_lock = threading.Lock()
    ip_status: Dict[str, Dict[str, object]] = {}
    cctv_status: Dict[str, Dict[str, object]] = {}
    ap_status: Dict[str, Dict[str, object]] = {}
    cctv_server_status: Dict[str, Dict[str, object]] = {}
    
    # Initialize regular IP status
    for ip, name in monitored_ips_data:
        ip_status[ip] = {
            "reachable": None, 
            "latency_ms": None, 
            "last_checked": None,
            "name": name,
            "first_unreachable": None
        }
    
    # Initialize CCTV IP status
    for ip, name in cctv_ips_data:
        cctv_status[ip] = {
            "reachable": None, 
            "latency_ms": None, 
            "last_checked": None,
            "name": name,
            "first_unreachable": None
        }
    
    # Initialize AP IP status
    for ip, name in ap_ips_data:
        ap_status[ip] = {
            "reachable": None, 
            "latency_ms": None, 
            "last_checked": None,
            "name": name,
            "first_unreachable": None
        }
    
    # Initialize CCTV Server IP status
    for ip, name in cctv_server_ips_data:
        cctv_server_status[ip] = {
            "reachable": None,
            "latency_ms": None,
            "last_checked": None,
            "name": name,
            "first_unreachable": None
        }
    
    stop_event = threading.Event()

    def _ping_command(target_ip: str) -> Tuple[List[str], Dict[str, str]]:
        system = platform.system().lower()
        if system == "windows":
            # -n 1: one echo request, -w 1000: 1s timeout in ms
            return ["ping", "-n", "1", "-w", "1000", target_ip], {}
        elif system == "darwin":
            # macOS: -c 1 one packet, -W 1000 timeout in ms (BSD ping uses ms)
            return ["ping", "-c", "1", "-W", "1000", target_ip], {}
        else:
            # Linux: -c 1 one packet, -W 1 timeout in seconds
            return ["ping", "-c", "1", "-W", "1", target_ip], {}

    def ping_once(target_ip: str, timeout_seconds: float = 2.0) -> Tuple[bool, float | None, str | None]:
        try:
            cmd, env = _ping_command(target_ip)
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={**os.environ, **env},
                text=True,
                timeout=timeout_seconds,
            )
            output = completed.stdout or ""
            reachable = completed.returncode == 0

            # Attempt to parse latency in ms from output
            latency_ms = None
            # Common patterns: time=12 ms, time<1ms, time=12.3 ms
            match = re.search(r"time[=<]([0-9]+\.?[0-9]*)\s*ms", output)
            if match:
                try:
                    latency_ms = float(match.group(1))
                except ValueError:
                    latency_ms = None

            return reachable, latency_ms, None
        except subprocess.TimeoutExpired:
            return False, None, "timeout"
        except Exception as exc:
            return False, None, str(exc)

    ip_file_mtime: float | None = None
    cctv_file_mtime: float | None = None
    ap_file_mtime: float | None = None
    cctv_server_file_mtime: float | None = None

    def maybe_reload_ips_from_file():
        nonlocal ip_file_mtime, cctv_file_mtime, ap_file_mtime, cctv_server_file_mtime, monitored_ips, monitored_ips_data, cctv_ips, cctv_ips_data, ap_ips, ap_ips_data, cctv_server_ips, cctv_server_ips_data
        
        # Reload regular IPs
        path = app.config["IP_FILE_PATH"]
        try:
            if os.path.exists(path):
                mtime = os.path.getmtime(path)
                if ip_file_mtime is None or mtime != ip_file_mtime:
                    ip_file_mtime = mtime
                    new_ips_data = read_ips_from_file(path)
                    if new_ips_data:
                        # Update monitored list
                        monitored_ips_data = new_ips_data
                        monitored_ips = [ip for ip, name in monitored_ips_data]
                        # Ensure status map has same keys
                        with status_lock:
                            # remove dropped
                            for existing in list(ip_status.keys()):
                                if existing not in monitored_ips:
                                    ip_status.pop(existing, None)
                            # add new
                            for ip, name in monitored_ips_data:
                                if ip not in ip_status:
                                    ip_status[ip] = {
                                        "reachable": None, 
                                        "latency_ms": None, 
                                        "last_checked": None,
                                        "name": name,
                                        "first_unreachable": None
                                    }
        except Exception:
            # ignore file reload errors
            pass
        
        # Reload CCTV IPs
        cctv_path = app.config["CCTV_FILE_PATH"]
        try:
            if os.path.exists(cctv_path):
                mtime = os.path.getmtime(cctv_path)
                if cctv_file_mtime is None or mtime != cctv_file_mtime:
                    cctv_file_mtime = mtime
                    new_cctv_data = read_ips_from_file(cctv_path)
                    if new_cctv_data:
                        # Update CCTV list
                        cctv_ips_data = new_cctv_data
                        cctv_ips = [ip for ip, name in cctv_ips_data]
                        # Ensure status map has same keys
                        with status_lock:
                            # remove dropped
                            for existing in list(cctv_status.keys()):
                                if existing not in cctv_ips:
                                    cctv_status.pop(existing, None)
                            # add new
                            for ip, name in cctv_ips_data:
                                if ip not in cctv_status:
                                    cctv_status[ip] = {
                                        "reachable": None, 
                                        "latency_ms": None, 
                                        "last_checked": None,
                                        "name": name,
                                        "first_unreachable": None
                                    }
        except Exception:
            # ignore file reload errors
            pass

        # Reload AP IPs
        ap_path = app.config["AP_FILE_PATH"]
        try:
            if os.path.exists(ap_path):
                mtime = os.path.getmtime(ap_path)
                if ap_file_mtime is None or mtime != ap_file_mtime:
                    ap_file_mtime = mtime
                    new_ap_data = read_ips_from_file(ap_path)
                    if new_ap_data is not None:
                        # Update AP list (allow empty to clear)
                        ap_ips_data = new_ap_data
                        ap_ips = [ip for ip, name in ap_ips_data]
                        # Ensure status map has same keys
                        with status_lock:
                            for existing in list(ap_status.keys()):
                                if existing not in ap_ips:
                                    ap_status.pop(existing, None)
                            for ip, name in ap_ips_data:
                                if ip not in ap_status:
                                    ap_status[ip] = {
                                        "reachable": None,
                                        "latency_ms": None,
                                        "last_checked": None,
                                        "name": name,
                                        "first_unreachable": None
                                    }
        except Exception:
            # ignore file reload errors
            pass

        # Reload CCTV Server IPs
        cctv_server_path = app.config["CCTV_SERVER_FILE_PATH"]
        try:
            if os.path.exists(cctv_server_path):
                mtime = os.path.getmtime(cctv_server_path)
                if cctv_server_file_mtime is None or mtime != cctv_server_file_mtime:
                    cctv_server_file_mtime = mtime
                    new_cctv_server_data = read_ips_from_file(cctv_server_path)
                    if new_cctv_server_data is not None:
                        cctv_server_ips_data = new_cctv_server_data
                        cctv_server_ips = [ip for ip, name in cctv_server_ips_data]
                        with status_lock:
                            for existing in list(cctv_server_status.keys()):
                                if existing not in cctv_server_ips:
                                    cctv_server_status.pop(existing, None)
                            for ip, name in cctv_server_ips_data:
                                if ip not in cctv_server_status:
                                    cctv_server_status[ip] = {
                                        "reachable": None,
                                        "latency_ms": None,
                                        "last_checked": None,
                                        "name": name,
                                        "first_unreachable": None
                                    }
        except Exception:
            # ignore file reload errors
            pass

    def background_pinger():
        interval = app.config["PING_INTERVAL_SECONDS"]
        while not stop_event.is_set():
            start_time = time.time()
            # Reload IPs if file changed
            maybe_reload_ips_from_file()
            
            # Ping regular IPs
            ips_snapshot = list(monitored_ips)
            for ip in ips_snapshot:
                reachable, latency_ms, error = ping_once(ip)
                with status_lock:
                    current_time = int(time.time())
                    current_status = ip_status.get(ip, {})
                    
                    # Track when IP first became unreachable
                    first_unreachable = current_status.get("first_unreachable")
                    if not reachable and first_unreachable is None:
                        # Just became unreachable
                        first_unreachable = current_time
                    elif reachable and first_unreachable is not None:
                        # Just became reachable again
                        first_unreachable = None
                    
                    ip_status[ip] = {
                        "reachable": bool(reachable),
                        "latency_ms": latency_ms,
                        "error": error,
                        "last_checked": current_time,
                        "name": current_status.get("name", ip),
                        "first_unreachable": first_unreachable
                    }
            
            # Ping CCTV IPs
            cctv_snapshot = list(cctv_ips)
            for ip in cctv_snapshot:
                reachable, latency_ms, error = ping_once(ip)
                with status_lock:
                    current_time = int(time.time())
                    current_status = cctv_status.get(ip, {})
                    
                    # Track when IP first became unreachable
                    first_unreachable = current_status.get("first_unreachable")
                    if not reachable and first_unreachable is None:
                        # Just became unreachable
                        first_unreachable = current_time
                    elif reachable and first_unreachable is not None:
                        # Just became reachable again
                        first_unreachable = None
                    
                    cctv_status[ip] = {
                        "reachable": bool(reachable),
                        "latency_ms": latency_ms,
                        "error": error,
                        "last_checked": current_time,
                        "name": current_status.get("name", ip),
                        "first_unreachable": first_unreachable
                    }
            
            # Ping Access Point IPs
            ap_snapshot = list(ap_ips)
            for ip in ap_snapshot:
                reachable, latency_ms, error = ping_once(ip)
                with status_lock:
                    current_time = int(time.time())
                    current_status = ap_status.get(ip, {})
                    
                    first_unreachable = current_status.get("first_unreachable")
                    if not reachable and first_unreachable is None:
                        first_unreachable = current_time
                    elif reachable and first_unreachable is not None:
                        first_unreachable = None
                    
                    ap_status[ip] = {
                        "reachable": bool(reachable),
                        "latency_ms": latency_ms,
                        "error": error,
                        "last_checked": current_time,
                        "name": current_status.get("name", ip),
                        "first_unreachable": first_unreachable
                    }
            
            # Ping CCTV Server IPs
            cctv_server_snapshot = list(cctv_server_ips)
            for ip in cctv_server_snapshot:
                reachable, latency_ms, error = ping_once(ip)
                with status_lock:
                    current_time = int(time.time())
                    current_status = cctv_server_status.get(ip, {})
                    
                    first_unreachable = current_status.get("first_unreachable")
                    if not reachable and first_unreachable is None:
                        first_unreachable = current_time
                    elif reachable and first_unreachable is not None:
                        first_unreachable = None
                    
                    cctv_server_status[ip] = {
                        "reachable": bool(reachable),
                        "latency_ms": latency_ms,
                        "error": error,
                        "last_checked": current_time,
                        "name": current_status.get("name", ip),
                        "first_unreachable": first_unreachable
                    }
            elapsed = time.time() - start_time
            # Sleep remainder of interval
            remaining = max(0.0, interval - elapsed)
            stop_event.wait(remaining)

    pinger_thread: threading.Thread | None = None
    background_started: bool = False

    # Flask 3 removed before_first_request; use before_serving if available,
    # otherwise fall back to a guarded before_request.
    if hasattr(app, "before_serving"):
        @app.before_serving
        def start_background_thread():
            nonlocal pinger_thread
            if pinger_thread is None or not pinger_thread.is_alive():
                pinger_thread = threading.Thread(target=background_pinger, name="background_pinger", daemon=True)
                pinger_thread.start()
    else:
        @app.before_request
        def start_background_thread_fallback():
            nonlocal pinger_thread, background_started
            if not background_started:
                if pinger_thread is None or not pinger_thread.is_alive():
                    pinger_thread = threading.Thread(target=background_pinger, name="background_pinger", daemon=True)
                    pinger_thread.start()
                background_started = True

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def get_status():
        with status_lock:
            # compute counts for switches (regular IPs)
            live_count = sum(1 for v in ip_status.values() if v.get("reachable") is True)
            down_count = sum(1 for v in ip_status.values() if v.get("reachable") is False)
            total = len(ip_status)
            
            # compute counts for CCTV IPs
            cctv_live_count = sum(1 for v in cctv_status.values() if v.get("reachable") is True)
            cctv_down_count = sum(1 for v in cctv_status.values() if v.get("reachable") is False)
            cctv_total = len(cctv_status)
            
            # compute counts for Access Points
            ap_live_count = sum(1 for v in ap_status.values() if v.get("reachable") is True)
            ap_down_count = sum(1 for v in ap_status.values() if v.get("reachable") is False)
            ap_total = len(ap_status)
            
            # compute counts for CCTV Servers
            cctv_server_live_count = sum(1 for v in cctv_server_status.values() if v.get("reachable") is True)
            cctv_server_down_count = sum(1 for v in cctv_server_status.values() if v.get("reachable") is False)
            cctv_server_total = len(cctv_server_status)
            
            return jsonify({
                "ips": ip_status,
                "cctv_ips": cctv_status,
                "ap_ips": ap_status,
                "cctv_server_ips": cctv_server_status,
                "interval_seconds": app.config["PING_INTERVAL_SECONDS"],
                "counts": {"live": live_count, "down": down_count, "total": total},
                "cctv_counts": {"live": cctv_live_count, "down": cctv_down_count, "total": cctv_total},
                "ap_counts": {"live": ap_live_count, "down": ap_down_count, "total": ap_total},
                "cctv_server_counts": {"live": cctv_server_live_count, "down": cctv_server_down_count, "total": cctv_server_total},
            })

    # Note: IP list now sourced from file; add/remove via editing the file.

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()

if __name__ == "__main__":
    # Use threaded server to handle API + background worker peacefully
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "4000")), debug=True, threaded=True)

