# Run with: uvicorn scanner:app --host 0.0.0.0 --port 8765 --reload

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Depends, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from ipaddress import IPv4Address, IPv4Network
import bcrypt
import nmap
import socket
import asyncio
import aiohttp
from mac_vendor_lookup import AsyncMacLookup, VendorNotFoundError
from concurrent.futures import ThreadPoolExecutor
import uuid
import subprocess
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import os
import json

SCAN_CLEANUP_AGE_MINUTES = 15
HISTORY_FILE = "scan_history.json"
PORT_LOG_FILE = "port_history.log"
CONFIG_FILE = "config.json"

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def load_config() -> Dict[str, Any]:
    default_config = {
        "ai": {
            "enabled": True,
            "base_url": "http://192.168.1.50:1234/v1",
            "model_name": "qwen2.5-35b-instruct",
            "timeout": 300
        },
        "last_cidr": "",
        "password_hash": None,
        "session_token": None
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                stored = json.load(f)
                # Merge with defaults to ensure all keys exist
                if "ai" in stored: default_config["ai"].update(stored["ai"])
                if "last_cidr" in stored: default_config["last_cidr"] = stored["last_cidr"]
                if "password_hash" in stored: default_config["password_hash"] = stored["password_hash"]
                if "session_token" in stored: default_config["session_token"] = stored["session_token"]
                return default_config
        except:
            return default_config
    return default_config

def save_config(config: Dict[str, Any]):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# Global instances and config
executor = ThreadPoolExecutor(max_workers=50)
mac_lookup = AsyncMacLookup()
current_config = load_config()
ai_config = current_config["ai"]

async def verify_token(x_sentinel_token: Optional[str] = Header(None)):
    if not current_config.get("password_hash"):
        return # Allow setup
    if not x_sentinel_token or x_sentinel_token != current_config.get("session_token"):
        raise HTTPException(status_code=401, detail="Unauthorized")

# Risk Weights for common ports (0-10)
PORT_WEIGHTS = {
    21: 8,    # FTP
    22: 4,    # SSH (usually authorized, but high impact)
    23: 9,    # Telnet (Insecure)
    25: 5,    # SMTP
    53: 3,    # DNS
    80: 4,    # HTTP
    111: 6,   # RPC
    135: 7,   # RPC Endpoint Mapper
    139: 8,   # NetBIOS
    443: 2,   # HTTPS
    445: 10,  # SMB (High Risk)
    3306: 6,  # MySQL
    3389: 9,  # RDP
    5432: 6,  # PostgreSQL
    5900: 8,  # VNC
    5985: 8,  # WinRM (HTTP)
    5986: 8,  # WinRM (HTTPS)
    8080: 5,  # HTTP Proxy/Alt
}

def load_history() -> Dict[str, Any]:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_history(history: Dict[str, Any]):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

class CIDRRequest(BaseModel):
    cidr: str = Field(..., json_schema_extra={"example": "192.168.1.0/24"})

class IPRequest(BaseModel):
    ip: str = Field(..., json_schema_extra={"example": "192.168.1.1"})

class AIConfigRequest(BaseModel):
    base_url: str
    model_name: str
    enabled: bool = True

class AIAnalyzeRequest(BaseModel):
    host_data: Dict[str, Any]

class ConfirmRequest(BaseModel):
    ip: str
    port: int
    service: str
    confirmed: bool

class AuthRequest(BaseModel):
    password: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    executor.shutdown(wait=True)

app = FastAPI(title="Network Scanner API", lifespan=lifespan)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth Endpoints
@app.post("/api/auth/setup")
async def auth_setup(request: AuthRequest):
    global current_config
    if current_config.get("password_hash"):
        raise HTTPException(status_code=400, detail="Setup already completed")
    
    current_config["password_hash"] = hash_password(request.password)
    current_config["session_token"] = str(uuid.uuid4())
    save_config(current_config)
    return {"status": "ok", "token": current_config["session_token"]}

@app.post("/api/auth/login")
async def auth_login(request: AuthRequest):
    global current_config
    hashed = current_config.get("password_hash")
    if not hashed or not verify_password(request.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    current_config["session_token"] = str(uuid.uuid4())
    save_config(current_config)
    return {"status": "ok", "token": current_config["session_token"]}

@app.post("/api/auth/logout")
async def auth_logout(x_sentinel_token: str = Depends(verify_token)):
    global current_config
    current_config["session_token"] = None
    save_config(current_config)
    return {"status": "ok"}

@app.get("/api/auth/status")
async def auth_status():
    global current_config
    return {"setup_required": current_config.get("password_hash") is None}

# Global state for tracking scans
scan_registry: Dict[str, Dict[str, Any]] = {}

def cleanup_old_scans():
    """Remove completed scans older than SCAN_CLEANUP_AGE_MINUTES."""
    cutoff = datetime.now() - timedelta(minutes=SCAN_CLEANUP_AGE_MINUTES)
    to_remove = [
        scan_id for scan_id, data in scan_registry.items()
        if data.get("status") in ("completed", "failed")
        and data.get("completed_at", datetime.min) < cutoff
    ]
    for scan_id in to_remove:
        del scan_registry[scan_id]

def get_hostname(ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname else ip
    except socket.herror:
        return ip

def get_mac_from_arp(ip: str) -> Optional[str]:
    """Get MAC address from ARP table using subprocess."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == ip:
                    mac_addr = parts[2].replace(":", "").lower()
                    return mac_addr
    except (subprocess.TimeoutExpired, Exception):
        pass
    return None

async def lookup_vendor(mac: str) -> str:
    """Lookup vendor information using AsyncMacLookup singleton."""
    try:
        if not mac or mac == "N/A":
            return "Unknown"
        return await mac_lookup.lookup(mac)
    except (VendorNotFoundError, Exception):
        return "Unknown"

def ping_host(ip: str) -> bool:
    """Ping a host using system ping command."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False

def register_scan() -> str:
    """Register a new scan with pending status."""
    cleanup_old_scans()
    scan_id = str(uuid.uuid4())
    scan_registry[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "progress": 0,
        "total": 1,
        "results": [],
        "error": None,
        "current_ip": None
    }
    return scan_id

def update_scan(scan_id: str, **kwargs) -> Dict[str, Any]:
    """Update scan status and data."""
    if scan_id in scan_registry:
        for key, value in kwargs.items():
            scan_registry[scan_id][key] = value
        return scan_registry[scan_id]
    return {}

async def discover_scan_worker(cidr: str, scan_id: str):
    """Worker function for ping sweep discovery scan."""
    try:
        update_scan(scan_id, status="running", progress=0, current_ip="starting")
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        update_scan(scan_id, total=total_hosts)
        
        semaphore = asyncio.Semaphore(50)
        loop = asyncio.get_running_loop()
        
        async def ping_and_enrich(ip_str: str, index: int):
            async with semaphore:
                if index % max(1, total_hosts // 20) == 0:
                    prog = int((index / total_hosts) * 100)
                    update_scan(scan_id, progress=prog, current_ip=ip_str)

                is_alive = await loop.run_in_executor(executor, ping_host, ip_str)
                if is_alive:
                    hostname = await loop.run_in_executor(executor, get_hostname, ip_str)
                    mac_addr = await loop.run_in_executor(executor, get_mac_from_arp, ip_str)
                    vendor = await lookup_vendor(mac_addr)
                    return {
                        "hostname": hostname, "ip": ip_str,
                        "mac": mac_addr if mac_addr else "N/A",
                        "vendor": vendor, "index": index
                    }
                return None
        
        results = await asyncio.gather(*[ping_and_enrich(str(host), i) for i, host in enumerate(hosts)])
        live_hosts = sorted([r for r in results if r], key=lambda x: x["index"])
        for h in live_hosts: del h["index"]
        
        # Save discovered hosts to history (persist MAC, vendor, hostname)
        history = load_history()
        for host in live_hosts:
            ip = host["ip"]
            if ip not in history:
                history[ip] = {"confirmed": []}
            history[ip]["mac"] = host.get("mac", "N/A")
            history[ip]["vendor"] = host.get("vendor", "Unknown")
            history[ip]["hostname"] = host.get("hostname", "")
        save_history(history)
        
        update_scan(scan_id, status="completed", results=live_hosts, progress=100, current_ip="done", completed_at=datetime.now())
    except Exception as e:
        update_scan(scan_id, status="failed", error=str(e), completed_at=datetime.now())

async def port_scan_worker(ip: str, scan_id: str):
    """Worker function for Nmap port scanning with history comparison."""
    try:
        print(f"[*] Starting port scan for {ip} (Scan ID: {scan_id})")
        update_scan(scan_id, status="running", progress=10)
        history = load_history()
        
        # Get current MAC address for comparison
        loop = asyncio.get_running_loop()
        mac_addr = await loop.run_in_executor(executor, get_mac_from_arp, ip)
        
        # Check if MAC changed - if so, fail the scan (ignore "N/A" as valid stored MAC)
        stored_mac = history.get(ip, {}).get("mac", "")
        if stored_mac and stored_mac != "N/A" and mac_addr and mac_addr != "N/A" and stored_mac != mac_addr:
            print(f"[!] MAC address changed for {ip}: stored={stored_mac}, current={mac_addr}")
            update_scan(scan_id, status="failed", error="MAC address changed - run a new network discovery scan first", completed_at=datetime.now())
            return
        
        vendor = await lookup_vendor(mac_addr) if mac_addr else "Unknown"
        hostname = await loop.run_in_executor(executor, get_hostname, ip)
        
        # Check if MAC changed - if so, treat as new device
        is_new_device = stored_mac and mac_addr and stored_mac != mac_addr
        is_first_scan = is_new_device or ip not in history or not history[ip].get("last_ports")
        
        prev_scan_ports = history.get(ip, {}).get("last_ports", [])
        confirmed_ok = history.get(ip, {}).get("confirmed", [])

        def run_nmap():
            nm = nmap.PortScanner()
            # -Pn: Skip host discovery (treat as online)
            # -sV: Version detection
            # -T4: Aggressive timing
            print(f"[*] Running nmap -sV -Pn -T4 {ip}...")
            nm.scan(hosts=ip, arguments="-sV -Pn -T4")
            return nm

        loop = asyncio.get_running_loop()
        try:
            nm = await loop.run_in_executor(executor, run_nmap)
            print(f"[*] Nmap scan finished for {ip}")
        except Exception as e:
            print(f"[!] Nmap execution error: {e}")
            raise Exception(f"Nmap failed: {e}")

        scanned_hosts = nm.all_hosts()
        host_result = nm[ip] if ip in scanned_hosts else None
        
        if not host_result:
            print(f"[!] No results found for host {ip}")

        current_results = []
        if host_result and "tcp" in host_result:
            tcp_ports = host_result.get("tcp", {})
            print(f"[*] Found {len(tcp_ports)} open ports on {ip}")
            for port_num, port_info in sorted(tcp_ports.items()):
                p_num = int(port_num)
                p_srv = port_info.get("name", "unknown")
                p_ver = (port_info.get("product", "") + " " + port_info.get("version", "")).strip()
                
                key = f"{p_num}/{p_srv}"
                is_confirmed = key in confirmed_ok
                risk_weight = PORT_WEIGHTS.get(p_num, 3) # Default weight of 3 for unknown ports
                
                # Logic: If it's the first scan, it's 'baseline'. If not, and it's not in prev, it's 'new'.
                if is_first_scan:
                    change = "baseline"
                else:
                    change = "new" if not any(p["port"] == p_num for p in prev_scan_ports) else "unchanged"
                
                current_results.append({
                    "port": p_num, "protocol": "tcp", "state": "open",
                    "service": p_srv, "version": p_ver,
                    "confirmed_ok": is_confirmed, "change": change,
                    "risk_weight": risk_weight
                })

        # Check for closed ports
        if not is_first_scan:
            for old_p in prev_scan_ports:
                if not any(curr["port"] == old_p["port"] for curr in current_results):
                    current_results.append({
                        **old_p, "state": "closed", "change": "removed", "confirmed_ok": False
                    })

        # Update History
        if ip not in history: history[ip] = {"confirmed": []}
        history[ip]["last_ports"] = [p for p in current_results if p["state"] == "open"]
        history[ip]["last_scanned"] = datetime.now().isoformat()
        history[ip]["mac"] = mac_addr if mac_addr else "N/A"
        history[ip]["hostname"] = hostname if hostname else ""
        history[ip]["vendor"] = vendor
        save_history(history)

        # Add last_scanned timestamp to each port result
        last_scanned = history[ip].get("last_scanned", "")
        for port in current_results:
            port["last_scanned"] = last_scanned

        # Log to TXT
        with open(PORT_LOG_FILE, "a") as log:
            log.write(f"\n[{datetime.now().isoformat()}] {ip} results:\n")
            for p in current_results:
                log.write(f"  {p['port']}/{p['service']} ({p['state']}) [{p['change']}]\n")

        update_scan(scan_id, status="completed", results=current_results, progress=100, completed_at=datetime.now())
    except Exception as e:
        print(f"[!] Critical Error in port_scan_worker for {ip}: {e}")
        import traceback
        traceback.print_exc()
        update_scan(scan_id, status="failed", error=str(e), completed_at=datetime.now())

@app.get("/")
async def get_dashboard():
    if os.path.exists("dashboard.html"): return FileResponse("dashboard.html")
    return {"error": "dashboard.html not found"}

@app.post("/api/scan/discover", dependencies=[Depends(verify_token)])
async def discover_hosts(request: CIDRRequest, background_tasks: BackgroundTasks):
    # Save last CIDR
    global current_config
    current_config["last_cidr"] = request.cidr
    save_config(current_config)

    scan_id = register_scan()
    background_tasks.add_task(discover_scan_worker, request.cidr, scan_id)
    return {"scan_id": scan_id, "status": "pending"}

@app.post("/api/scan/ports", dependencies=[Depends(verify_token)])
async def port_scan(request: IPRequest, background_tasks: BackgroundTasks):
    scan_id = register_scan()
    background_tasks.add_task(port_scan_worker, request.ip, scan_id)
    return {"scan_id": scan_id, "status": "pending"}

@app.get("/api/scan/history", dependencies=[Depends(verify_token)])
async def get_scan_history():
    """Return all historical hosts with their ports and last scanned timestamps."""
    history = load_history()
    hosts = []
    for ip, data in history.items():
        if data.get("last_ports"):
            hosts.append({
                "ip": ip,
                "mac": data.get("mac", "N/A"),
                "hostname": data.get("hostname", ""),
                "vendor": data.get("vendor", "Unknown"),
                "last_scanned": data.get("last_scanned", data.get("last_scan", "")),
                "last_ports": data.get("last_ports", []),
                "confirmed": data.get("confirmed", [])
            })
    return {"hosts": hosts}

@app.get("/api/scan/status", dependencies=[Depends(verify_token)])
async def get_status(scan_id: str):
    if scan_id not in scan_registry:
        print(f"[!] Status check for unknown scan ID: {scan_id}")
        raise HTTPException(status_code=404, detail="Scan not found")
    data = scan_registry[scan_id]
    print(f"[*] Status check for {scan_id}: {data.get('status')} - Results count: {len(data.get('results', []))}")
    return data

@app.get("/api/config/last_cidr", dependencies=[Depends(verify_token)])
async def get_last_cidr():
    return {"cidr": current_config.get("last_cidr", "")}

@app.get("/api/ai/config", dependencies=[Depends(verify_token)])
async def get_ai_config():
    return ai_config

@app.post("/api/ai/config", dependencies=[Depends(verify_token)])
async def set_ai_config(request: AIConfigRequest):
    global ai_config, current_config
    ai_config.update({"base_url": request.base_url.rstrip("/"), "model_name": request.model_name, "enabled": request.enabled})
    current_config["ai"] = ai_config
    save_config(current_config)
    return ai_config

@app.get("/api/ai/health", dependencies=[Depends(verify_token)])
async def check_ai_health():
    if not ai_config["enabled"]:
        return {"status": "disabled"}
    try:
        async with aiohttp.ClientSession() as session:
            # Use the standard OpenAI-compatible /v1/models endpoint
            url = f"{ai_config['base_url']}/v1/models"
            async with session.get(url, timeout=2) as resp:
                if resp.status == 200:
                    return {"status": "online"}
    except:
        pass
    return {"status": "offline"}

@app.get("/api/ai/models", dependencies=[Depends(verify_token)])
async def get_available_models():
    """Fetch list of loaded models from LM Studio."""
    if not ai_config["enabled"]:
        return {"models": []}
    try:
        async with aiohttp.ClientSession() as session:
            # We use LM Studio's specific API to see which models are actually LOADED
            url = f"{ai_config['base_url']}/api/v1/models"
            async with session.get(url, timeout=2) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # LM Studio specific structure: data['models'] list of objects with 'key' and 'loaded_instances'
                    models_list = data.get('models', [])
                    # Only return models that have active loaded instances
                    models = [m['key'] for m in models_list if m.get('loaded_instances')]
                    return {"models": models}
    except Exception as e:
        print(f"Error fetching models: {e}")
    return {"models": []}

@app.post("/api/history/confirm", dependencies=[Depends(verify_token)])
async def confirm_port(request: ConfirmRequest):
    history = load_history()
    if request.ip not in history: history[request.ip] = {"confirmed": [], "last_ports": []}
    key = f"{request.port}/{request.service}"
    confirmed = history[request.ip].get("confirmed", [])
    if request.confirmed and key not in confirmed: confirmed.append(key)
    elif not request.confirmed and key in confirmed: confirmed.remove(key)
    history[request.ip]["confirmed"] = confirmed
    save_history(history)
    return {"status": "ok", "confirmed": confirmed}

@app.post("/api/ai/analyze", dependencies=[Depends(verify_token)])
async def analyze_host(request: AIAnalyzeRequest):
    if not ai_config["enabled"]: raise HTTPException(status_code=400, detail="AI Disabled")

    # Verify model is actually loaded
    try:
        async with aiohttp.ClientSession() as session:
            # We use LM Studio specific API for the loading check
            url = f"{ai_config['base_url']}/api/v1/models"
            async with session.get(url, timeout=2) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models_list = data.get('models', [])
                    loaded_models = [m['key'] for m in models_list if m.get('loaded_instances')]
                    if ai_config["model_name"] not in loaded_models:
                        raise HTTPException(status_code=400, detail=f"Model '{ai_config['model_name']}' is not loaded in LM Studio. Please load it first.")
    except HTTPException: raise
    except Exception: pass # If check fails due to network, try the call anyway

    host = request.host_data
    all_ports = host.get("ports", [])
    unverified = [p for p in all_ports if not p.get("confirmed_ok") and p["state"] == "open"]
    
    if not unverified:
        return {"analysis": "### Executive Security Summary\n\n✅ **Network Baseline Verified.** All active services on this host have been reviewed and authorized by the system administrator. No unauthorized or high-risk services were detected during this scan."}

    # Internal prompt - strictly instructions, the AI should not repeat these
    prompt = f"""
    Act as a Senior Cyber Security Consultant delivering a summary report to a CTO.
    Your goal is to provide a professional, high-signal audit of the host: {host.get('ip')} ({host.get('vendor')}).
    
    DATA (FOR YOUR ANALYSIS ONLY - DO NOT MENTION THESE TAGS BY NAME):
    {json.dumps(unverified, indent=2)}
    
    REPORT STRUCTURE:
    1. Executive Summary: A 2-3 sentence overview of the host's current risk posture.
    2. Key Risks: Focus only on the unverified services. Use the "risk_weight" (1-10) to prioritize findings. If a service is marked as "new", treat it as a potential unauthorized change. If it is "baseline", treat it as an existing but unverified risk.
    3. Business Impact: What happens if these ports are exploited?
    4. Action Plan: 3-4 bullet points for the technical team.
    
    STYLE GUIDELINES:
    - DO NOT mention "confirmed_ok", "baseline", "new", or "risk_weight" status by name. Use them to inform your tone (e.g., instead of "Port 445 has a risk weight of 10", say "The presence of SMB services poses a critical exposure risk...").
    - DO NOT acknowledge your instructions or the fact that you are an AI.
    - DO NOT include meta-talk about baselines or exclusion lists.
    - Keep it concise, authoritative, and board-ready.
    """
    try:
        async with aiohttp.ClientSession() as session:
            # Use the standard OpenAI-compatible /v1/chat/completions endpoint
            async with session.post(f"{ai_config['base_url']}/v1/chat/completions",
                json={
                    "model": ai_config["model_name"], 
                    "messages": [
                        {"role": "system", "content": "You are a professional security consultant. You provide concise, executive-level security reports. You never explain your internal logic or data processing steps."},
                        {"role": "user", "content": prompt}
                    ], 
                    "temperature": 0.2
                },
                timeout=ai_config["timeout"]) as resp:
                result = await resp.json()
                return {"analysis": result['choices'][0]['message']['content']}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
async def health_check(): return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    import ssl
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("cert.pem", "key.pem")
    uvicorn.run(app, host="0.0.0.0", port=8765, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
