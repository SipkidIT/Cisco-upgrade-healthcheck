import io
import csv
import os
import re
import json
import time
import hashlib
import difflib
import secrets
import threading
from datetime import datetime
from zoneinfo import ZoneInfo
import paramiko
from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from netmiko import ConnectHandler, file_transfer
from netaddr import EUI, NotRegisteredError
import psycopg2
from psycopg2.extras import RealDictCursor

for kex in (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
):
    if kex not in paramiko.Transport._preferred_kex:
        paramiko.Transport._preferred_kex += (kex,)

for key in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
    if key not in paramiko.Transport._preferred_keys:
        paramiko.Transport._preferred_keys += (key,)

for cipher in ("aes128-cbc", "aes256-cbc", "3des-cbc"):
    if cipher not in paramiko.Transport._preferred_ciphers:
        paramiko.Transport._preferred_ciphers += (cipher,)

PST = ZoneInfo("America/Los_Angeles")
IMAGES_DIR = "/app/images"
SNAPSHOTS_DIR = "/app/snapshots"
os.makedirs(IMAGES_DIR, exist_ok=True)
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

security = HTTPBasic()
templates = Jinja2Templates(directory="templates")


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "")
    if not admin_pass:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ADMIN_PASSWORD is not configured in .env",
        )
    correct_user = secrets.compare_digest(credentials.username, admin_user)
    correct_pass = secrets.compare_digest(credentials.password, admin_pass)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


app = FastAPI(
    title="Cisco Upgrade Health Check",
    dependencies=[Depends(verify_admin)],
)


def get_db():
    return psycopg2.connect(
        host="db",
        database=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        cursor_factory=RealDictCursor,
    )


class CheckRequest(BaseModel):
    host: str
    username: str
    password: str
    secret: str = ""
    device_type: str = "switch"
    phase: str = "PRE"


class UpgradeRequest(BaseModel):
    host: str
    username: str
    password: str
    secret: str = ""
    device_type: str = "switch"
    image_filename: str
    mode: str = "STAGE_ONLY"
    expected_md5: str = ""
    auto_clean_inactive: bool = False
    auto_pre_check: bool = True
    auto_post_check: bool = True


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name).strip())


def resolve_vendor(mac_addr: str) -> str:
    try:
        clean = mac_addr.replace(".", "").replace(":", "").replace("-", "").strip()
        if len(clean) < 12 or clean.lower() == "incomplete":
            return "Incomplete / Unknown"
        mac = EUI(clean)
        return mac.oui.registration().org
    except NotRegisteredError:
        return "Unknown / Locally Administered"
    except Exception:
        return "Unknown / Locally Administered"


def compute_md5(filepath: str) -> str:
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_conn_params(host: str, username: str, password: str, secret: str = "") -> dict:
    return {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "secret": secret or password,
        "disabled_algorithms": {
            "pubkeys": [],
            "kex": [],
            "ciphers": [],
            "macs": [],
        },
    }


def collect_and_save_snapshot(host: str, username: str, password: str, secret: str, device_type: str, phase: str) -> dict:
    conn_params = build_conn_params(host, username, password, secret)
    with ConnectHandler(**conn_params) as net_connect:
        net_connect.enable()
        prompt_hostname = net_connect.find_prompt().rstrip("#>") or host

        interfaces = net_connect.send_command("show interface status", use_textfsm=True)
        if not isinstance(interfaces, list) or len(interfaces) == 0:
            interfaces = net_connect.send_command("show ip interface brief", use_textfsm=True)
        if not isinstance(interfaces, list):
            interfaces = []

        raw_arp = net_connect.send_command("show ip arp", use_textfsm=True)
        arp_table = []
        if isinstance(raw_arp, list):
            for entry in raw_arp:
                mac = entry.get("mac") or entry.get("mac_address") or ""
                entry["vendor"] = resolve_vendor(mac)
                arp_table.append(entry)

        mac_table = []
        if device_type.lower() == "switch":
            raw_macs = net_connect.send_command("show mac address-table", use_textfsm=True)
            if isinstance(raw_macs, list):
                for entry in raw_macs:
                    raw_port = entry.get("destination_port") or entry.get("ports") or ""
                    port_str = ",".join(raw_port) if isinstance(raw_port, list) else str(raw_port)
                    if "cpu" in port_str.lower():
                        continue
                    if "vlan" not in entry and "vlan_id" in entry:
                        entry["vlan"] = entry["vlan_id"]
                    mac = entry.get("destination_address") or entry.get("mac", "")
                    entry["vendor"] = resolve_vendor(mac)
                    mac_table.append(entry)

        running_config = net_connect.send_command("show running-config")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO devices (hostname, ip_address, device_type)
        VALUES (%s, %s, %s)
        ON CONFLICT (ip_address) DO UPDATE
        SET hostname = EXCLUDED.hostname, device_type = EXCLUDED.device_type
        RETURNING id;
        """,
        (prompt_hostname, host, device_type.lower()),
    )
    device_id = cur.fetchone()["id"]

    cur.execute(
        """
        INSERT INTO health_snapshots
        (device_id, phase, interfaces_json, arp_table_json, mac_table_json, running_config)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id, captured_at;
        """,
        (
            device_id,
            phase.upper(),
            json.dumps(interfaces),
            json.dumps(arp_table),
            json.dumps(mac_table),
            running_config,
        ),
    )
    snap = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    captured_pst = snap["captured_at"].astimezone(PST)
    ts_display = captured_pst.strftime("%Y-%m-%d %H:%M:%S %Z")
    ts_file = captured_pst.strftime("%Y-%m-%d_%H-%M-%S_PST")

    device_folder = sanitize_filename(f"{prompt_hostname}_{host}")
    folder_path = os.path.join(SNAPSHOTS_DIR, device_folder)
    os.makedirs(folder_path, exist_ok=True)
    snap_filename = f"{phase.upper()}_{ts_file}.json"
    rel_file_path = f"{device_folder}/{snap_filename}"
    full_file_path = os.path.join(SNAPSHOTS_DIR, rel_file_path)

    file_payload = {
        "snapshot_id": snap["id"],
        "device_id": device_id,
        "hostname": prompt_hostname,
        "ip_address": host,
        "device_type": device_type.lower(),
        "phase": phase.upper(),
        "timestamp_pst": ts_display,
        "interfaces": interfaces,
        "arp_table": arp_table,
        "mac_table": mac_table,
        "running_config": running_config,
    }
    with open(full_file_path, "w", encoding="utf-8") as f:
        json.dump(file_payload, f, indent=2)

    return {
        "snapshot_id": snap["id"],
        "device_id": device_id,
        "hostname": prompt_hostname,
        "phase": phase.upper(),
        "timestamp_pst": ts_display,
        "snapshot_file": rel_file_path,
    }


def get_flash_free_bytes(net_connect) -> int:
    out = net_connect.send_command("dir flash:")
    match = re.search(r"\((\d+)\s+bytes\s+free\)", out, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return -1


def flash_file_exists(net_connect, filename: str) -> bool:
    out = net_connect.send_command(f"dir flash:{filename}")
    lower = out.lower()
    if "no such file" in lower or "error" in lower or "%invalid" in lower:
        return False
    return filename.lower() in lower


def append_job_log(job_id: int, message: str, new_status: str = None, hostname: str = None):
    ts = datetime.now(PST).strftime("%Y-%m-%d %H:%M:%S %Z")
    line = f"[{ts}] {message}\n"
    conn = get_db()
    cur = conn.cursor()
    if new_status in ("COMPLETED", "FAILED"):
        cur.execute(
            """
            UPDATE upgrade_jobs
            SET logs = logs || %s, status = %s, hostname = COALESCE(%s, hostname), finished_at = NOW()
            WHERE id = %s;
            """,
            (line, new_status, hostname, job_id),
        )
    elif new_status:
        cur.execute(
            """
            UPDATE upgrade_jobs
            SET logs = logs || %s, status = %s, hostname = COALESCE(%s, hostname)
            WHERE id = %s;
            """,
            (line, new_status, hostname, job_id),
        )
    else:
        cur.execute(
            "UPDATE upgrade_jobs SET logs = logs || %s, hostname = COALESCE(%s, hostname) WHERE id = %s;",
            (line, hostname, job_id),
        )
    conn.commit()
    cur.close()
    conn.close()


def ensure_image_staged_on_flash(job_id: int, net_connect, image_path: str, image_name: str, auto_clean: bool) -> bool:
    image_size = os.path.getsize(image_path)
    image_mb = round(image_size / (1024 * 1024), 2)
    required_bytes = int(image_size * 1.5)
    required_mb = round(required_bytes / (1024 * 1024), 2)

    if flash_file_exists(net_connect, image_name):
        append_job_log(job_id, f"Found existing {image_name} on flash:. Verifying MD5 integrity...")
        verify_res = file_transfer(
            net_connect,
            source_file=image_path,
            dest_file=image_name,
            file_system="flash:",
            direction="put",
            overwrite_file=False,
            verify_file=True,
        )
        if verify_res.get("file_verified"):
            append_job_log(job_id, f"MD5 verified! {image_name} is already staged on flash: (skipped SCP upload).")
            return True
        append_job_log(job_id, f"Existing {image_name} on flash: failed MD5 check. Will re-upload.")

    append_job_log(job_id, f"Running pre-flight flash: free-space check (Image: {image_mb} MB, Recommended: {required_mb} MB)...")
    free_bytes = get_flash_free_bytes(net_connect)
    if free_bytes >= 0:
        free_mb = round(free_bytes / (1024 * 1024), 2)
        append_job_log(job_id, f"Available flash: space: {free_mb} MB.")

        if free_bytes < required_bytes:
            if auto_clean:
                append_job_log(job_id, "Low flash space detected. Running 'install remove inactive'...")
                clean_out = net_connect.send_command_timing("install remove inactive", read_timeout=180)
                if "[y/n]" in clean_out.lower() or "proceed" in clean_out.lower():
                    clean_out += net_connect.send_command_timing("y", read_timeout=180)
                free_bytes = get_flash_free_bytes(net_connect)
                free_mb = round(free_bytes / (1024 * 1024), 2)
                append_job_log(job_id, f"Available flash: space after cleanup: {free_mb} MB.")

            if free_bytes < image_size:
                append_job_log(
                    job_id,
                    f"ABORTED: Insufficient flash: space ({free_mb} MB free, image requires {image_mb} MB).",
                    "FAILED",
                )
                return False
            elif free_bytes < required_bytes:
                append_job_log(
                    job_id,
                    f"WARNING: Tight flash space ({free_mb} MB free vs {required_mb} MB recommended), proceeding...",
                )

    append_job_log(job_id, f"Transferring {image_name} ({image_mb} MB) to flash: via SCP...")
    transfer_res = file_transfer(
        net_connect,
        source_file=image_path,
        dest_file=image_name,
        file_system="flash:",
        direction="put",
        overwrite_file=True,
        verify_file=True,
    )
    if not transfer_res.get("file_verified"):
        append_job_log(job_id, "ERROR: SCP transfer completed, but remote MD5 verification failed!", "FAILED")
        return False

    append_job_log(job_id, f"SCP transfer complete and remote MD5 verified for flash:{image_name}!")
    return True


def execute_iosxe_upgrade(job_id: int, req: UpgradeRequest):
    image_name = os.path.basename(req.image_filename)
    image_path = os.path.join(IMAGES_DIR, image_name)
    mode = req.mode.upper()

    if not os.path.isfile(image_path):
        append_job_log(job_id, f"ERROR: Image file {image_name} not found in /app/images.", "FAILED")
        return

    try:
        append_job_log(job_id, f"Mode: {mode} | Calculating local MD5 for {image_name}...")
        local_md5 = compute_md5(image_path)
        append_job_log(job_id, f"Local MD5: {local_md5}")

        if req.expected_md5 and req.expected_md5.strip().lower() != local_md5.lower():
            append_job_log(
                job_id,
                f"ERROR: MD5 mismatch! Expected {req.expected_md5.strip().lower()}, got {local_md5}",
                "FAILED",
            )
            return

        conn_params = build_conn_params(req.host, req.username, req.password, req.secret)

        if mode == "STAGE_ONLY":
            with ConnectHandler(**conn_params) as net_connect:
                net_connect.enable()
                hostname = net_connect.find_prompt().rstrip("#>") or req.host
                append_job_log(job_id, f"Connected to {hostname} for image staging.", hostname=hostname)
                if not ensure_image_staged_on_flash(job_id, net_connect, image_path, image_name, req.auto_clean_inactive):
                    return
            append_job_log(job_id, f"STAGING COMPLETE: {image_name} is verified on flash: and ready.", "COMPLETED")
            return

        if req.auto_pre_check:
            append_job_log(job_id, "Running automatic PRE-upgrade health check snapshot...")
            pre_res = collect_and_save_snapshot(
                req.host, req.username, req.password, req.secret, req.device_type, "PRE"
            )
            append_job_log(job_id, f"PRE snapshot saved ({pre_res['snapshot_file']}).", hostname=pre_res["hostname"])

        with ConnectHandler(**conn_params) as net_connect:
            net_connect.enable()
            hostname = net_connect.find_prompt().rstrip("#>") or req.host
            append_job_log(job_id, f"Connected to {hostname}. Saving running configuration...", hostname=hostname)
            net_connect.send_command("write memory")

            ver_out = net_connect.send_command("show version | include Cisco IOS")
            append_job_log(job_id, f"Current Version: {ver_out.strip()}")

            if not ensure_image_staged_on_flash(job_id, net_connect, image_path, image_name, req.auto_clean_inactive):
                return

            install_cmd = f"install add file flash:{image_name} activate commit"
            append_job_log(job_id, f"Executing: {install_cmd}")
            output = net_connect.send_command_timing(install_cmd, strip_prompt=False, strip_command=False, read_timeout=300)
            append_job_log(job_id, output.strip())

            for _ in range(4):
                if "[y/n]" in output.lower() or "[yes/no]" in output.lower() or "proceed" in output.lower():
                    answer = "yes" if "[yes/no]" in output.lower() else "y"
                    append_job_log(job_id, f"Sending confirmation '{answer}'...")
                    try:
                        output = net_connect.send_command_timing(answer, strip_prompt=False, strip_command=False, read_timeout=300)
                        append_job_log(job_id, output.strip())
                    except Exception:
                        break
                else:
                    break

        append_job_log(job_id, "Device is expanding packages and reloading. Waiting 90 seconds before polling...", "RELOADING")
        time.sleep(90)

        reconnected = False
        for attempt in range(1, 31):
            append_job_log(job_id, f"Polling SSH reachability (attempt {attempt}/30)...")
            try:
                with ConnectHandler(**conn_params) as check_conn:
                    check_conn.enable()
                    new_ver = check_conn.send_command("show version | include Cisco IOS")
                    append_job_log(job_id, f"Device is BACK ONLINE! New Version: {new_ver.strip()}")
                    reconnected = True
                    break
            except Exception:
                time.sleep(30)

        if not reconnected:
            append_job_log(job_id, "WARNING: Timed out waiting for device to return via SSH after 15 minutes.", "FAILED")
            return

        if req.auto_post_check:
            append_job_log(job_id, "Waiting 20 seconds for interfaces/MACs to settle, then capturing POST snapshot...")
            time.sleep(20)
            post_res = collect_and_save_snapshot(
                req.host, req.username, req.password, req.secret, req.device_type, "POST"
            )
            append_job_log(job_id, f"POST snapshot saved ({post_res['snapshot_file']}).")

        append_job_log(job_id, "IOS-XE Upgrade workflow finished successfully!", "COMPLETED")

    except Exception as e:
        append_job_log(job_id, f"Upgrade failed with error: {str(e)}", "FAILED")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, username: str = Depends(verify_admin)):
    return templates.TemplateResponse("index.html", {"request": request, "username": username})


@app.get("/api/images")
def list_images():
    items = []
    for fname in sorted(os.listdir(IMAGES_DIR)):
        fpath = os.path.join(IMAGES_DIR, fname)
        if os.path.isfile(fpath) and not fname.startswith("."):
            size_mb = round(os.path.getsize(fpath) / (1024 * 1024), 2)
            items.append({"filename": fname, "size_mb": size_mb})
    return items


@app.post("/api/images/upload")
async def upload_image(file: UploadFile = File(...)):
    safe_name = os.path.basename(file.filename)
    dest = os.path.join(IMAGES_DIR, safe_name)
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
    return {"status": "uploaded", "filename": safe_name}


@app.post("/api/upgrade")
def start_upgrade(req: UpgradeRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO upgrade_jobs (device_ip, image_filename, status, logs)
        VALUES (%s, %s, 'RUNNING', %s)
        RETURNING id;
        """,
        (req.host, req.image_filename, f"Starting {req.mode} job for {req.host} -> {req.image_filename}\n"),
    )
    job_id = cur.fetchone()["id"]
    conn.commit()
    cur.close()
    conn.close()

    t = threading.Thread(target=execute_iosxe_upgrade, args=(job_id, req), daemon=True)
    t.start()
    return {"job_id": job_id, "status": "RUNNING"}


@app.get("/api/upgrade/{job_id}")
def get_upgrade_job(job_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM upgrade_jobs WHERE id = %s;", (job_id,))
    job = cur.fetchone()
    cur.close()
    conn.close()
    if not job:
        raise HTTPException(status_code=404, detail="Upgrade job not found")
    return job


@app.get("/api/devices")
def list_devices():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT d.id, d.hostname, d.ip_address, d.device_type,
               COUNT(CASE WHEN h.phase = 'PRE' THEN 1 END) AS pre_count,
               COUNT(CASE WHEN h.phase = 'POST' THEN 1 END) AS post_count,
               MAX(CASE WHEN h.phase = 'PRE' THEN h.captured_at END) AS last_pre,
               MAX(CASE WHEN h.phase = 'POST' THEN h.captured_at END) AS last_post
        FROM devices d
        LEFT JOIN health_snapshots h ON d.id = h.device_id
        GROUP BY d.id
        ORDER BY d.id DESC;
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for row in rows:
        if row["last_pre"]:
            row["last_pre"] = row["last_pre"].astimezone(PST).strftime("%Y-%m-%d %H:%M:%S %Z")
        if row["last_post"]:
            row["last_post"] = row["last_post"].astimezone(PST).strftime("%Y-%m-%d %H:%M:%S %Z")
    return rows


@app.post("/api/healthcheck")
def run_health_check(req: CheckRequest):
    if req.phase.upper() not in ("PRE", "POST"):
        raise HTTPException(status_code=400, detail="Phase must be 'PRE' or 'POST'")
    try:
        res = collect_and_save_snapshot(
            req.host, req.username, req.password, req.secret, req.device_type, req.phase
        )
        return {"status": "success", **res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH Collection Failed: {str(e)}")


@app.get("/api/snapshots/{device_id}")
def get_device_snapshots(device_id: int, pre_id: int = None, post_id: int = None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s;", (device_id,))
    device = cur.fetchone()
    if not device:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    cur.execute(
        "SELECT id, phase, captured_at FROM health_snapshots WHERE device_id = %s ORDER BY captured_at DESC;",
        (device_id,),
    )
    all_rows = cur.fetchall()
    device_folder = sanitize_filename(f"{device['hostname']}_{device['ip_address']}")

    pre_history = []
    post_history = []
    for r in all_rows:
        dt_pst = r["captured_at"].astimezone(PST)
        ts_str = dt_pst.strftime("%Y-%m-%d %H:%M:%S %Z")
        fname = f"{r['phase']}_{dt_pst.strftime('%Y-%m-%d_%H-%M-%S_PST')}.json"
        item = {
            "id": r["id"],
            "timestamp_pst": ts_str,
            "filename": fname,
            "download_url": f"/api/snapshot-file/{device_folder}/{fname}"
            if os.path.isfile(os.path.join(SNAPSHOTS_DIR, device_folder, fname))
            else None,
        }
        if r["phase"] == "PRE":
            pre_history.append(item)
        elif r["phase"] == "POST":
            post_history.append(item)

    if pre_id:
        cur.execute("SELECT * FROM health_snapshots WHERE id = %s AND device_id = %s;", (pre_id, device_id))
    else:
        cur.execute(
            "SELECT * FROM health_snapshots WHERE device_id = %s AND phase = 'PRE' ORDER BY captured_at DESC LIMIT 1;",
            (device_id,),
        )
    pre = cur.fetchone()

    if post_id:
        cur.execute("SELECT * FROM health_snapshots WHERE id = %s AND device_id = %s;", (post_id, device_id))
    else:
        cur.execute(
            "SELECT * FROM health_snapshots WHERE device_id = %s AND phase = 'POST' ORDER BY captured_at DESC LIMIT 1;",
            (device_id,),
        )
    post = cur.fetchone()
    cur.close()
    conn.close()

    def format_snap(snap):
        if not snap:
            return None
        dt_pst = snap["captured_at"].astimezone(PST)
        fname = f"{snap['phase']}_{dt_pst.strftime('%Y-%m-%d_%H-%M-%S_PST')}.json"
        has_file = os.path.isfile(os.path.join(SNAPSHOTS_DIR, device_folder, fname))
        return {
            "id": snap["id"],
            "timestamp_pst": dt_pst.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "filename": fname if has_file else None,
            "download_url": f"/api/snapshot-file/{device_folder}/{fname}" if has_file else None,
            "interfaces": snap["interfaces_json"] or [],
            "arp_table": snap["arp_table_json"] or [],
            "mac_table": snap["mac_table_json"] or [],
            "running_config": snap["running_config"] or "",
        }

    config_diff = []
    if pre and post:
        config_diff = list(
            difflib.unified_diff(
                (pre["running_config"] or "").splitlines(),
                (post["running_config"] or "").splitlines(),
                fromfile=f"BEFORE ({pre['captured_at'].astimezone(PST).strftime('%Y-%m-%d %H:%M:%S %Z')})",
                tofile=f"AFTER ({post['captured_at'].astimezone(PST).strftime('%Y-%m-%d %H:%M:%S %Z')})",
                lineterm="",
            )
        )

    return {
        "device": device,
        "pre_history": pre_history,
        "post_history": post_history,
        "before": format_snap(pre),
        "after": format_snap(post),
        "config_diff": config_diff,
    }


@app.get("/api/snapshot-file/{device_folder}/{filename}")
def download_snapshot_file(device_folder: str, filename: str):
    safe_folder = sanitize_filename(device_folder)
    safe_file = sanitize_filename(filename)
    full_path = os.path.join(SNAPSHOTS_DIR, safe_folder, safe_file)
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="Snapshot file not found")
    return FileResponse(full_path, media_type="application/json", filename=safe_file)


def _norm_port(name: str) -> str:
    if not name:
        return ""
    s = str(name).strip().lower()
    for full, short in (
        ("twentyfivegige", "twe"),
        ("hundredgige", "hu"),
        ("fortygigabitethernet", "fo"),
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("port-channel", "po"),
    ):
        if s.startswith(full):
            return short + s[len(full):]
    return s


def _index_ports(snap: dict) -> dict:
    port_map = {}
    if not snap:
        return port_map
    for iface in snap.get("interfaces") or []:
        port_label = iface.get("port") or iface.get("interface") or ""
        key = _norm_port(port_label)
        if not key:
            continue
        port_map[key] = {
            "port": port_label,
            "name": str(iface.get("name") or "").strip(),
            "status": str(iface.get("status") or "").strip(),
            "vlan": str(iface.get("vlan") or "").strip(),
            "duplex": str(iface.get("duplex") or "").strip(),
            "speed": str(iface.get("speed") or "").strip(),
            "type": str(iface.get("type") or "").strip(),
            "macs": [],
        }
    for m in snap.get("mac_table") or []:
        raw_ports = m.get("destination_port") if isinstance(m.get("destination_port"), list) else [m.get("destination_port") or m.get("ports") or ""]
        for p in raw_ports:
            key = _norm_port(p)
            if not key:
                continue
            if key not in port_map:
                port_map[key] = {
                    "port": p,
                    "name": "",
                    "status": "",
                    "vlan": str(m.get("vlan") or m.get("vlan_id") or "").strip(),
                    "duplex": "",
                    "speed": "",
                    "type": "Logical",
                    "macs": [],
                }
            if not port_map[key]["vlan"] and (m.get("vlan") or m.get("vlan_id")):
                port_map[key]["vlan"] = str(m.get("vlan") or m.get("vlan_id")).strip()
            mac_val = str(m.get("destination_address") or m.get("mac") or "").strip()
            vendor_val = str(m.get("vendor") or "Unknown").strip()
            port_map[key]["macs"].append((mac_val, vendor_val))
    for entry in port_map.values():
        entry["macs"].sort(key=lambda x: x[0].lower())
    return port_map


@app.get("/api/export-csv/{device_id}")
def export_comparison_csv(device_id: int, pre_id: int = None, post_id: int = None):
    from fastapi.responses import StreamingResponse

    data = get_device_snapshots(device_id, pre_id=pre_id, post_id=post_id)
    device = data["device"]
    before = data["before"]
    after = data["after"]

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Cisco Upgrade Health Check Comparison Report"])
    writer.writerow(["Hostname", device["hostname"], "IP Address", device["ip_address"], "Device Type", device["device_type"].upper()])
    writer.writerow(["Before Snapshot (PST)", before["timestamp_pst"] if before else "Not Captured"])
    writer.writerow(["After Snapshot (PST)", after["timestamp_pst"] if after else "Not Captured"])
    writer.writerow([])

    # Section 1: Interface & MAC Comparison
    writer.writerow(["=== INTERFACE & MAC COMPARISON ==="])
    writer.writerow([
        "Change Status",
        "Port",
        "Before Name", "After Name",
        "Before Status", "After Status",
        "Before VLAN", "After VLAN",
        "Before Duplex", "After Duplex",
        "Before Speed", "After Speed",
        "Before Type", "After Type",
        "Before MACs", "After MACs",
        "Before Vendors", "After Vendors",
    ])

    pre_ports = _index_ports(before)
    post_ports = _index_ports(after)
    all_keys = list(pre_ports.keys()) + [k for k in post_ports.keys() if k not in pre_ports]

    for k in all_keys:
        p1 = pre_ports.get(k)
        p2 = post_ports.get(k)
        port_name = (p2 or p1)["port"]

        b_macs = "; ".join(m[0] for m in p1["macs"]) if p1 else ""
        a_macs = "; ".join(m[0] for m in p2["macs"]) if p2 else ""
        b_vendors = "; ".join(m[1] for m in p1["macs"]) if p1 else ""
        a_vendors = "; ".join(m[1] for m in p2["macs"]) if p2 else ""

        if p1 and not p2:
            chg = "MISSING AFTER UPGRADE"
        elif p2 and not p1:
            chg = "ADDED AFTER UPGRADE"
        else:
            diffs = (
                p1["name"] != p2["name"]
                or p1["status"] != p2["status"]
                or p1["vlan"] != p2["vlan"]
                or p1["duplex"] != p2["duplex"]
                or p1["speed"] != p2["speed"]
                or p1["type"] != p2["type"]
                or b_macs != a_macs
            )
            chg = "CHANGED" if diffs else "UNCHANGED"

        writer.writerow([
            chg,
            port_name,
            p1["name"] if p1 else "", p2["name"] if p2 else "",
            p1["status"] if p1 else "", p2["status"] if p2 else "",
            p1["vlan"] if p1 else "", p2["vlan"] if p2 else "",
            p1["duplex"] if p1 else "", p2["duplex"] if p2 else "",
            p1["speed"] if p1 else "", p2["speed"] if p2 else "",
            p1["type"] if p1 else "", p2["type"] if p2 else "",
            b_macs, a_macs,
            b_vendors, a_vendors,
        ])

    writer.writerow([])

    # Section 2: ARP Table Comparison
    writer.writerow(["=== ARP TABLE COMPARISON ==="])
    writer.writerow(["Change Status", "IP Address", "Before MAC", "After MAC", "Before Vendor", "After Vendor", "Before Interface", "After Interface"])

    pre_arp = {(a.get("address") or a.get("ip_address") or ""): a for a in (before["arp_table"] if before else [])}
    post_arp = {(a.get("address") or a.get("ip_address") or ""): a for a in (after["arp_table"] if after else [])}
    all_ips = list(pre_arp.keys()) + [ip for ip in post_arp.keys() if ip not in pre_arp]

    for ip in all_ips:
        if not ip:
            continue
        a1 = pre_arp.get(ip)
        a2 = post_arp.get(ip)
        m1 = (a1.get("mac") or a1.get("mac_address") or "") if a1 else ""
        m2 = (a2.get("mac") or a2.get("mac_address") or "") if a2 else ""
        v1 = a1.get("vendor", "") if a1 else ""
        v2 = a2.get("vendor", "") if a2 else ""
        i1 = a1.get("interface", "") if a1 else ""
        i2 = a2.get("interface", "") if a2 else ""

        if a1 and not a2:
            chg = "MISSING AFTER UPGRADE"
        elif a2 and not a1:
            chg = "ADDED AFTER UPGRADE"
        elif m1 != m2:
            chg = "MAC CHANGED"
        else:
            chg = "UNCHANGED"

        writer.writerow([chg, ip, m1, m2, v1, v2, i1, i2])

    output.seek(0)
    safe_host = sanitize_filename(f"{device['hostname']}_{device['ip_address']}")
    ts_now = datetime.now(PST).strftime("%Y-%m-%d_%H-%M-%S_PST")
    filename = f"Comparison_{safe_host}_{ts_now}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
