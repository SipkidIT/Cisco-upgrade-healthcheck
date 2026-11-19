# Cisco Upgrade Health Check & Automated IOS-XE Upgrade Portal

A self-hosted web application for network engineers to capture **Before (PRE)** and **After (POST)** health-check snapshots from Cisco IOS/IOS-XE switches and routers, resolve MAC addresses to IEEE OUI vendors offline, visualize vendor distributions, compare field-level changes side-by-side, export Excel-ready CSV reports, and stage or execute automated Cisco IOS-XE firmware upgrades.

---

## Features Built

* **Secure Web Portal (HTTPS + Auth)**: Served over TLS on port `8083` via Nginx reverse proxy with HTTP Basic Authentication (`ADMIN_USER` / `ADMIN_PASSWORD`) and a persistent **Dark / Light Mode** UI toggle.
* **Unified Interface & MAC Status Table**: Combines `show interface status` (or `show ip interface brief` on routers) with `show mac address-table` (dynamic + static entries, automatically filtering out `CPU` MACs) into a single table without duplicate columns.
* **Offline IEEE OUI Vendor Mapping & Pie Charts**: Maps every MAC address in both the **MAC Address Table** and **ARP Table** (`show ip arp`) to its hardware manufacturer offline using `netaddr`, paired with dynamic percentage pie charts.
* **Timestamped Snapshot Files & Date/Time Comparison**:
  * Every PRE and POST run saves a record to PostgreSQL **and** generates a standalone timestamped JSON file in `./snapshots/<hostname>_<ip>/<PRE|POST>_YYYY-MM-DD_HH-MM-SS_PST.json` (`America/Los_Angeles`).
  * Filter saved snapshots by date/time, pick any two historical PRE and POST runs from dropdowns, and download raw JSON files or export an **Excel-ready CSV Comparison Report**.
* **Targeted Field-Level Diffs & Row Alignment**:
  * Highlights only actual changes in `Port`, `Name`, `Status`, `VLAN`, `Duplex`, `Speed`, `Type`, `MAC Address`, and `Vendor` (crossing out missing MACs/vendors in red on the BEFORE side and highlighting newly learned ones in green on the AFTER side).
  * Automatically synchronizes row heights across side-by-side tables so ports, ARP tables, and running configs stay horizontally aligned.
* **3-Mode Automated Cisco IOS-XE Upgrade Engine**:
  * **Pre-Flight Flash Check**: Parses `dir flash:` before SCP copy to ensure at least `1.5x` image free space, with optional automated `install remove inactive` cleanup.
  * **Mode 1 (`STAGE_ONLY`)**: Copies `.bin` image to `flash:` via SCP and verifies remote MD5 hash with zero reboot.
  * **Mode 2 (`ACTIVATE_ONLY`)**: Uses an already-staged image on `flash:`, captures a PRE snapshot, runs `install add file flash:<image.bin> activate commit`, polls SSH until reboot completes, and captures a POST snapshot.
  * **Mode 3 (`FULL_UPGRADE`)**: Performs staging, PRE snapshot, `install add ... activate commit`, reload polling, and POST snapshot in one workflow.

---

## Project Directory Structure

```text
cisco-upgrade-healthcheck/
├── docker-compose.yml          # Orchestrates Nginx (8083), FastAPI (web), and PostgreSQL (db)
├── .env                        # Database & Web Portal admin credentials (excluded from Git)
├── README.md                   # Complete documentation, troubleshooting & AI rebuild prompt
├── images/                     # Local repository for Cisco .bin firmware images
├── snapshots/                  # Auto-generated timestamped PRE/POST JSON snapshot files
├── nginx/
│   ├── nginx.conf              # HTTPS reverse proxy (port 8083, 2GB upload limit, 600s timeout)
│   └── certs/                  # Self-signed or CA TLS certificates (cert.pem, key.pem)
└── app/
    ├── Dockerfile              # Python 3.11-slim container build
    ├── requirements.txt        # Pinned dependencies (paramiko==3.5.1, netmiko, netaddr, etc.)
    ├── main.py                 # FastAPI backend, Netmiko collector, CSV exporter & upgrade engine
    └── templates/
        └── index.html          # Single-page responsive dashboard (Dark/Light mode, charts, diffs)
```

---

## Quick Start & Installation

### 1. Create `.env` Configuration
```env
POSTGRES_DB=upgrade_healthcheck
POSTGRES_USER=netadmin
POSTGRES_PASSWORD=ChangeMeStrongDBPass!
ADMIN_USER=admin
ADMIN_PASSWORD=ChangeMeWebPortalPass!
```

### 2. Generate Self-Signed TLS Certificate (If Not Using Internal CA)
```bash
mkdir -p nginx/certs images snapshots
openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout nginx/certs/key.pem \
  -out nginx/certs/cert.pem \
  -subj "/CN=cisco-healthcheck.local"
```

### 3. Build & Launch Containers
```bash
docker compose up -d --build
```

### 4. Initialize PostgreSQL Tables
```bash
docker exec -i cuhc-db psql -U netadmin -d upgrade_healthcheck << 'SQL'
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    device_type VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS health_snapshots (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    phase VARCHAR(10) NOT NULL,
    interfaces_json JSONB,
    arp_table_json JSONB,
    mac_table_json JSONB,
    running_config TEXT,
    captured_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS upgrade_jobs (
    id SERIAL PRIMARY KEY,
    device_ip VARCHAR(45) NOT NULL,
    hostname VARCHAR(100),
    image_filename VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'RUNNING',
    logs TEXT DEFAULT '',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
SQL
```

Access the portal at **`https://<your-server-ip>:8083/`**.

---

## Cisco Switch & Router Prerequisites

Configure the following on target Cisco IOS/IOS-XE devices before running health checks or upgrades:

```ios
! 1. Local Privilege 15 User & Exec Authorization (Required for SCP file_transfer)
username admin privilege 15 secret <YourStrongPassword>
aaa new-model
aaa authentication login default local
aaa authorization exec default local

! 2. Enable SSH v2 & SCP Server (Required for Netmiko SCP image uploads)
ip domain name example.local
crypto key generate rsa modulus 2048
ip ssh version 2
ip scp server enable

! 3. Allow SSH on VTY Lines
line vty 0 15
 login authentication default
 transport input ssh
```

*(Note: Ensure your Catalyst 9000 / IOS-XE switch is booted in **Install Mode** (`packages.conf`) rather than Bundle Mode before running `install add file flash:<image.bin> activate commit`.)*

---

## Troubleshooting Lessons & Fixes Built Into This Project

During development, several real-world edge cases were encountered and permanently resolved in the codebase:

1. **Legacy Cisco SSH Key Exchange (`Incompatible ssh peer (no acceptable kex algorithm)`)**
   * **Cause**: Paramiko 4.0+ and 5.0+ removed SHA-1 Diffie-Hellman KEX handlers (`diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1`), causing connections to older Cisco switches/routers to fail—or raise `KeyError: 'diffie-hellman-group14-sha1'` when forced.
   * **Fix**: Pinned `paramiko==3.5.1` in `app/requirements.txt` and explicitly appended legacy KEX algorithms, `ssh-rsa` host keys, and CBC ciphers to `paramiko.Transport` in `app/main.py`.

2. **Empty OUI Vendor Resolution (`mac-vendor-lookup` Event Loop & Cache Failures)**
   * **Cause**: `MacLookup()` crashes inside FastAPI's active `asyncio` event loop, and `AsyncMacLookup()` fails when `/root/.cache/mac-vendors.txt` is empty or IEEE's server rate-limits container downloads.
   * **Fix**: Replaced `mac-vendor-lookup` with **`netaddr` (`EUI(mac).oui.registration().org`)**, which ships with a complete built-in offline IEEE OUI database requiring zero internet access or cache files.

3. **Blank VLAN Column in Newer `ntc-templates`**
   * **Cause**: Newer `ntc-templates` parsers return `vlan_id` instead of `vlan` for `show mac address-table`.
   * **Fix**: Normalized `entry["vlan"] = entry["vlan_id"]` in `app/main.py`.

4. **`RuntimeError: Form data requires "python-multipart" to be installed`**
   * **Cause**: FastAPI requires `python-multipart` to parse `UploadFile` requests on `/api/images/upload`.
   * **Fix**: Added `python-multipart==0.0.12` to `app/requirements.txt`.

5. **Nginx `502 Bad Gateway` After Container Rebuilds**
   * **Cause**: Rebuilding the `web` container assigns it a new internal Docker IP while Nginx caches the old upstream IP (or `web` fails to start due to a missing dependency).
   * **Fix**: Always run `docker compose up -d --build web && docker compose restart nginx` and check `docker logs cuhc-web --tail 30`.

6. **Table Row Misalignment When One Snapshot Has More Vendors or MACs**
   * **Cause**: Extra lines in the Vendor Pie Chart legend or multi-MAC trunk ports pushed the right-hand table down relative to the left-hand table.
   * **Fix**: Added `syncSideBySideHeights()` in `index.html` to equalize `.chart-wrapper`, individual `tbody tr` row heights (`preTables[0]` / `postTables[0]`), and table container heights across both columns.

---

## Master Prompt to Recreate or Extend This Project with AI

If you want to rebuild this exact application from scratch or spin up a similar network automation portal in the future, copy and paste the prompt below:

> **Prompt:**
> Build a containerized web application using **Docker Compose**, **FastAPI (Python 3.11)**, **PostgreSQL**, and an **Nginx HTTPS reverse proxy on port 8083** (with HTTP Basic Auth via `.env` and `America/Los_Angeles` PST timestamps) for Cisco IOS/IOS-XE switch and router upgrade health checks and automated firmware upgrades.
>
> **Include these exact technical requirements:**
> 1. **SSH & Legacy Cisco Compatibility**: Use `netmiko==4.4.0` with **`paramiko==3.5.1`** pinned in `requirements.txt`, and re-enable legacy SHA-1 KEX algorithms (`diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1`), `ssh-rsa` host keys, and CBC ciphers on `paramiko.Transport` so older Cisco devices connect cleanly.
> 2. **Health Check Data Collection**: Connect via SSH (`cisco_ios`) to collect `show interface status` (falling back to `show ip interface brief` for routers), `show ip arp`, `show mac address-table` (both dynamic and static entries, filtering out `CPU` ports and normalizing `vlan_id` to `vlan`), and `show running-config`.
> 3. **Offline Vendor Resolution**: Use **`netaddr`** (`EUI(mac).oui.registration().org`) for 100% offline MAC-to-vendor mapping on both ARP and MAC tables.
> 4. **Snapshot Persistence & Date/Time Comparison**: Save every PRE and POST run in PostgreSQL **and** write a standalone timestamped JSON file to `./snapshots/<hostname>_<ip>/<PRE|POST>_YYYY-MM-DD_HH-MM-SS_PST.json`. Provide a device dropdown, date/time search filter, PRE/POST snapshot selectors, raw JSON download links, and an Excel-ready **CSV Comparison Export** (`/api/export-csv/{device_id}`).
> 5. **Frontend Dashboard (`index.html`)**:
>    * Include a **Dark / Light Mode** toggle persisted in `localStorage`.
>    * Render a **Vendor Distribution Pie Chart** (with percentage breakdown and counts) for Before and After snapshots.
>    * Merge Interface Status and MAC/Vendor data into a **single unified table** (`Port`, `Name`, `Status`, `VLAN`, `Duplex`, `Speed`, `Type`, `MAC Address`, `Vendor`) without repeating fields.
>    * Highlight only changed cells in those 9 fields (with red strikethrough on missing MACs/Vendors in the BEFORE column and green highlights on added entries in the AFTER column), and synchronize row heights across both columns so rows align horizontally.
> 6. **3-Mode Automated IOS-XE Firmware Upgrade**:
>    * Support `.bin` uploads (`python-multipart`, Nginx `client_max_body_size 2G`) to `./images` and pre-flight `dir flash:` free-space checks (`1.5x` image size) with optional `install remove inactive` cleanup.
>    * Provide three execution modes with live background log polling: **`STAGE_ONLY`** (SCP upload + remote MD5 verify, no reboot), **`ACTIVATE_ONLY`** (auto-PRE check, `install add file flash:<image.bin> activate commit`, SSH reload polling, auto-POST check), and **`FULL_UPGRADE`** (upload + reboot).
