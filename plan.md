
# Nmap Management Platform (Option B - FastAPI + Celery Architecture)

## Overview

This project is a centralized Nmap scanning platform built using a **FastAPI + background worker architecture (Option B)**.

It allows users to:
- Manage scan targets
- Run predefined Nmap scans
- Schedule automated scans
- View scan results
- Generate reports

It does **NOT use SSH**. All scans are executed locally by a worker service.

---

# Recommended Tech Stack

## Backend API
- FastAPI (preferred) OR Flask

## Background Processing
- Celery

## Message Broker
- Redis

## Database
- PostgreSQL

## Scanner Engine
- Nmap (installed on Debian 13 server)

## Optional Frontend
- Bootstrap 5 / HTML templates OR React

---

# System Architecture

```text
Browser UI
   │
   ▼
FastAPI Backend
   │
   ├── PostgreSQL (data storage)
   ├── Redis (task queue)
   ▼
Celery Worker
   │
   ▼
Nmap Execution (local on Debian 13)
   │
   ▼
XML Parsing → Structured Storage

nmap-platform/
│
├── app/
│   ├── main.py
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── services/
│   ├── tasks/
│   ├── db/
│
├── worker/
│   └── celery_worker.py
│
├── requirements.txt
├── docker-compose.yml
└── README.md

pip install fastapi uvicorn sqlalchemy psycopg2 redis celery python-nmap

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    password_hash TEXT,
    role VARCHAR(50),
    created_at TIMESTAMP
);CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    ip_address VARCHAR(50),
    description TEXT,
    created_at TIMESTAMP
);CREATE TABLE scan_profiles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    command_template TEXT
);CREATE TABLE scan_jobs (
    id SERIAL PRIMARY KEY,
    target_id INT,
    profile_id INT,
    status VARCHAR(50),
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);CREATE TABLE scan_jobs (
    id SERIAL PRIMARY KEY,
    target_id INT,
    profile_id INT,
    status VARCHAR(50),
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);SCAN_PROFILES = {
    "quick": ["nmap", "-F"],
    "service": ["nmap", "-sV"],
    "os": ["nmap", "-O"],
    "deep": ["nmap", "-A"],
    "vuln": ["nmap", "--script", "vuln"]
}import subprocess

def run_nmap(target, profile):
    cmd = SCAN_PROFILES[profile] + [target]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    return result.stdoutfrom celery import Celery

celery = Celery(
    "scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1"
)@celery.task
def execute_scan(job_id, target, profile):
    output = run_nmap(target, profile)

    save_scan_result(job_id, output)

    return "completed"@celery.task
def execute_scan(job_id, target, profile):
    output = run_nmap(target, profile)

    save_scan_result(job_id, output)

    return "completed"@router.post("/scan")
def start_scan(target: str, profile: str):

    job = create_scan_job(target, profile)

    execute_scan.delay(job.id, target, profile)

    return {
        "job_id": job.id,
        "status": "queued"
    }@router.get("/scan/{job_id}")
def get_scan_status(job_id: int):
    return fetch_job_status(job_id)nmap -A 192.168.1.1 -oX result.xmlimport xml.etree.ElementTree as ET

def parse_nmap(xml_data):
    root = ET.fromstring(xml_data)

    results = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")

        ports = []

        for port in host.findall(".//port"):
            ports.append({
                "port": port.get("portid"),
                "state": port.find("state").get("state")
            })

        results.append({
            "ip": ip,
            "ports": ports
        })

    return resultsPhase 8: Scan Lifecycle
Status Flow
PENDING → RUNNING → COMPLETED → FAILEDPhase 8: Scan Lifecycle
Status Flow
PENDING → RUNNING → COMPLETED → FAILEDExecution Flow
User requests scan
        │
        ▼
API creates job
        │
        ▼
Job pushed to Redis queue
        │
        ▼
Celery worker executes job
        │
        ▼
Nmap runs locally
        │
        ▼
Results stored in database
        │
        ▼
Frontend fetches resultsPhase 9: UI Design
9.1 Dashboard
Total targets
Active scans
Completed scans
Vulnerabilities summary
9.2 Targets Page
Add target
Edit target
Delete target
Start scan
9.3 Scan Page
Target: [ 192.168.1.1 ]
Scan Type: [ Deep Scan ▼ ]

[ Start Scan ]
9.4 Results Page
Host: 192.168.1.1

Ports:
22   OPEN   SSH
80   OPEN   HTTP
443  OPEN   HTTPS
Phase 10: Scheduling (Optional Upgrade)
celery.conf.beat_schedule = {
    "daily-scan": {
        "task": "execute_scan",
        "schedule": 86400
    }
}
Phase 11: Security Rules
Allowed
Predefined scan profiles only
Whitelisted IP ranges
Controlled execution via API
Not Allowed
Raw shell commands
Arbitrary Nmap flags from user input
SSH command execution from UI
Phase 12: Reporting
Report Types
PDF reports
CSV exports
JSON API responses
Example Report Output
Host: 192.168.1.1
Open Ports: 3
Services: SSH, HTTP, HTTPS
Risk Level: Medium
Final System Architecture Summary
FastAPI Application
   │
   ├── PostgreSQL (persistent storage)
   ├── Redis (job queue)
   ├── Celery Worker (task execution)
   └── Nmap Engine (local scanning)
