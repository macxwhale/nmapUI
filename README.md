# Nmap Management Platform

A centralized Nmap scanning platform built with FastAPI, Celery, Redis, and PostgreSQL.

## Features
- Manage scan targets
- Run predefined Nmap scans (Quick, Service, OS, Deep, Vuln)
- Background processing of scans
- Structured storage of scan results (XML parsing)

## Setup and Running

### Using Docker Compose (Recommended)
1. Ensure Docker and Docker Compose are installed.
2. Run:
   ```bash
   docker compose up --build
   ```
3. The API will be available at `http://localhost:8000`.
4. Swagger UI documentation: `http://localhost:8000/docs`.

### Running Locally (Manual)
1. Install system dependencies: `nmap`, `redis-server`, `postgresql`.
2. Create a virtual environment and install requirements:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Set up PostgreSQL:
   ```sql
   CREATE USER nmapuser WITH PASSWORD 'nmap-pass';
   CREATE DATABASE nmapdb OWNER nmapuser;
   ```
4. Start Redis and PostgreSQL services.
5. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```
6. Start the Celery worker (in a separate terminal):
   ```bash
   celery -A app.core.celery_app worker --loglevel=info
   ```

## API Usage Example

### 1. Add a Target
```bash
curl -X POST "http://localhost:8000/targets/" -H "Content-Type: application/json" -d '{"name": "Localhost", "ip_address": "127.0.0.1", "description": "Local machine"}'
```

### 2. Start a Scan
```bash
curl -X POST "http://localhost:8000/scan/" -H "Content-Type: application/json" -d '{"target_id": 1, "profile_name": "quick"}'
```

### 3. Check Scan Status and Results
```bash
curl -X GET "http://localhost:8000/scan/1"
```
