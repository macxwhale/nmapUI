#!/bin/bash
/home/maxx/nmapUI/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 &
/home/maxx/nmapUI/venv/bin/celery -A app.core.celery_app worker --loglevel=info &
wait
