from ..core.celery_app import celery_app
from ..services.nmap_service import run_nmap
from ..db.session import SessionLocal
from ..models.models import ScanJob
from sqlalchemy.sql import func
import datetime

@celery_app.task(name="app.tasks.execute_scan")
def execute_scan(job_id, target, profile):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            return "Job not found"
        
        job.status = "RUNNING"
        job.started_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        output = run_nmap(target, profile)

        job.status = "COMPLETED"
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        job.result_output = output
        db.commit()

        return "completed"
    except Exception as e:
        if job:
            job.status = "FAILED"
            job.result_output = str(e)
            db.commit()
        return f"failed: {str(e)}"
    finally:
        db.close()
