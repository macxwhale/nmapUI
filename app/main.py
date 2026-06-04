from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .db.session import engine, Base, get_db
from .models import models
from .tasks.tasks import execute_scan
from .services.nmap_service import parse_nmap_xml
from pydantic import BaseModel
from typing import List, Optional

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Nmap Management Platform")
templates = Jinja2Templates(directory="app/templates")

class TargetCreate(BaseModel):
    name: str
    ip_address: str
    description: Optional[str] = None

class ScanRequest(BaseModel):
    target_id: int
    profile_name: str

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/targets/", response_model=None)
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    db_target = models.Target(**target.dict())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@app.get("/targets/", response_model=None)
def list_targets(db: Session = Depends(get_db)):
    return db.query(models.Target).all()

@app.get("/scans/", response_model=None)
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(models.ScanJob).order_by(models.ScanJob.id.desc()).all()
    results = []
    for s in scans:
        target = db.query(models.Target).filter(models.Target.id == s.target_id).first()
        profile = db.query(models.ScanProfile).filter(models.ScanProfile.id == s.profile_id).first()
        results.append({
            "id": s.id,
            "target_ip": target.ip_address if target else "Unknown",
            "profile": profile.name if profile else "Unknown",
            "status": s.status
        })
    return results

@app.post("/scan/")
def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == request.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    profile = db.query(models.ScanProfile).filter(models.ScanProfile.name == request.profile_name).first()
    # For now, if profile doesn't exist in DB, we use it as a name if it's in SCAN_PROFILES
    from .services.nmap_service import SCAN_PROFILES
    if request.profile_name not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="Invalid scan profile")

    # Ensure profile exists in DB or create it
    if not profile:
        profile = models.ScanProfile(name=request.profile_name, command_template=" ".join(SCAN_PROFILES[request.profile_name]))
        db.add(profile)
        db.commit()
        db.refresh(profile)

    job = models.ScanJob(
        target_id=target.id,
        profile_id=profile.id,
        status="PENDING"
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    execute_scan.delay(job.id, target.ip_address, request.profile_name)

    return {"job_id": job.id, "status": "queued"}

@app.get("/scan/{job_id}")
def get_scan_status(job_id: int, db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    result = {
        "id": job.id,
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }

    if job.status == "COMPLETED" and job.result_output:
        result["parsed_results"] = parse_nmap_xml(job.result_output)
    elif job.status == "FAILED":
        result["error"] = job.result_output

    return result
