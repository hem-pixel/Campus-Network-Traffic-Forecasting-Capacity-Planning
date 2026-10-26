from __future__ import annotations

import csv
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from io import StringIO
from uuid import uuid4

import pandas as pd
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .core import capacity, forecast, token_for, validate_csv, validate_device_csv
from .models import Audit, Base, Dataset, DeviceImport, Session, User, engine

Base.metadata.create_all(engine)
app = FastAPI(title="Campus Network Capacity Planner", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    # Vite may be opened through either hostname; browsers treat these as
    # different origins even though both point to this same local machine.
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    ],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
ph = PasswordHasher()
attempts: dict[str, list[float]] = {}

def db():
    with Session() as s: yield s

def audit(s: DBSession, actor: str, action: str, detail: str = ""):
    s.add(Audit(actor=actor, action=action, detail=detail[:2000])); s.commit()

def principal(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    import jwt
    try:
        payload = jwt.decode(authorization[7:], os.getenv("JWT_SECRET", "local-development-secret-change-me"), algorithms=["HS256"])
        return {"email": payload["sub"], "role": payload["role"]}
    except Exception as exc: raise HTTPException(401, "Session expired; sign in again") from exc

def require(*roles):
    def guard(user=Depends(principal)):
        if roles and user["role"] not in roles: raise HTTPException(403, "Your role cannot perform this action")
        return user
    return guard

class Credentials(BaseModel):
    email: EmailStr
    password: str
    bootstrap_token: str | None = None

class CapacityInput(BaseModel):
    capacity_mbps: float
    headroom: float
    forecast_mbps: list[float]
    start_timestamp: datetime
    interval_minutes: int = 60

class RoleInput(BaseModel):
    role: str

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.post("/api/auth/signup")
def signup(body: Credentials, s: DBSession = Depends(db)):
    if len(body.password) < 12: raise HTTPException(422, "Password must contain at least 12 characters")
    if s.scalar(select(User).where(User.email == body.email.lower())): raise HTTPException(409, "Account already exists")
    # Public signup always creates Viewer; an administrator must assign elevated roles.
    bootstrap = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    bootstrap_secret = os.getenv("BOOTSTRAP_ADMIN_SECRET", "")
    is_bootstrap = bool(bootstrap and body.email.lower() == bootstrap)
    if is_bootstrap and (not bootstrap_secret or not body.bootstrap_token or not secrets.compare_digest(body.bootstrap_token, bootstrap_secret)):
        raise HTTPException(403, "Administrator bootstrap credentials are required for this address")
    user = User(email=body.email.lower(), password_hash=ph.hash(body.password), role="Administrator" if is_bootstrap else "Viewer")
    s.add(user); s.commit(); audit(s, user.email, "signup")
    return {"access_token": token_for(user.email, user.role), "token_type": "bearer", "role": user.role}

@app.post("/api/auth/signin")
def signin(body: Credentials, s: DBSession = Depends(db)):
    now = time.time(); key = body.email.lower(); attempts[key] = [t for t in attempts.get(key, []) if now - t < 900]
    if len(attempts[key]) >= 8: raise HTTPException(429, "Too many sign-in attempts. Try again later.")
    user = s.scalar(select(User).where(User.email == key))
    if not user:
        attempts[key].append(now); raise HTTPException(401, "Email or password is incorrect")
    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc): raise HTTPException(429, "Account temporarily locked")
    try: valid = ph.verify(user.password_hash, body.password)
    except Exception: valid = False
    if not valid:
        attempts[key].append(now); user.failed_logins += 1
        if user.failed_logins >= 8: user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + pd.Timedelta(minutes=15)
        s.commit(); raise HTTPException(401, "Email or password is incorrect")
    user.failed_logins = 0; user.locked_until = None; s.commit(); audit(s, user.email, "signin")
    return {"access_token": token_for(user.email, user.role), "token_type": "bearer", "role": user.role}

@app.post("/api/auth/forgot-password")
def forgot(body: dict, s: DBSession = Depends(db)):
    # Delivery is intentionally disabled until a production mail transport is configured.
    user = s.scalar(select(User).where(User.email == str(body.get("email", "")).lower()))
    if user: audit(s, user.email, "password_reset_requested")
    return {"message": "Password reset delivery is not configured. Contact an administrator."}

@app.get("/api/me")
def me(user=Depends(principal)):
    return user

@app.post("/api/datasets")
async def upload(file: UploadFile = File(...), user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    if not file.filename or not file.filename.lower().endswith(".csv"): raise HTTPException(415, "Upload an approved CSV file")
    content = await file.read(20_000_001)
    if len(content) > 20_000_000: raise HTTPException(413, "File exceeds 20 MB limit")
    frame, report = validate_csv(content)
    checksum = hashlib.sha256(content).hexdigest(); version = "ds-" + checksum[:12]
    rows = json.loads(frame.to_json(orient="records", date_format="iso"))
    dataset = Dataset(id=str(uuid4()), version=version, checksum=checksum, report_json=json.dumps(report), rows_json=json.dumps(rows), created_by=user["email"])
    s.add(dataset); s.commit(); audit(s, user["email"], "upload", json.dumps({"dataset_version": version, "validation": report}))
    return {"dataset_version": version, "validation": report}

@app.delete("/api/datasets/{dataset_id}")
def delete_dataset(dataset_id: str, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    d = s.get(Dataset, dataset_id) or s.scalar(select(Dataset).where(Dataset.version == dataset_id))
    if not d: raise HTTPException(404, "Dataset version not found")
    version = d.version
    s.delete(d); s.commit()
    audit(s, user["email"], "delete_dataset", f"dataset_version={version}")
    return {"deleted_dataset_version": version}

def get_dataset(dataset_id: str, s: DBSession):
    d = s.get(Dataset, dataset_id) or s.scalar(select(Dataset).where(Dataset.version == dataset_id))
    if not d: raise HTTPException(404, "Dataset version not found")
    return d, pd.DataFrame(json.loads(d.rows_json))

@app.get("/api/datasets")
def list_datasets(user=Depends(principal), s: DBSession = Depends(db)):
    return [{"id": d.id, "version": d.version, "created_at": d.created_at.isoformat(), "created_by": d.created_by, "validation": json.loads(d.report_json)} for d in s.scalars(select(Dataset).order_by(Dataset.created_at.desc())).all()]

@app.get("/api/history/{dataset_id}")
def history(dataset_id: str, segment_id: str | None = None, user=Depends(principal), s: DBSession = Depends(db)):
    d, frame = get_dataset(dataset_id, s)
    if segment_id: frame = frame[frame.segment_id == segment_id]
    return {"dataset_version": d.version, "points": frame.to_dict(orient="records"), "units": "Mbps", "date_range": json.loads(d.report_json)["date_range"]}

@app.post("/api/forecast/{dataset_id}")
def run_forecast(dataset_id: str, horizon: int = 24, segment_id: str | None = None, user=Depends(principal), s: DBSession = Depends(db)):
    d, frame = get_dataset(dataset_id, s)
    if segment_id: frame = frame[frame.segment_id == segment_id]
    series = frame.groupby("timestamp", as_index=False).traffic_mbps.sum().sort_values("timestamp")
    try: result = forecast(series.traffic_mbps.tolist(), min(max(horizon, 1), 168))
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    return {"dataset_version": d.version, "date_range": json.loads(d.report_json)["date_range"], "units": "Mbps", **result}

@app.post("/api/capacity")
def capacity_api(body: CapacityInput, user=Depends(require("Administrator", "Planner"))):
    points = [{"timestamp": (pd.Timestamp(body.start_timestamp) + pd.Timedelta(minutes=body.interval_minutes*i)).isoformat(), "traffic_mbps": v} for i, v in enumerate(body.forecast_mbps)]
    try: return capacity(points, body.capacity_mbps, body.headroom)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc

@app.post("/api/devices/import")
async def import_devices(file: UploadFile = File(...), user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    content = await file.read(10_000_001)
    if len(content) > 10_000_000: raise HTTPException(413, "Controller export exceeds 10 MB limit")
    frame, report = validate_device_csv(content)
    rows = json.loads(frame.to_json(orient="records", date_format="iso"))
    entry = DeviceImport(id=str(uuid4()), report_json=json.dumps(report), rows_json=json.dumps(rows), created_by=user["email"])
    s.add(entry); s.commit(); audit(s, user["email"], "device_aggregate_import", json.dumps({"rows": report["rows_accepted"], "source": "approved controller export"}))
    return {"import_id": entry.id, "source": "approved controller export", "validation": report}

@app.get("/api/devices")
def devices(user=Depends(require("Administrator", "Planner", "Viewer")), s: DBSession = Depends(db)):
    latest = s.scalar(select(DeviceImport).order_by(DeviceImport.created_at.desc()))
    audit(s, user["email"], "view_device_aggregate", "aggregate controller export data")
    if not latest: return {"status": "to be recorded", "source": "approved controller export", "message": "No aggregate controller export has been uploaded."}
    frame = pd.DataFrame(json.loads(latest.rows_json)); frame["timestamp"] = pd.to_datetime(frame.timestamp, utc=True)
    latest_time = frame.timestamp.max(); now = pd.Timestamp.now(tz="UTC"); stale = now - latest_time > pd.Timedelta(hours=24)
    grouped = []
    for name, g in frame.groupby("ap_or_building"):
        g = g.sort_values("timestamp")
        g["traffic_per_device_mbps"] = g.apply(lambda r: float(r.traffic_mbps) / float(r.device_count) if r.device_count else None, axis=1)
        grouped.append({"ap_or_building": name, "peak_connected_count": int(g.device_count.max()),
                        "average_traffic_per_device_mbps": float(g.traffic_per_device_mbps.dropna().mean()) if g.traffic_per_device_mbps.notna().any() else None,
                        "points": [{"timestamp": r.timestamp.isoformat(), "device_count": int(r.device_count), "traffic_mbps": float(r.traffic_mbps), "traffic_per_device_mbps": r.traffic_per_device_mbps} for r in g.itertuples()]})
    current = frame[frame.timestamp == latest_time]
    return {"status": "stale" if stale else "current", "source": latest.source, "measurement_time": latest_time.isoformat(),
            "freshness_limit_hours": 24, "freshness_warning": "Measurement is older than the 24-hour default freshness limit." if stale else None,
            "dataset_version": latest.id, "date_range": json.loads(latest.report_json)["date_range"], "units": {"traffic": "Mbps", "traffic_per_device": "Mbps/device"},
            "current_load_by_ap": [{"ap_or_building": r.ap_or_building, "traffic_mbps": float(r.traffic_mbps), "connected_devices": int(r.device_count)} for r in current.itertuples()],
            "aggregates": grouped}

@app.get("/api/audit")
def audit_log(user=Depends(require("Administrator")), s: DBSession = Depends(db)):
    return [{"actor": a.actor, "action": a.action, "detail": a.detail, "created_at": a.created_at.isoformat()} for a in s.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(500)).all()]

@app.get("/api/users")
def users(user=Depends(require("Administrator")), s: DBSession = Depends(db)):
    return [{"email": u.email, "role": u.role} for u in s.scalars(select(User).order_by(User.email)).all()]

@app.patch("/api/users/{email}/role")
def update_role(email: str, body: RoleInput, user=Depends(require("Administrator")), s: DBSession = Depends(db)):
    if body.role not in {"Administrator", "Planner", "Viewer"}: raise HTTPException(422, "Role must be Administrator, Planner, or Viewer")
    target = s.scalar(select(User).where(User.email == email.lower()))
    if not target: raise HTTPException(404, "User not found")
    if target.role == "Administrator" and body.role != "Administrator" and len(s.scalars(select(User).where(User.role == "Administrator")).all()) <= 1:
        raise HTTPException(409, "The last administrator cannot be demoted")
    prior = target.role; target.role = body.role; s.commit()
    audit(s, user["email"], "user_role_changed", json.dumps({"target": target.email, "from": prior, "to": body.role}))
    return {"email": target.email, "role": target.role}

@app.get("/api/exports/{dataset_id}/summary.txt", response_class=PlainTextResponse)
def summary_export(dataset_id: str, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    d = s.get(Dataset, dataset_id) or s.scalar(select(Dataset).where(Dataset.version == dataset_id))
    if not d: raise HTTPException(404, "Dataset version not found")
    report = json.loads(d.report_json); content = f"Campus traffic planning summary\nDataset version: {d.version}\nConfiguration: forecast selection rule v1; capacity: to be configured\nDate range: {report['date_range']}\nLimitations: Mbps values are decision support only; capacity estimates depend on configured headroom.\n"
    audit(s, user["email"], "export", f"summary.txt dataset={d.version}")
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="summary-{d.version}.txt"'})

@app.get("/api/exports/{dataset_id}/forecast.csv")
def forecast_export(dataset_id: str, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    d, frame = get_dataset(dataset_id, s); series = frame.groupby("timestamp", as_index=False).traffic_mbps.sum().sort_values("timestamp")
    result = forecast(series.traffic_mbps.tolist())
    output = StringIO(); writer = csv.writer(output); writer.writerow(["dataset_version", d.version]); writer.writerow(["configuration", "selection rule v1; horizon=24; units=Mbps"]); writer.writerow(["limitations", "Decision support estimate only; no guarantee"]); writer.writerow(["step", "forecast_mbps"])
    writer.writerows(enumerate(result["forecast_mbps"], start=1)); audit(s, user["email"], "export", f"forecast.csv dataset={d.version}")
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="forecast-{d.version}.csv"'})

@app.get("/api/exports/{dataset_id}/evaluation.csv")
def evaluation_export(dataset_id: str, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    d, frame = get_dataset(dataset_id, s); series = frame.groupby("timestamp", as_index=False).traffic_mbps.sum().sort_values("timestamp")
    result = forecast(series.traffic_mbps.tolist()); output = StringIO(); writer = csv.writer(output)
    writer.writerow(["dataset_version", d.version]); writer.writerow(["configuration", "chronological 70/15/15; selection rule v1; units=Mbps"]); writer.writerow(["date_range", *json.loads(d.report_json)["date_range"]]); writer.writerow(["limitations", "Decision support only; holdout results do not guarantee future accuracy"])
    writer.writerow(["model", "validation_mae_mbps", "validation_rmse_mbps", "holdout_mae_mbps", "holdout_rmse_mbps", "recommended"])
    for name, metrics in result["evaluations"].items(): writer.writerow([name, metrics["validation"]["mae_mbps"], metrics["validation"]["rmse_mbps"], metrics["holdout"]["mae_mbps"], metrics["holdout"]["rmse_mbps"], name == result["selected_model"]])
    audit(s, user["email"], "export", f"evaluation.csv dataset={d.version}")
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="evaluation-{d.version}.csv"'})

@app.get("/api/exports/{dataset_id}/capacity.csv")
def capacity_export(dataset_id: str, capacity_mbps: float, headroom: float, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    d, frame = get_dataset(dataset_id, s); series = frame.groupby("timestamp", as_index=False).traffic_mbps.sum().sort_values("timestamp")
    result = forecast(series.traffic_mbps.tolist()); start = pd.Timestamp(series.timestamp.max()) + pd.Timedelta(hours=1)
    points = [{"timestamp": (start + pd.Timedelta(hours=i)).isoformat(), "traffic_mbps": v} for i,v in enumerate(result["forecast_mbps"])]
    try: plan = capacity(points, capacity_mbps, headroom)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    output = StringIO(); writer = csv.writer(output); writer.writerow(["dataset_version", d.version]); writer.writerow(["configuration", f"capacity_mbps={capacity_mbps}; headroom={headroom}; threshold_mbps={plan['threshold_mbps']}; date_range={json.loads(d.report_json)['date_range']}"]); writer.writerow(["limitations", plan["assumption"]]); writer.writerow(["risk_start", "risk_end", "peak_mbps", "duration_hours", "required_capacity_mbps_estimate"])
    writer.writerows([[x["start"],x["end"],x["peak_mbps"],x["duration_hours"],x["required_capacity_mbps_estimate"]] for x in plan["risk_periods"]])
    audit(s, user["email"], "export", f"capacity.csv dataset={d.version}; capacity={capacity_mbps}; headroom={headroom}")
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="capacity-{d.version}.csv"'})

@app.get("/api/exports/{dataset_id}/planning-summary.pdf")
def pdf_export(dataset_id: str, user=Depends(require("Administrator", "Planner")), s: DBSession = Depends(db)):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from io import BytesIO
    d = s.get(Dataset, dataset_id) or s.scalar(select(Dataset).where(Dataset.version == dataset_id))
    if not d: raise HTTPException(404, "Dataset version not found")
    report = json.loads(d.report_json); stream = BytesIO(); pdf = canvas.Canvas(stream, pagesize=letter)
    pdf.setTitle("Campus Network Planning Summary"); pdf.setFont("Helvetica-Bold", 18); pdf.drawString(54, 740, "Campus network planning summary")
    pdf.setFont("Helvetica", 11); lines = [f"Dataset version: {d.version}", f"Date range: {report['date_range']}", "Configuration: no capacity configuration attached", "", "Limitations", "Decision support only. Forecasts and capacity estimates are approximate", "and do not guarantee congestion prevention or savings. Review with a", "qualified network administrator before taking action."]
    y = 706
    for line in lines: pdf.drawString(54, y, line); y -= 19
    pdf.setFont("Helvetica-Oblique", 9); pdf.drawString(54, 500, "Generated from approved uploaded traffic only. No live equipment connection.")
    pdf.save(); audit(s, user["email"], "export", f"planning-summary.pdf dataset={d.version}")
    return StreamingResponse(iter([stream.getvalue()]), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="planning-summary-{d.version}.pdf"'})

