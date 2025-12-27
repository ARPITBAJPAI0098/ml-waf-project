from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import datetime
import logging
from rate_limiter import RateLimiter

from ml_model import MLWAFModel
from db import Database, RequestLog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ML-WAF API",
    description="Machine Learning Web Application Firewall",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ml_model = MLWAFModel()
db = Database()
rate_limiter = RateLimiter()

class HTTPRequest(BaseModel):
    method: str
    path: str
    headers: dict
    body: Optional[str] = ""
    ip_address: str
    user_agent: Optional[str] = ""

class PredictionResponse(BaseModel):
    is_malicious: bool
    confidence: float
    threat_type: str
    timestamp: str
    request_id: int

class StatsResponse(BaseModel):
    total_requests: int
    malicious_requests: int
    blocked_percentage: float
    top_threats: List[dict]

@app.on_event("startup")
async def startup_event():
    try:
        db.create_tables()
        ml_model.load_or_train()
        logger.info("ML-WAF initialized successfully")
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "ML-WAF",
        "version": "1.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.post("/api/analyze", response_model=PredictionResponse)
async def analyze_request(request: HTTPRequest, background_tasks: BackgroundTasks):
    try:
        #  STEP 1: Rate limiting
        rate_info = rate_limiter.check_rate(
            source_ip=request.ip_address,
            path=request.path
        )

        if rate_info["is_rate_limited"]:
            log_entry = RequestLog(
                timestamp=datetime.datetime.utcnow(),
                method=request.method,
                path=request.path,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
                is_malicious=True,
                confidence=1.0,
                threat_type="rate_limit_exceeded"
            )
            request_id = db.log_request(log_entry)

            return PredictionResponse(
                is_malicious=True,
                confidence=1.0,
                threat_type="rate_limit_exceeded",
                timestamp=datetime.datetime.utcnow().isoformat(),
                request_id=request_id
            )

        # 🔹 STEP 2: Build traffic object
        traffic = {
            "method": request.method,
            "path": request.path,
            "headers": request.headers,
            "body": request.body,
            "ip_address": request.ip_address,
            "user_agent": request.user_agent
        }

        # 🔹 STEP 3: ML prediction (FeatureExtractor used internally)
        is_malicious, confidence, threat_type = ml_model.predict(traffic)

        # 🔹 STEP 4: Log request
        log_entry = RequestLog(
            timestamp=datetime.datetime.utcnow(),
            method=request.method,
            path=request.path,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            is_malicious=is_malicious,
            confidence=confidence,
            threat_type=threat_type
        )

        request_id = db.log_request(log_entry)

        # 🔹 STEP 5: Response
        return PredictionResponse(
            is_malicious=is_malicious,
            confidence=round(confidence, 4),
            threat_type=threat_type,
            timestamp=datetime.datetime.utcnow().isoformat(),
            request_id=request_id
        )

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats", response_model=StatsResponse)
async def get_statistics():
    try:
        stats = db.get_statistics()
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(limit: int = 100, malicious_only: bool = False):
    try:
        logs = db.get_recent_logs(limit=limit, malicious_only=malicious_only)
        return {"logs": logs, "count": len(logs)}
    except Exception as e:
        logger.error(f"Logs error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/retrain")
async def retrain_model(background_tasks: BackgroundTasks):
    try:
        background_tasks.add_task(ml_model.retrain)
        return {"status": "retraining_started", "message": "Model retraining initiated"}
    except Exception as e:
        logger.error(f"Retrain error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/model/info")
async def model_info():
    return {
        "model_type": "Isolation Forest",
        "features": ml_model.feature_count,
        "trained": ml_model.is_trained,
        "last_trained": ml_model.last_trained_time
    }