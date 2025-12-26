import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from typing import List, Dict

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:password123@postgres:5432/ml_waf_db")

Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

class RequestLog(Base):
    __tablename__ = "request_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    method = Column(String(10))
    path = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    is_malicious = Column(Boolean)
    confidence = Column(Float)
    threat_type = Column(String(50))

class Database:
    def __init__(self):
        self.engine = engine
    
    def create_tables(self):
        Base.metadata.create_all(bind=self.engine)
    
    def log_request(self, log_entry: RequestLog) -> int:
        session = SessionLocal()
        try:
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            return log_entry.id
        finally:
            session.close()
    
    def get_recent_logs(self, limit: int = 100, malicious_only: bool = False) -> List[Dict]:
        session = SessionLocal()
        try:
            query = session.query(RequestLog)
            if malicious_only:
                query = query.filter(RequestLog.is_malicious == True)
            
            logs = query.order_by(RequestLog.timestamp.desc()).limit(limit).all()
            
            return [{
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'method': log.method,
                'path': log.path,
                'ip_address': log.ip_address,
                'is_malicious': log.is_malicious,
                'confidence': log.confidence,
                'threat_type': log.threat_type
            } for log in logs]
        finally:
            session.close()
    
    def get_statistics(self) -> Dict:
        session = SessionLocal()
        try:
            total = session.query(RequestLog).count()
            malicious = session.query(RequestLog).filter(RequestLog.is_malicious == True).count()
            
            threat_query = session.query(
                RequestLog.threat_type,
                func.count(RequestLog.id).label('count')
            ).filter(
                RequestLog.is_malicious == True
            ).group_by(RequestLog.threat_type).all()
            
            top_threats = [{'type': t[0], 'count': t[1]} for t in threat_query]
            
            blocked_pct = (malicious / total * 100) if total > 0 else 0
            
            return {
                'total_requests': total,
                'malicious_requests': malicious,
                'blocked_percentage': round(blocked_pct, 2),
                'top_threats': top_threats
            }
        finally:
            session.close()