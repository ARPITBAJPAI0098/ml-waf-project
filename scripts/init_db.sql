CREATE TABLE IF NOT EXISTS request_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    is_malicious BOOLEAN NOT NULL,
    confidence FLOAT NOT NULL,
    threat_type VARCHAR(50) NOT NULL
);

CREATE INDEX idx_timestamp ON request_logs(timestamp DESC);
CREATE INDEX idx_is_malicious ON request_logs(is_malicious);
CREATE INDEX idx_threat_type ON request_logs(threat_type);