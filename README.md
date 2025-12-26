# 🛡️ ML-WAF - Machine Learning Web Application Firewall

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [API Endpoints](#-api-endpoints)
- [Machine Learning](#-machine-learning)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 🎯 Overview

ML-WAF is a **production-ready Web Application Firewall** that uses **Machine Learning** to protect web applications from common cyber attacks. Unlike traditional rule-based WAFs, ML-WAF learns from traffic patterns and can detect zero-day attacks and sophisticated threats.

### What Makes ML-WAF Special?

- 🧠 **Machine Learning Detection** - Uses Isolation Forest algorithm for anomaly detection
- ⚡ **Real-time Analysis** - Analyzes requests in milliseconds
- 📊 **Beautiful Dashboard** - Modern, responsive monitoring interface
- 🐳 **Docker Ready** - Fully containerized, deploy anywhere
- 🔌 **REST API** - Easy integration with any web application
- 💾 **Persistent Storage** - PostgreSQL database for all logs and analytics

---

## ✨ Features

### 🔒 Security Features
- ✅ **SQL Injection Detection** - Identifies and blocks SQL injection attempts
- ✅ **Cross-Site Scripting (XSS) Protection** - Prevents XSS attacks
- ✅ **Path Traversal Detection** - Blocks directory traversal attempts
- ✅ **Bot & Scanner Detection** - Identifies malicious crawlers
- ✅ **Anomaly Detection** - ML-powered detection of unusual patterns

### 📊 Monitoring & Analytics
- ✅ **Real-time Dashboard** - Live monitoring with auto-refresh
- ✅ **Statistics & Metrics** - Total requests, blocked threats, block rate
- ✅ **Request Logging** - Complete audit trail in PostgreSQL
- ✅ **Threat Classification** - Categorizes attacks by type

### 🛠️ Developer Features
- ✅ **REST API** - Complete API with OpenAPI/Swagger docs
- ✅ **Docker Compose** - One-command deployment
- ✅ **Model Retraining** - Update ML model with new data
- ✅ **Extensible** - Easy to add custom detection rules

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ML-WAF System                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│                 │         │                  │         │                  │
│   Frontend      │────────▶│    Backend       │────────▶│   PostgreSQL     │
│   (Next.js)     │         │    (FastAPI)     │         │   Database       │
│   Port 3000     │         │    Port 8000     │         │   Port 5432      │
│                 │         │                  │         │                  │
└─────────────────┘         └──────────────────┘         └──────────────────┘
                                     │
                                     │
                                     ▼
                            ┌──────────────────┐
                            │                  │
                            │   ML Model       │
                            │  (Sklearn)       │
                            │  Isolation       │
                            │  Forest          │
                            │                  │
                            └──────────────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │  Feature         │
                            │  Extraction      │
                            │  (15 features)   │
                            └──────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Request Flow                              │
└─────────────────────────────────────────────────────────────┘

HTTP Request → Backend API → Feature Extraction → ML Model
                                                      │
                                              Prediction
                                                      │
                                    ┌─────────────────┴─────────────────┐
                                    ▼                                   ▼
                            ┌──────────────┐                   ┌──────────────┐
                            │  Malicious   │                   │   Benign     │
                            │   Block      │                   │   Allow      │
                            └──────────────┘                   └──────────────┘
                                    │                                   │
                                    └──────────────┬────────────────────┘
                                                   ▼
                                          Log to Database
                                                   │
                                                   ▼
                                          Display on Dashboard
```

---

## 🔧 Technology Stack

### Backend
| Technology | Purpose | Version |
|------------|---------|---------|
| **Python** | Programming Language | 3.11 |
| **FastAPI** | Web Framework | 0.104 |
| **scikit-learn** | Machine Learning | 1.3.2 |
| **PostgreSQL** | Database | 15 |
| **SQLAlchemy** | ORM | 2.0 |
| **Uvicorn** | ASGI Server | 0.24 |

### Frontend
| Technology | Purpose | Version |
|------------|---------|---------|
| **Next.js** | React Framework | 14.0 |
| **React** | UI Library | 18.2 |
| **TypeScript** | Type Safety | 5.3 |

### Infrastructure
| Technology | Purpose |
|------------|---------|
| **Docker** | Containerization |
| **Docker Compose** | Orchestration |

---

## 📁 Project Structure

```
ml-waf-project/
│
├── backend/                    # Python FastAPI Backend
│   ├── main.py                # API endpoints & application logic
│   ├── ml_model.py            # Machine Learning model (Isolation Forest)
│   ├── db.py                  # Database models & operations
│   ├── Dockerfile             # Backend container configuration
│   └── requirements.txt       # Python dependencies
│
├── frontend/                   # Next.js Frontend
│   ├── app/                   # Next.js 14 app directory
│   │   ├── layout.tsx        # Root layout component
│   │   └── page.tsx          # Dashboard page component
│   ├── Dockerfile            # Frontend container configuration
│   ├── package.json          # Node.js dependencies
│   └── next.config.js        # Next.js configuration
│
├── scripts/                    # Database initialization
│   └── init_db.sql           # PostgreSQL table creation
│
├── data/                      # Training datasets (place CSV here)
│   └── (your-dataset.csv)    # Your training data goes here
│
├── models/                    # Saved ML models
│   └── ml_waf_model.pkl      # Trained model (auto-generated)
│
├── logs/                      # Application logs (optional)
│
├── docker-compose.yml         # Docker orchestration configuration
├── .gitignore                # Git ignore rules
├── README.md                 # This file
└── LICENSE                   # MIT License
```

### File Descriptions

#### Backend Files

**`main.py`** - Core API Logic
- Defines all REST API endpoints
- Request analysis and threat detection
- Database logging
- CORS middleware configuration

**`ml_model.py`** - Machine Learning Engine
- Isolation Forest implementation
- Feature extraction (15 features per request)
- Attack pattern matching (SQL, XSS, traversal)
- Model training and persistence

**`db.py`** - Database Layer
- SQLAlchemy models
- Database CRUD operations
- Statistics and analytics queries

#### Frontend Files

**`app/page.tsx`** - Dashboard Component
- Real-time statistics display
- Request logs table
- Auto-refresh every 5 seconds
- Responsive design

**`app/layout.tsx`** - Root Layout
- Page metadata
- Global layout wrapper

---

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:
- ✅ **Docker Desktop** installed ([Download](https://www.docker.com/products/docker-desktop))
- ✅ **8GB RAM** minimum
- ✅ **Ports available:** 3000, 8000, 5432
- ✅ **Git** (optional, for cloning)

### Installation

#### Option 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ml-waf-project.git

# Navigate to project directory
cd ml-waf-project

# Start all services
docker-compose up --build
```

#### Option 2: Download ZIP

1. Download ZIP from GitHub
2. Extract to your desired location
3. Open terminal in the extracted folder
4. Run `docker-compose up --build`

### First Launch

After running `docker-compose up --build`:

1. **Wait 30-60 seconds** for all services to initialize
2. You'll see these messages indicating success:
   ```
   ml_waf_postgres  | database system is ready to accept connections
   ml_waf_backend   | Application startup complete
   ml_waf_frontend  | ready - started server on 0.0.0.0:3000
   ```

3. **Access the application:**
   - 🌐 **Dashboard:** http://localhost:3000
   - 🔌 **API Docs:** http://localhost:8000/docs
   - ✅ **Health Check:** http://localhost:8000

---

## 💻 Usage

### Web Dashboard

Navigate to `http://localhost:3000` to see:

- **Total Requests** - Number of analyzed requests
- **Threats Blocked** - Number of malicious requests blocked
- **Block Rate** - Percentage of blocked traffic
- **Recent Activity** - Live table of analyzed requests with threat classification

The dashboard auto-refreshes every 5 seconds!

### API Usage

#### Analyze a Request

```bash
POST http://localhost:8000/api/analyze
```

**Request Body:**
```json
{
  "method": "GET",
  "path": "/api/users?id=1",
  "headers": {
    "User-Agent": "Mozilla/5.0"
  },
  "body": "",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0"
}
```

**Response:**
```json
{
  "is_malicious": false,
  "confidence": 0.95,
  "threat_type": "benign",
  "timestamp": "2025-12-26T10:30:00",
  "request_id": 1
}
```

---

## 🔌 API Endpoints

### Core Endpoints

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/` | GET | Health check | Status info |
| `/api/analyze` | POST | Analyze HTTP request | Threat analysis |
| `/api/stats` | GET | Get statistics | Total/blocked requests |
| `/api/logs` | GET | Get request logs | Recent activity |
| `/api/retrain` | POST | Retrain ML model | Training status |
| `/api/model/info` | GET | Model information | Model details |
| `/docs` | GET | API documentation | Swagger UI |

### Detailed API Documentation

Visit `http://localhost:8000/docs` for interactive API documentation with:
- Full endpoint descriptions
- Request/response schemas
- Try-it-now functionality
- Example requests

---

## 🧠 Machine Learning

### Algorithm: Isolation Forest

ML-WAF uses **Isolation Forest**, an unsupervised learning algorithm for anomaly detection.

**Why Isolation Forest?**
- ✅ Effective for outlier detection
- ✅ Fast training and prediction
- ✅ Works well with imbalanced data
- ✅ No need for labeled training data (initially)

### Feature Extraction

The model extracts **15 features** from each HTTP request:

| # | Feature | Description |
|---|---------|-------------|
| 1 | Path Length | Length of URL path |
| 2 | Path Segments | Number of `/` in path |
| 3 | Query Length | Length of query string |
| 4 | Parameter Count | Number of URL parameters |
| 5 | Special Characters | Count of unusual characters |
| 6 | SQL Injection Score | Pattern matching for SQL attacks |
| 7 | XSS Score | Pattern matching for XSS attacks |
| 8 | Path Traversal Score | Pattern matching for directory traversal |
| 9 | Body Length | Size of request body |
| 10 | Header Count | Number of HTTP headers |
| 11 | HTTP Method | GET=0, POST=1, PUT=2, DELETE=3 |
| 12 | Suspicious User Agent | Bot/scanner detection |
| 13 | Path Entropy | Randomness measure |
| 14 | Numeric Ratio | Ratio of digits in path |
| 15 | File Extension | Presence of file extension |

### Detection Types

1. **SQL Injection** - Detects:
   - `UNION SELECT`
   - `OR 1=1`
   - `'; DROP TABLE`
   - Comment injections (`--`, `/**/`)

2. **Cross-Site Scripting (XSS)** - Detects:
   - `<script>` tags
   - `javascript:` protocol
   - Event handlers (`onerror`, `onload`)
   - `<iframe>` injections

3. **Path Traversal** - Detects:
   - `../` sequences
   - `/etc/passwd` access
   - Windows path traversal (`c:\windows`)

4. **Anomaly Detection** - Catches:
   - Unusual request patterns
   - Zero-day attacks
   - Sophisticated threats

### Model Training

The model can be trained with custom datasets:

1. **Place your CSV** in the `data/` folder
2. **Run training:** `docker exec -it ml_waf_backend python train_model.py`
3. **Model saved** to `models/ml_waf_model.pkl`
4. **Automatic reload** on next request

---

## 🧪 Testing

### PowerShell Commands (Windows)

**Test 1: Normal Request**
```powershell
$body = @{
    method = "GET"
    path = "/api/users"
    headers = @{}
    body = ""
    ip_address = "192.168.1.1"
    user_agent = "Chrome"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/analyze" -Method Post -Body $body -ContentType "application/json"
```

**Expected Output:**
```json
{
  "is_malicious": false,
  "threat_type": "benign"
}
```

**Test 2: SQL Injection Attack**
```powershell
$body = @{
    method = "GET"
    path = "/login?id=1' OR '1'='1--"
    headers = @{}
    body = ""
    ip_address = "192.168.1.100"
    user_agent = "Attacker"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/analyze" -Method Post -Body $body -ContentType "application/json"
```

**Expected Output:**
```json
{
  "is_malicious": true,
  "threat_type": "sql_injection",
  "confidence": 0.9
}
```

**Test 3: XSS Attack**
```powershell
$body = @{
    method = "POST"
    path = "/comment"
    headers = @{}
    body = "<script>alert('XSS')</script>"
    ip_address = "192.168.1.200"
    user_agent = "Hacker"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/analyze" -Method Post -Body $body -ContentType "application/json"
```

**Expected Output:**
```json
{
  "is_malicious": true,
  "threat_type": "xss",
  "confidence": 0.85
}
```

### Bash/Linux Commands

**Test Normal Request:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users",
    "headers": {},
    "body": "",
    "ip_address": "192.168.1.1",
    "user_agent": "Chrome"
  }'
```

**Check Statistics:**
```bash
curl http://localhost:8000/api/stats
```

### After Testing

Visit `http://localhost:3000` and you should see:
- Total Requests: 3
- Threats Blocked: 2
- Block Rate: 66.67%
- Recent Activity table with all requests

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Commit your changes:**
   ```bash
   git commit -m "Add: amazing feature description"
   ```
5. **Push to the branch:**
   ```bash
   git push origin feature/amazing-feature
   ```
6. **Open a Pull Request**

### Contribution Ideas



- 🔒 **Security Features**
  - Add CSRF detection
  - Implement XXE (XML External Entity) detection
  - Add SSRF (Server-Side Request Forgery) detection
  - Rate limiting implementation
  - IP whitelisting/blacklisting

- 🧠 **Machine Learning**
  - Implement deep learning models (LSTM, Transformers)
  - Add ensemble methods
  - Improve feature engineering
  - Add model explainability (SHAP values)

- 📊 **Dashboard & Monitoring**
  - Add charts and graphs (time series)
  - Implement filtering and search
  - Export functionality (PDF, CSV)
  - Dark/light mode toggle
  - Mobile responsive improvements

- 🛠️ **DevOps & Integration**
  - Kubernetes deployment configs
  - CI/CD pipelines
  - Integration with popular frameworks (Django, Flask, Express)
  - Cloud deployment guides (AWS, Azure, GCP)
  - Performance benchmarks

- 📝 **Documentation**
  - Video tutorials
  - Architecture diagrams
  - Deployment guides
  - Security best practices
  - Internationalization

### Code Style

- **Python:** Follow PEP 8
- **TypeScript:** Use ESLint configuration
- **Commits:** Use conventional commits format
- **Documentation:** Update README for new features

---

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Stop all containers
docker-compose down

# Remove all volumes
docker-compose down -v

# Restart
docker-compose up --build
```

#### Database Connection Error
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Restart database
docker-compose restart postgres

# Check logs
docker logs ml_waf_postgres
```

#### Frontend Can't Connect to Backend
1. Verify backend is running: `curl http://localhost:8000`
2. Check browser console for errors
3. Verify `NEXT_PUBLIC_API_URL` in docker-compose.yml

#### Model Not Loading
```bash
# Access backend container
docker exec -it ml_waf_backend bash

# Check if model exists
ls -la /app/models/

# Retrain model
python -c "from ml_model import MLWAFModel; m = MLWAFModel(); m._train_with_sample_data()"
```

### View Logs

```bash
# Backend logs
docker logs ml_waf_backend -f

# Frontend logs
docker logs ml_waf_frontend -f

# Database logs
docker logs ml_waf_postgres -f

# All logs
docker-compose logs -f
```

### Clean Restart

```bash
# Stop everything
docker-compose down -v

# Remove old images
docker rmi ml-waf-project-backend ml-waf-project-frontend

# Rebuild
docker-compose up --build
```

---

