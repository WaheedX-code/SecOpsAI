# SecOpsAI

A production-grade Security Operations Center (SOC) tool that ingests raw network flow data, runs it through a hardened ML model, exposes results via a secured REST API, and fires alerts through an automated response pipeline.

---

## Prerequisites

- Docker and Docker Compose
- Python 3.11 (pyenv recommended)
- Make
- Git

---

## Quick Start

\```bash
git clone https://github.com/WaheedX-code/SecOpsAI.git
cd SecOpsAI
cp .env.example .env
nano .env
make setup
make train
make start
\```

Services:
- API: http://localhost:8000
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090
- MLflow: http://localhost:5000

---

## Environment Setup

Required values in `.env`:

\```env
POSTGRES_PASSWORD=your_strong_password
POSTGRES_USER=secopsai
POSTGRES_DB=secopsai
JWT_SECRET_KEY=your_long_random_string
ADMIN_PASSWORD=your_admin_password
ANALYST_PASSWORD=your_analyst_password
\```

---

## API Usage

Get a token:
\```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_admin_password"}'
\```

Run a detection:
\```bash
curl -X POST http://localhost:8000/detect \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"features": [0.1, 0.5, 1.2]}'
\```

View audit logs:
\```bash
curl http://localhost:8000/audit/logs \
  -H "Authorization: Bearer YOUR_TOKEN"
\```

---

## Architecture

Network Flow Data → Ingestion Pipeline → XGBoost Model → FastAPI
│
Alert Pipeline
├── VirusTotal
├── Shodan
├── Slack
├── Wazuh
└── Auto-containment
│
PostgreSQL audit log

---

## Troubleshooting

**API won't start** — check `.env` vars are set and `make train` has been run

**Grafana no data** — set Prometheus data source to `http://prometheus:9090`

**Database errors** — run migrations: `psql -h localhost -U secopsai -d secopsai -f db/migrations/001_audit_logs.sql`

---

## Developer Commands

| Command | Description |
|---|---|
| `make setup` | Install dependencies |
| `make train` | Train ML model |
| `make test` | Run test suite |
| `make start` | Start all services |
| `make stop` | Stop all services |
| `make logs` | Tail logs |
| `make status` | Show service status |

---

## Security Notes

- JWT tokens expire after 60 minutes
- Rate limiting: 60 requests/minute per IP
- All credentials via environment variables
- Model hardened against adversarial attacks using IBM ART


