.PHONY: help setup train test start stop restart logs status api clean

# ─── Config ───────────────────────────────────────────────────────────────────
VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# ─── Default ──────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "SecOpsAI — Available Commands"
	@echo "────────────────────────────────────────"
	@echo "  make setup      Install dependencies and prepare environment"
	@echo "  make train      Train baseline and ML detection model"
	@echo "  make test       Run full test suite"
	@echo "  make start      Start all infrastructure + API"
	@echo "  make stop       Stop all services"
	@echo "  make restart    Restart all services"
	@echo "  make logs       Tail logs from all services"
	@echo "  make status     Show running service status"
	@echo "  make api        Start FastAPI server only"
	@echo "  make clean      Remove model artifacts and cache"
	@echo ""

# ─── Setup ────────────────────────────────────────────────────────────────────
setup:
	@echo "[*] Checking .env..."
	@test -f .env || (cp .env.example .env && echo "[!] .env created from .env.example — fill in your secrets")
	@echo "[*] Installing dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "[*] Creating data directories..."
	mkdir -p data/raw/cicids2017 data/models detection/models
	@echo "[✓] Setup complete"

# ─── Train ────────────────────────────────────────────────────────────────────
train:
	@echo "[*] Running baseline detection..."
	$(PYTHON) detection/baseline.py
	@echo "[*] Training ML model..."
	$(PYTHON) detection/train.py
	@echo "[✓] Training complete — check detection/ml_metrics.json"

# ─── Test ─────────────────────────────────────────────────────────────────────
test:
	@echo "[*] Running full test suite..."
	$(PYTHON) -m pytest tests/ -v --tb=short
	@echo "[✓] Tests complete"

# ─── Infrastructure ───────────────────────────────────────────────────────────
start:
	@echo "[*] Starting infrastructure..."
	docker compose up -d
	@echo "[*] Waiting for services to be ready..."
	@sleep 5
	@echo "[*] Starting FastAPI server..."
	$(PYTHON) -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload &
	@echo "[✓] SecOpsAI running"
	@echo "    API:        http://localhost:8000"
	@echo "    Docs:       http://localhost:8000/docs"
	@echo "    MLflow:     http://localhost:5000"
	@echo "    Prometheus: http://localhost:9090"
	@echo "    Grafana:    http://localhost:3000"

stop:
	@echo "[*] Stopping services..."
	docker compose down
	@pkill -f "uvicorn api.main:app" || true
	@echo "[✓] All services stopped"

restart: stop start

logs:
	docker compose logs -f

status:
	@echo "[*] Docker services:"
	docker compose ps
	@echo ""
	@echo "[*] API:"
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "API not running"

# ─── API only ─────────────────────────────────────────────────────────────────
api:
	$(PYTHON) -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# ─── Clean ────────────────────────────────────────────────────────────────────
clean:
	@echo "[*] Cleaning artifacts..."
	rm -rf detection/models/*.pkl
	rm -rf detection/*.json
	rm -rf data/audit.log data/alerts.log data/containment.log
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "[✓] Clean complete"

