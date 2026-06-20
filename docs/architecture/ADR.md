# Architecture Decision Record — SecOpsAI

**Project:** SecOpsAI — Adversarial AI Detection Platform  
**Author:** Mubeen A. Waheed  
**Date:** June 2026  
**Status:** Approved

---

## ADR-001 — Mermaid for Architecture Diagrams

**Decision:** All architecture diagrams are written in Mermaid and live in the repo.

**Context:**  
Diagrams need to be version-controlled, diffable, and reviewable in pull requests.
External tools like Lucidchart or draw.io produce binary/opaque files that can't be
meaningfully reviewed in a PR or tracked across changes.

**Alternatives Considered:**
- draw.io — visual but not version-controllable as text
- PlantUML — text-based but heavier tooling requirement
- Mermaid — native GitHub rendering, zero tooling, lives in markdown

**Consequences:**  
All diagram changes are visible in PRs. No external tool dependency.
C4 diagrams are not supported by GitHub's Mermaid renderer — flowchart TB/LR used instead.

---

## ADR-002 — XGBoost as Primary Classifier with PyTorch as Secondary

**Decision:** XGBoost is the primary detection model. PyTorch LSTM is secondary,
used specifically for sequential/temporal attack patterns (C2 beaconing, slow exfil).

**Context:**  
The detection problem involves structured tabular features (packet counts, byte ratios,
entropy scores, flow durations). Tree-based models consistently outperform neural nets
on structured tabular data. However, temporal attack patterns benefit from sequence
modelling, which XGBoost cannot do natively.

**Alternatives Considered:**
- Random Forest — interpretable but slower inference, lower F1 on imbalanced data
- Pure PyTorch — flexible but overkill for tabular features, harder to explain
- XGBoost only — misses sequential patterns in beaconing and slow exfil
- Isolation Forest — good for anomaly detection but no multi-class support

**Consequences:**  
Two models to maintain and version. XGBoost handles C2, lateral movement, DNS tunnelling.
PyTorch LSTM handles beaconing cadence and slow exfiltration sequences.
Both are served through a single FastAPI inference endpoint with a routing layer.

---

## ADR-003 — Redis Streams over Kafka

**Decision:** Redis Streams is used as the message bus instead of Kafka.

**Context:**  
Kafka is the industry standard for high-throughput event streaming but introduces
significant operational overhead — ZooKeeper or KRaft cluster management, broker
configuration, partition tuning. For a single-node development and demo environment,
this overhead is not justified. Redis Streams provides the same consumer group
semantics, message acknowledgement, and replay capability with a single Docker container.

**Alternatives Considered:**
- Kafka — production-grade but operationally heavy for solo deployment
- RabbitMQ — message queue but lacks stream replay semantics
- Direct function calls — no buffering, no backpressure, not production-realistic

**Consequences:**  
Redis Streams is used throughout. The ingestion → detection data flow is fully buffered
and replayable. If this were deployed at scale, swapping Redis for Kafka would require
minimal code changes — only the producer/consumer client library changes, the interface
contract stays identical.

---

## ADR-004 — FastAPI over Flask or Django

**Decision:** FastAPI is used for the detection API service.

**Context:**  
The API must serve ML inference at p99 < 200ms, generate OpenAPI docs automatically,
and enforce strict input validation. FastAPI provides async request handling, automatic
Pydantic-based input validation, and auto-generated OpenAPI/Swagger docs out of the box.
Flask requires manual validation and has no native async support. Django is too heavy
for a focused inference API.

**Alternatives Considered:**
- Flask — familiar but synchronous, no native validation, no auto-docs
- Django REST Framework — production-grade but over-engineered for this scope
- FastAPI — async, Pydantic validation, OpenAPI generation, lightweight

**Consequences:**  
All request bodies are validated by Pydantic models before reaching inference logic.
OpenAPI spec is auto-generated at /docs. Async endpoints allow concurrent inference
requests without blocking.

---

## ADR-005 — PostgreSQL for Audit Logs and Alert Storage

**Decision:** PostgreSQL is the system of record for audit logs, alerts, and model metadata.

**Context:**  
Audit logs must be tamper-evident, queryable, and durable. Alert records need relational
structure — linking alerts to enrichment results, containment actions, and analyst
overrides. PostgreSQL provides ACID guarantees, row-level security, and append-only
table enforcement via triggers.

**Alternatives Considered:**
- SQLite — insufficient for concurrent writes from API + pipeline
- MongoDB — flexible schema but weaker consistency guarantees
- Elasticsearch only — good for search but not the system of record
- PostgreSQL — ACID, triggers, row-level security, battle-tested

**Consequences:**  
Audit log table is append-only enforced at DB level. Alerts are linked to enrichment
and containment records via foreign keys. PostgreSQL also feeds Grafana dashboards
directly via the PostgreSQL data source plugin.

---

## ADR-006 — IBM ART for Adversarial Robustness Testing

**Decision:** IBM Adversarial Robustness Toolbox (ART) is the sole framework for
adversarial attack generation and hardening.

**Context:**  
The project requires running at least 5 adversarial attack types against the model
and demonstrating pre/post-hardening improvement. ART supports FGSM, PGD, C&W,
DeepFool, and Boundary attacks out of the box, works with both scikit-learn and
PyTorch models, and provides adversarial training utilities.

**Alternatives Considered:**
- Foolbox — similar capability but less scikit-learn support
- CleverHans — TensorFlow-centric, poor XGBoost support
- Manual implementation — too time-consuming, not reproducible
- IBM ART — framework-agnostic, supports XGBoost + PyTorch, active maintenance

**Consequences:**  
All adversarial examples are generated through ART. Adversarial training loop uses
ART's AdversarialTrainer. Attack results are reproducible with fixed random seeds
and logged to MLflow.

---

## ADR-007 — MLflow for Experiment Tracking

**Decision:** MLflow tracks all training runs, model versions, and performance metrics.

**Context:**  
The project requires proving ML beats the rule baseline by 15% F1 with statistical
evidence. This means every experiment must be logged, comparable, and reproducible.
MLflow provides run tracking, artifact storage, and a model registry with promotion
workflows.

**Alternatives Considered:**
- Weights & Biases — excellent but requires external account
- Neptune.ai — similar issue, external dependency
- Manual CSV logging — not reproducible, not auditable
- MLflow — self-hosted, no external dependency, integrates with scikit-learn + PyTorch

**Consequences:**  
Every training run logs: hyperparameters, F1/precision/recall, confusion matrix,
feature importance, and model artifact hash. Model promotion from staging to production
requires hash verification (links to E3 in STRIDE model).

---

## ADR-008 — What Was Intentionally Left Out

**Not implemented and why:**

| Decision | Reason |
|---|---|
| No Kubernetes | Single-node Docker Compose is sufficient for demo scope. K8s adds orchestration complexity without benefit at this scale |
| No real firewall integration | Containment actions are mocked. Real firewall API calls require infrastructure access outside project scope |
| No online learning / model retraining in production | Concept drift monitoring is in scope; automated retraining in production introduces model stability risks beyond current hardening scope |
| No full MISP integration | MISP feed is documented and architected but stubbed with static IOC files. Full TAXII/STIX client adds operational complexity for marginal demo value |
| No multi-tenancy | Single-tenant design. RBAC is implemented but tenant isolation is out of scope |
