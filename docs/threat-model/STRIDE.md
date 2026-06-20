# STRIDE Threat Model — SecOpsAI

## Methodology
Each threat is identified per component/data flow, mapped to a MITRE ATT&CK technique,
and assigned a mitigation. AI-specific threats (poisoning, evasion, inference attacks)
are treated as first-class threat categories alongside traditional STRIDE.

---

## Trust Zone Crossings — Threat Surface

| Zone Crossing | Direction | Risk Level |
|---|---|---|
| Z0 → Z1 (PCAP/Logs into Ingestion) | Inbound untrusted | High |
| Z1 → Z2 (Features into Detection) | Internal | Medium |
| Z2 → Z3 (Model output into API) | Internal | Medium |
| Z3 → Z4 (API into Response) | Egress | Medium |
| Z4 → External (VT/Shodan/Slack) | Outbound | High |
| Any → Z5 (Metrics into Observability) | Internal | Low |

---

## S — Spoofing

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| S1 | Ingestion (Z0→Z1) | Attacker injects forged PCAP or log data impersonating a legitimate host to poison the feature pipeline | T1565.001 – Stored Data Manipulation | Cryptographic signing of ingestion sources; HMAC on log files at origin |
| S2 | Detection API (Z3) | Client spoofs a valid JWT token to submit false inference requests or manipulate alert history | T1550.001 – Application Access Token | Short-lived JWT with RS256 signing; token revocation list in Redis |
| S3 | MISP Feed (Z0→Z1) | Attacker spoofs the MISP threat intel feed to inject false IOCs, poisoning detection logic | T1199 – Trusted Relationship | Mutual TLS on MISP connection; feed signature verification |
| S4 | Enrichment (Z4) | Response pipeline receives spoofed VirusTotal/Shodan responses via DNS hijack or MITM | T1557 – Adversary in the Middle | Certificate pinning on external API calls; response schema validation |

---

## T — Tampering

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| T1 | Kafka/Redis Stream (Z1→Z2) | Attacker with internal access modifies feature vectors in transit to suppress detections | T1565 – Data Manipulation | Encrypt stream with TLS; HMAC each message; consumer verifies before processing |
| T2 | ML Model Artifacts | Trained model weights tampered with on disk to degrade detection or introduce backdoors | T1195 – Supply Chain Compromise | Model artifact hashing (SHA-256) stored in MLflow; hash verified at load time |
| T3 | Training Data | Adversarial examples injected into training pipeline (data poisoning) to shift decision boundary | T1565.001 – Stored Data Manipulation | Tamper-evident hash chaining on dataset; anomaly detection on label distribution before training |
| T4 | Audit Log (PostgreSQL) | Attacker deletes or modifies audit records to cover lateral movement through the platform | T1070 – Indicator Removal | Append-only audit table with DB-level triggers; log mirroring to external SIEM |
| T5 | Feature Engineering (Z1→Z2) | Malicious traffic crafted to produce adversarial feature vectors that evade the ML model | T1027 – Obfuscated Files or Information | Adversarial training with IBM ART; input validation on feature bounds |

---

## R — Repudiation

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| R1 | Detection API | Analyst denies triggering a manual override or suppressing an alert — no audit trail | T1562 – Impair Defenses | Structured audit log on every API call: who, what, when, result — stored in PostgreSQL |
| R2 | Containment Engine | Automated containment action (firewall block, host isolation) executed with no traceable trigger | T1070 – Indicator Removal | Every containment action logged with: triggering alert ID, model score, timestamp, action taken |
| R3 | ML Model | Model makes a high-impact decision with no explainability — impossible to audit why | — | SHAP values logged per inference; prediction confidence + feature contributions stored with each alert |

---

## I — Information Disclosure

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| I1 | Detection API (Z3) | API error messages leak internal architecture, stack traces, or model details to attacker | T1592 – Gather Victim Host Information | Generic error responses in production; detailed errors only in structured internal logs |
| I2 | ML Model (Z2) | Model inversion attack — attacker queries the API repeatedly to reconstruct training data or infer sensitive network topology | T1590 – Gather Victim Network Information | Rate limiting on inference endpoint; query anomaly detection; output confidence score rounding |
| I3 | Observability Stack (Z5) | Grafana dashboard exposed publicly leaks detection thresholds, model performance, and alert volumes | T1590 | Grafana behind VPN or auth proxy; dashboards read-only for non-admin roles |
| I4 | Enrichment Egress (Z4) | IOCs sent to VirusTotal/Shodan leak internal IP addresses and internal threat intelligence | T1567 – Exfiltration Over Web Service | Hash IOCs before external lookup where possible; document data sharing policy |

---

## D — Denial of Service

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| D1 | Ingestion Layer (Z1) | Attacker floods ingestion with massive PCAP files or log bursts to exhaust pipeline capacity | T1499 – Endpoint Denial of Service | Ingestion rate limiting; Kafka consumer lag alerting; backpressure handling in pipeline |
| D2 | Detection API (Z3) | API flooded with inference requests to exhaust compute and delay real detections | T1499 | Rate limiting per API key (Redis token bucket); autoscaling policy; p99 latency alerting |
| D3 | ML Model (Z2) | Adversarially crafted inputs designed to maximise inference time (algorithmic complexity attack) | T1499 | Input feature bounds validation; inference timeout enforced at 200ms; malformed input rejection |
| D4 | Kafka Stream (Z1→Z2) | Consumer lag attack — producer overwhelms stream faster than consumer can process | T1499 | Dead letter queue; consumer group lag monitoring in Prometheus; circuit breaker pattern |

---

## E — Elevation of Privilege

| # | Component | Threat | MITRE ATT&CK | Mitigation |
|---|---|---|---|---|
| E1 | Detection API (Z3) | JWT with insufficient scope allows read-only analyst to trigger containment actions | T1078 – Valid Accounts | Role-based access control (RBAC): analyst / operator / admin scopes enforced per endpoint |
| E2 | Containment Engine (Z4) | Automated response pipeline exploited to execute arbitrary firewall rules or system commands | T1059 – Command and Scripting Interpreter | Containment actions whitelisted and parameterised — no raw command execution; action schema validated |
| E3 | MLflow (Z2) | Attacker with MLflow access promotes a poisoned model to production by manipulating model registry | T1195 – Supply Chain Compromise | Model promotion requires signed approval + hash verification; MLflow API behind auth |
| E4 | Docker / Compose | Container escape from detection engine container grants host-level access | T1611 – Escape to Host | Non-root containers; read-only filesystem where possible; seccomp profiles applied |

---

## AI-Specific Threats (Beyond Standard STRIDE)

| # | Threat Type | Description | Mitigation |
|---|---|---|---|
| AI1 | Model Evasion | Adversarially crafted traffic (FGSM, PGD, C&W attacks) causes model to misclassify malicious as benign | Adversarial training via IBM ART; ensemble detection; anomaly score on feature distribution |
| AI2 | Data Poisoning | Attacker injects mislabelled samples into training pipeline to degrade model over time | Dataset integrity checks; label distribution monitoring; holdout clean validation set |
| AI3 | Model Inversion | Repeated API queries used to reconstruct sensitive training data or network topology | Rate limiting; output perturbation; confidence score truncation |
| AI4 | Model Stealing | Attacker clones the model by querying the API systematically to replicate decision boundaries | Query volume anomaly detection; watermarking model outputs |
| AI5 | Backdoor Attack | Trojan trigger embedded in training data causes model to always pass traffic with specific pattern | Activation clustering analysis during training; neural cleanse checks post-training |

---

## Threat Summary

| Category | Threats Identified | AI-Specific |
|---|---|---|
| Spoofing | 4 | 0 |
| Tampering | 5 | 2 (T3, T5) |
| Repudiation | 3 | 1 (R3) |
| Information Disclosure | 4 | 1 (I2) |
| Denial of Service | 4 | 1 (D3) |
| Elevation of Privilege | 4 | 1 (E3) |
| AI-Specific | 5 | 5 |
| **Total** | **29** | **11** |
