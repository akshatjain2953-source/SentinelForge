# SentinelForge — Roadmap

## MVP Boundary
- Local-only mode, no Azure, synthetic telemetry only
- Single-user RBAC (admin + analyst roles)
- Rule evaluation from YAML files stored on disk
- CLI/dashboard UI for alert triage
- No Docker orchestration initially (manual `python app.py`)

## Phase Order & Dependencies
```
Backend Foundation → Database → Telemetry → Detection-as-Code
   → Detection Engine → Alerts → Incidents → MITRE ATT&CK
   → React Dashboard → Detection Validation → Response Automation
   → Auth & RBAC → Security Hardening → Docker → CI/CD
   → Azure/Sentinel → Production Readiness → Documentation
```
Each phase depends on the previous phase's core deliverables.

---

## 1. Backend Foundation
- **Goal**: Establish Flask app structure with blueprints, config, and logging.
- **Main tasks**: App factory, environment config classes, request logging, error handlers.
- **Tests**: `curl` health endpoint; config variables load correctly.
- **Done**: App runs `python app.py` without errors; all blueprints registered.

## 2. Database
- **Goal**: Connect Flask to PostgreSQL via SQLAlchemy; define base models.
- **Main tasks**: `SQLAlchemy` init, migration scaffold, engine pool, model base.
- **Tests**: `flask db init` creates migration directory; models import without error.
- **Done**: Flask-SQLAlchemy configured; models can be created via shell.

## 3. Telemetry
- **Goal**: Accept and validate incoming security telemetry events.
- **Main tasks**: `POST /api/v1/telemetry` endpoint; JSON schema validation; quarantine malformed.
- **Tests**: `curl -X POST` with valid/invalid payloads; schema rejects bad data.
- **Done**: Telemetry accepted; malformed events return 400 and are logged.

## 4. Detection-as-Code
- **Goal**: Store and manage detection rules as YAML files on disk.
- **Main tasks**: YAML rule format; rule loading on startup; rule metadata (id, name, severity).
- **Tests**: Rule YAML parsed; rules list populated; invalid YAML rejected.
- **Done**: Rules directory scanned; rules loaded into memory; API `GET /api/v1/rules` returns them.

## 5. Detection Engine
- **Goal**: Evaluate normalized telemetry against detection rules.
- **Main tasks**: Event loop iterates rules; matched events create `detection_executions`; no arbitrary code execution.
- **Tests**: Known event matches rule; non-matching event produces no alert; rule with bad query fails safe.
- **Done**: Rule evaluation produces `detection_execution` records; matches logged with latency ms.

## 6. Alerts
- **Goal**: Convert detection executions into actionable alerts.
- **Main tasks**: Alert creation with severity/status; `attck_technique_id` mapping; assigned user.
- **Tests**: Detection match creates alert; alert has required fields; severity levels valid.
- **Done**: Alert appears in API `GET /api/v1/alerts`; status defaults to "new".

## 7. Incidents & Investigation
- **Goal**: Group alerts into incidents with timeline and evidence.
- **Main tasks**: Alert → incident promotion; incident notes/timeline; related alerts linkage.
- **Tests**: Multiple alerts promoted to single incident; incident UI displays timeline.
- **Done**: Incident created with alert group; investigation UI accessible.

## 8. MITRE ATT&CK
- **Goal**: Map alerts/incidents to ATT&CK techniques and tactics.
- **Main tasks**: ATT&CK technique table; technique_id on alerts; subtechnique support.
- **Tests**: Alert with T1059 maps to Command and Scripting Interpreter; technique filter works.
- **Done**: ATT&CK lookup endpoint `GET /api/v1/attck` returns techniques; UI shows mapping.

## 9. React Dashboard
- **Goal**: Frontend UI for alert triage, rule viewing, and incident investigation.
- **Main tasks**: Vite + TS setup; React Query for server state; feature modules (detection, incidents, rules).
- **Tests**: `npm run dev` starts frontend; UI connects to Flask API; rules list displays.
- **Done**: Frontend runs; API calls succeed; basic dashboard layout complete.

## 10. Detection Validation
- **Goal**: Test rules against positive/negative telemetry and record pass/fail.
- **Main tasks**: Test case YAML per rule; validation pipeline; false-positive tracking.
- **Tests**: Positive telemetry triggers alert (pass); negative telemetry does not (pass); results stored.
- **Done**: Validation runs on rule reload; pass/fail counts visible in UI.

## 11. Response Automation
- **Goal**: Controlled automation actions for incidents (require approval for high-impact).
- **Main tasks**: Response action types (allowlist); approval workflow; audit of executed actions.
- **Tests**: Safe action (e.g., "add_note") executes without approval; destructive action (e.g., "block_ip") requires approval.
- **Done**: Response actions API `POST /api/v1/response`; audit log records execution.

## 12. Authentication & RBAC
- **Goal**: JWT auth with role-based access control.
- **Main tasks**: Login endpoint; password hashing; role assignment; permission decorators.
- **Tests**: Login with valid credentials returns JWT; endpoints restricted by role; unauthorized returns 401.
- **Done**: Auth blueprint registered; `flask login` works; RBAC enforced on all API blueprints.

## 13. Security Hardening
- **Goal**: Headers, rate limiting, input sanitization, secure errors.
- **Main tasks**: Flask-Talisman; Flask-Limiter; marshmallow validation; error handler masking.
- **Tests**: Security headers present; rate limit triggers 429; malformed JSON rejected; no stack traces in production.
- **Done**: App passes basic security checks; rate limits active; errors are user-friendly.

## 14. Docker
- **Goal**: Containerize the application for consistent deployment.
- **Main tasks**: `Dockerfile` for backend; `docker-compose.yml` for frontend+backend+DB; env vars config.
- **Tests**: `docker build` succeeds; `docker compose up` starts all services; health checks pass.
- **Done**: Containers run; API accessible at `localhost:8080`; DB migrates automatically.

## 15. CI/CD
- **Goal**: Automated testing and deployment pipeline.
- **Main tasks**: GitHub Actions workflow; test suite (pytest); lint (ruff/flake8); deploy script.
- **Tests**: PR runs CI; all tests pass on main; lint passes.
- **Done**: Pipeline green on merge; Docker image pushed; deployment to local environment works.

## 16. Azure / Sentinel Integration
- **Goal**: Optional Azure Monitor / Log Analytics / Microsoft Sentinel integration.
- **Main tasks**: Feature flag `AZURE_INTEGRATION_ENABLED`; telemetry export via Data Collection Rules; KQL rule sync.
- **Tests**: Flag OFF → no Azure calls; flag ON → telemetry forwarded (mock); incident sync tested.
- **Done**: Integration toggle works; export format defined; documentation added.

## 17. Production Readiness
- **Goal**: Harden for deployment: secrets, DB backup, monitoring, scaling considerations.
- **Main tasks**: Secret management (env vars/Vault); DB backup script; metrics (Prometheus); config profiles.
- **Tests**: Production config runs; secrets not in repo; health endpoint returns status.
- **Done**: Production-ready config; backup verified; monitoring dashboards operational.

## 18. Documentation
- **Goal**: Project documentation, usage guides, and portfolio-ready examples.
- **Main docs**: `README.md`, `API.md`, `ARCHITECTURE.md`, `ROADMAP.md`, deployment guides.
- **Tests**: Docs build; examples run; new contributor can `clone` and `run` the app.
- **Done**: All key docs complete; contributor onboarding guide published.

---
*Roadmap v1.0 — for solo developer implementation. Phases are executable independently; pause at any point.*