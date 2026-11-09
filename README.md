# 🛡️ AGENTGUARD

> **Task-Aware Runtime Security and Reliability Framework for Autonomous AI Agents**
>
> **Release:** `v0.1.0` (Initial Research Prototype)  
> **Notice:** AGENTGUARD v0.1.0 is an early-stage research prototype exploring task-context aware runtime guardrails and tool call monitoring. It is not currently intended for unmonitored production deployment.

AGENTGUARD provides deterministic runtime guardrails, task-context aware interception, policy enforcement, trajectory tracking, and reliability evaluation for autonomous AI agents executing real-world tool operations.

---

## 🌟 Key Capabilities (Stages 01 – 04)

- **FastAPI Core & Diagnostics (Stage 01)**: High-performance asynchronous API engine with health probes, database connectivity checks, and Pydantic v2 configuration management.
- **Task Context Manager (Stage 02)**: Immutable task security boundaries defining allowed/denied action whitelists, entity restrictions, transaction limits, and expiration controls with deny-by-default semantics.
- **Deterministic Policy Engine (Stage 02)**: Algorithmic rule evaluation producing structured `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL` decisions without relying on non-deterministic LLMs for authorization.
- **Authoritative Approval Store (Stage 02)**: Tamper-proof, role-verified human approval registry strictly bound to task ID, action type, target entity/beneficiary, and maximum approved amount.
- **Runtime Monitoring Engine (Stage 03)**: Central security evaluation engine combining parameter validation, context resolution, chronological trajectory inspection, and policy evaluation into auditable `MonitoringDecision` records.
- **Action Interceptor & Tool Wrapping (Stage 03)**: Transparent tool wrapper ensuring that no simulated agent tool executes directly without security inspection.
- **Execution Gateway (Stage 03)**: Thread-safe dispatch boundary with atomic concurrency locking, duplicate execution prevention, single-use approval token replay protection, and fail-closed error handling.
- **Trajectory Tracker & Anomaly Detector (Stage 03)**: Strict separation of proposed vs. executed actions, chronological action tracking, and automatic detection of suspicious action ordering, burst requests, and action repetition loops.
- **Structured Security Event Emitter (Stage 03)**: Real-time, thread-safe audit event streaming covering all runtime decisions, anomalies, and execution outcomes.
- **Execution Sandbox & Mock Services (Stage 04)**: Isolated in-memory environment providing synthetic accounts, vendors, invoices, payments, virtual filesystem, mock HTTP client, and mock database operations.
- **Deterministic Fault Injection (Stage 04)**: Post-authorization tool-level simulation of network timeouts, HTTP rate limits (429), 5xx server errors, and payload corruption.
- **Adversarial Scenarios & Regression Runner (Stage 04)**: Standardized benchmark catalog and automated trace replay runner with forensic verdict comparison.

---

## 📁 Project Structure

```
AGENTGUARD/
├── backend/
│   ├── __init__.py               # Package metadata and version definition
│   ├── main.py                   # FastAPI application factory & lifespan
│   ├── agent/                    # Agent orchestration & state machines (Stage 03 exports)
│   │   └── __init__.py
│   ├── api/                      # API routers, route handlers, and schemas
│   │   ├── __init__.py
│   │   ├── router.py             # Main router aggregation
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   └── health.py         # Health check & database probe endpoint
│   │   └── schemas/
│   │       ├── __init__.py
│   │       └── health.py         # Pydantic v2 Health response models
│   ├── core/                     # Central configuration and logging
│   │   ├── __init__.py
│   │   ├── config.py             # Pydantic Settings management
│   │   └── logging.py            # Centralized logging configuration
│   ├── database/                 # SQLAlchemy 2.0 ORM session and engine
│   │   ├── __init__.py
│   │   ├── base.py               # DeclarativeBase model
│   │   └── session.py            # SessionLocal factory & get_db dependency
│   ├── evaluation/               # Metrics & reliability analytics (Stage 05)
│   │   └── __init__.py
│   ├── security/                 # Security context, policies, monitoring & gateway
│   │   ├── __init__.py           # Security module exports
│   │   ├── models.py             # Pydantic models (TaskContext, Action, Policy, ApprovalRecord)
│   │   ├── context.py            # TaskContextManager & authoritative approval registry
│   │   ├── engine.py             # Deterministic PolicyEngine
│   │   ├── events.py             # SecurityEventEmitter & structured security events
│   │   ├── gateway.py            # ExecutionGateway & concurrency/replay guards
│   │   ├── interceptor.py        # ActionInterceptor & wrap_tool interface
│   │   ├── monitoring.py         # MonitoringEngine & MonitoringDecision
│   │   └── tracker.py            # TrajectoryTracker & workflow anomaly detector
│   └── simulator/                # Execution sandbox & mock services (Stage 04)
│       ├── __init__.py           # Simulator exports
│       ├── models.py             # Synthetic accounts, vendors, invoices, payments
│       ├── state.py              # Thread-safe in-memory SimulationState container
│       ├── seed.py               # create_default_state() seed factory
│       ├── sandbox.py            # SimulationSandbox with guarded tool wrappers
│       ├── approval.py           # ApprovalService simulating human approvals
│       ├── faults.py             # Deterministic FaultInjector & fault rules
│       ├── scenarios.py          # AdversarialScenario catalog & builders
│       ├── runner.py             # SandboxRunner for trace and scenario replay
│       └── tools/                # Underlying tool implementations
│           ├── __init__.py
│           ├── banking.py        # Accounts, invoices, payments
│           ├── filesystem.py     # Virtual sandboxed filesystem
│           ├── http_client.py    # Mock HTTP request dispatcher
│           └── database.py       # Mock database key-value operations
├── dashboard/                    # Streamlit operator dashboard
│   ├── __init__.py
│   └── app.py                    # Dashboard application entrypoint
├── tests/                        # Automated verification test suite
│   ├── __init__.py
│   ├── conftest.py               # Shared fixtures & test client
│   ├── api/
│   │   ├── __init__.py
│   │   └── test_health.py        # Endpoint status & schema validation (3 tests)
│   ├── security/                 # Security, policy, monitoring & adversarial tests
│   │   ├── __init__.py
│   │   ├── test_context.py       # Context manager & approval registry tests (28 tests)
│   │   ├── test_engine.py        # Policy engine & authorization rule tests (27 tests)
│   │   ├── test_monitoring.py    # Monitoring engine & gateway tests (12 tests)
│   │   └── test_adversarial.py   # Multi-threaded concurrency & race audit (13 tests)
│   ├── simulator/                # Execution sandbox & environment tests (Stage 04)
│   │   ├── __init__.py
│   │   ├── test_banking.py       # Synthetic banking & approval workflow tests (4 tests)
│   │   ├── test_filesystem.py    # Virtual filesystem & path traversal tests (3 tests)
│   │   ├── test_http_database.py # Mock HTTP & database CRUD tests (2 tests)
│   │   ├── test_faults.py        # Deterministic fault injection tests (2 tests)
│   │   └── test_scenarios_runner.py # Scenario benchmark & trace replay tests (7 tests)
│   └── unit/
│       ├── __init__.py
│       ├── test_config.py        # Settings validation tests (3 tests)
│       ├── test_database.py      # Database session lifecycle tests (2 tests)
│       └── test_logging.py       # Logger formatting tests (3 tests)
├── data/                         # Local SQLite database files
│   └── .gitkeep
├── docs/                         # Technical documentation & roadmaps
│   ├── ARCHITECTURE.md           # Subsystem boundaries & data flow
│   └── DEVELOPMENT_ROADMAP.md    # Multi-stage roadmap progression
├── .env.example                  # Template environment variables
├── .gitignore                    # Git exclusions
├── LICENSE                       # Apache 2.0 Open Source License
├── pyproject.toml                # Build metadata & pytest configuration
├── requirements.txt              # Python dependencies
└── README.md                     # Project documentation & setup guide
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.11+** (tested on Python 3.12).
- Standard tools: `git`, `python`, `pip` (or `uv`).

### 1. Environment Setup

Clone the repository and navigate into the project directory:

```bash
cd AGENTGUARD
```

Create and activate a Python virtual environment:

**On Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
# If script execution is disabled, temporarily allow for current session:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

**On Windows (Command Prompt):**
```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

**Using `uv` (Recommended for fast builds):**
```bash
uv venv .venv --python 3.12
.\.venv\Scripts\activate
```

---

### 2. Install Dependencies

Install all required production and testing dependencies:

```bash
pip install -r requirements.txt
```

*(Or via uv: `uv pip install -r requirements.txt`)*

---

### 3. Environment Configuration

Copy the sample environment file to create your local `.env`:

**On Linux/macOS:**
```bash
cp .env.example .env
```

**On Windows:**
```powershell
Copy-Item .env.example .env
```

Review or modify settings inside `.env` as needed:

```ini
APP_NAME=AGENTGUARD
APP_ENV=development
DEBUG=true
API_V1_PREFIX=/api/v1
HOST=127.0.0.1
PORT=8000
LOG_LEVEL=INFO
LOG_FORMAT=console
DATABASE_URL=sqlite:///./data/agentguard.db
CORS_ORIGINS=http://localhost:8501,http://127.0.0.1:8501,http://localhost:8000,http://127.0.0.1:8000
```

---

## ⚡ Execution

### Running the FastAPI Backend

Launch the development server with live reload:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Verify the service is up:
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Root Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **API v1 Health Check**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

Sample Health Check Response:
```json
{
  "status": "ok",
  "app_name": "AGENTGUARD",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-11-03T02:00:00.000000Z",
  "database": "connected",
  "details": {
    "database_url": "./data/agentguard.db"
  }
}
```

---

### Running the Test Suite

Execute the automated test suite with pytest:

```bash
pytest -v
```

All 109 unit, API, context manager, policy engine, monitoring, adversarial, and simulation sandbox tests will run in ~0.4 seconds:

```
collected 109 items

tests/api/test_health.py ...                                      [  2%]
tests/security/test_adversarial.py .............                  [ 14%]
tests/security/test_context.py ............................       [ 40%]
tests/security/test_engine.py ...........................         [ 65%]
tests/security/test_monitoring.py ............                    [ 76%]
tests/simulator/test_banking.py ....                              [ 79%]
tests/simulator/test_faults.py ..                                 [ 81%]
tests/simulator/test_filesystem.py ...                            [ 84%]
tests/simulator/test_http_database.py ..                          [ 86%]
tests/simulator/test_scenarios_runner.py .......                  [ 92%]
tests/unit/test_config.py ...                                     [ 95%]
tests/unit/test_database.py ..                                    [ 97%]
tests/unit/test_logging.py ...                                    [100%]

============================== 109 passed in 0.37s ==============================
```

---

### Running the Streamlit Dashboard

To launch the operator dashboard interface:

```bash
streamlit run dashboard/app.py
```

The dashboard will open automatically at [http://localhost:8501](http://localhost:8501).

---

## 📖 Documentation

- [Architecture Guide](file:///docs/ARCHITECTURE.md): Detailed subsystem responsibilities, security boundaries, and data flow.
- [Development Roadmap](file:///docs/DEVELOPMENT_ROADMAP.md): Detailed progression across Stages 01 through 06.

---

## 📜 License

AGENTGUARD is licensed under the [Apache 2.0 License](file:///LICENSE).
