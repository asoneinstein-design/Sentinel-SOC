# Sentinel SOC — System Architecture

## 1. Architecture Overview

Sentinel SOC is an autonomous Security Operations Center platform that combines security evidence, AI-assisted investigation, policy-controlled response tools, and post-action verification.

The architecture is designed around a closed-loop security model:

```text
Evidence
   ↓
Investigation
   ↓
Decision
   ↓
Response
   ↓
Verification
   ↓
Adaptation
   ↓
Resolution
```

Unlike conventional alert-response systems, Sentinel SOC maintains an incident state throughout the entire lifecycle.

---

# 2. High-Level Architecture

```text
                    SECURITY ENVIRONMENT
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
      NIDS            SERVER LOGS       CVE INTELLIGENCE
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Evidence Layer  │
                  │ Correlation     │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Incident State  │
                  │ & Memory        │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ AI SOC Agent     │
                  │ Investigation    │
                  │ Decision Engine  │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Policy /        │
                  │ Safety Layer    │
                  └────────┬────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │ Response Tool Layer     │
              │                         │
              │ Firewall Block          │
              │ Host Quarantine         │
              │ Network Controls        │
              └────────────┬────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Verification    │
                  │ Engine           │
                  └────────┬────────┘
                           │
                    ┌──────┴──────┐
                    │             │
                  SUCCESS       FAILURE
                    │             │
                    ▼             ▼
                 RESOLVED      REPLANNING
                                  │
                                  └──────→ AI Agent
```

---

# 3. Frontend Layer

The Sentinel SOC frontend acts as the SOC command center.

It presents:

* incident queue
* incident severity
* confidence
* evidence sources
* threat correlation
* current hypothesis
* containment state
* agent trace
* investigation timeline
* network state
* host state
* response actions
* verification results
* final outcome

The frontend is not merely a dashboard.

It exposes the reasoning and state transitions of the autonomous response loop so that the operator can understand why an action was taken and whether it worked.

---

# 4. API Layer

The backend exposes REST APIs for the frontend and investigation workflow.

Representative endpoints include:

```text
/api/incidents
/api/incidents/{id}
/api/incidents/{id}/timeline
/api/dashboard/{id}
/api/tools/execute
/health
```

The API layer is responsible for:

* receiving incident requests
* retrieving incident state
* exposing investigation timelines
* executing controlled response tools
* returning verification results
* providing dashboard information

---

# 5. Backend Layer

The backend is implemented using Python and FastAPI.

Major backend responsibilities include:

```text
Incident Management
        ↓
Evidence Processing
        ↓
Agent Execution
        ↓
Tool Execution
        ↓
Verification
        ↓
State Update
```

The backend maintains the lifecycle of an incident and exposes the current state to the frontend.

---

# 6. Data Layer

Sentinel SOC uses structured persistence for incident information.

The data model records information such as:

* incident identifier
* timestamp
* severity
* affected host
* source indicators
* evidence
* confidence
* actions
* verification results
* incident state
* final outcome

This allows an incident to be reconstructed after the response has completed.

---

# 7. Evidence Layer

Sentinel SOC combines multiple security evidence sources.

### NIDS

Network Intrusion Detection System data provides:

* source IP
* destination IP
* destination port
* suspicious traffic
* protocol information
* timestamps

### Server Logs

Server-side evidence can reveal:

* authentication attempts
* service access
* abnormal activity
* failed requests
* process or service behavior

### CVE Intelligence

Vulnerability intelligence provides context about:

* vulnerable services
* known vulnerabilities
* severity
* exploit relevance

### Network State

Network state provides information about:

* connectivity
* active paths
* containment state
* host isolation
* communication status

---

# 8. Evidence Correlation

A single security event may not provide enough information to make a reliable decision.

Sentinel SOC therefore correlates evidence across multiple sources.

Conceptually:

```text
NIDS
  +
Server Logs
  +
CVE Intelligence
  +
Network State
       ↓
Evidence Correlation
       ↓
Security Hypothesis
```

This reduces dependence on isolated alerts.

---

# 9. AI Decision Layer

The AI layer assists the system in interpreting evidence and selecting an appropriate response strategy.

The architecture supports:

* Qwen3 8B through Ollama as the primary local model
* Gemini as a backup model
* deterministic fallback behavior

The AI is used for tasks such as:

* summarizing evidence
* forming a threat hypothesis
* determining likely attack behavior
* selecting a response strategy
* explaining decisions
* interpreting verification failures
* proposing replanning actions

---

# 10. Policy and Safety Layer

The AI agent does not receive unrestricted control over infrastructure.

Actions pass through a controlled response layer.

```text
AI Decision
     ↓
Policy Validation
     ↓
Allowed Tool
     ↓
Execution
```

This provides an important security boundary between AI reasoning and operational controls.

---

# 11. Response Tool Layer

Sentinel SOC abstracts security controls as tools.

Examples include:

### Firewall Block

```text
Block suspicious source IP
```

### Host Quarantine

```text
Isolate affected host
```

### Network Control

```text
Change or restrict network communication
```

Tool execution is recorded in the incident timeline.

---

# 12. Verification Layer

Verification is a first-class architectural component.

After every significant containment action, the system checks whether the intended security state has actually been achieved.

```text
Response Action
      ↓
Expected State
      ↓
Observed State
      ↓
Comparison
      ↓
Verification Result
```

Example:

```text
Expected:
Attacker cannot reach FILE-01

Observed:
New attacker communication detected

Result:
FAILED
```

---

# 13. Failure Classification

When verification fails, Sentinel SOC determines the likely reason.

Possible classifications include:

```text
Attacker Adaptation
Incomplete Containment
Incorrect Hypothesis
Tool Failure
Verification Failure
```

The classification influences the next response.

This prevents the system from blindly repeating the same failed action.

---

# 14. Adaptive Replanning

The architecture supports an adaptive response loop.

Example:

```text
Block 10.0.0.31
       ↓
Verification
       ↓
FAILURE
       ↓
New source: 10.0.0.44
       ↓
Attacker adaptation detected
       ↓
Replanning
       ↓
Quarantine FILE-01
       ↓
Verification
       ↓
SUCCESS
```

This demonstrates that the agent responds to changing conditions rather than executing a static playbook.

---

# 15. Demonstration Scenario

The primary demonstration uses:

```text
Victim:
FILE-01

Victim IP:
10.0.0.15

Service:
SMB / TCP 445

Initial attacker:
10.0.0.31

Adaptive attacker:
10.0.0.44
```

The first containment action blocks the initial source.

The attacker then changes its source address.

Verification detects that containment is insufficient.

The agent therefore changes strategy and quarantines the victim host.

The second verification succeeds.

Final state:

```text
RESOLVED
```

---

# 16. Technology Stack

### Backend

* Python
* FastAPI
* SQLAlchemy
* Pydantic
* SQLite

### AI

* Qwen3 8B
* Ollama
* Gemini fallback
* deterministic fallback

### Frontend

* Web-based SOC dashboard
* REST API integration

### Deployment

* Render
* GitHub

---

# 17. Security Boundary

The system follows a controlled architecture:

```text
Untrusted Security Evidence
          ↓
Evidence Processing
          ↓
AI Reasoning
          ↓
Policy Boundary
          ↓
Controlled Security Tools
          ↓
Verification
```

This separation reduces the risk of allowing raw AI output to directly control infrastructure.

---

# 18. Architectural Principle

Sentinel SOC is built around one core principle:

> **Security automation must close the loop.**

A system that detects an attack and executes a firewall command has not necessarily contained the attack.

Sentinel SOC therefore measures success using:

```text
Action Execution
        +
Security-State Verification
        +
Adaptive Response
```

The final objective is not simply to execute a response.

It is to establish and verify a safe security state.
