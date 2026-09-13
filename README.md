# 🛡️ Sentinel SOC

### Autonomous Security Investigation, Response & Verification Platform

> **Investigate → Decide → Act → Verify → Adapt → Resolve**

Sentinel SOC is an autonomous Security Operations Center platform designed to investigate security incidents, correlate evidence, execute containment actions, verify whether those actions actually worked, and adapt its response when the initial containment fails.

Unlike conventional SOC systems that stop after generating an alert or executing a response action, Sentinel SOC maintains a closed-loop investigation and response cycle.

The system does not simply ask:

> **"Did we execute the containment action?"**

It asks:

> **"Did the containment actually work?"**

---

## 🚨 The Problem

Modern SOC teams receive large volumes of alerts from different security sources such as:

* Network Intrusion Detection Systems
* Server logs
* Vulnerability intelligence
* Network telemetry
* Host activity

The major challenge is not only detecting threats.

It is determining:

1. What is actually happening?
2. What evidence supports the hypothesis?
3. What action should be taken?
4. Did the action actually contain the threat?
5. What should happen if the first response fails?

Traditional automated workflows often follow:

```text
Alert
  ↓
Response
  ↓
Done
```

This creates a major weakness.

An action being successfully executed does **not** necessarily mean that the attack has been contained.

---

# 💡 Sentinel SOC Solution

Sentinel SOC implements a closed-loop autonomous security response architecture:

```text
Investigate
     ↓
Form Hypothesis
     ↓
Decide
     ↓
Act
     ↓
Verify
     ↓
Did it work?
   ↙       ↘
 YES       NO
 ↓          ↓
Resolve   Classify Failure
            ↓
         Replan
            ↓
        New Action
            ↓
         Verify
```

The system maintains investigation state throughout the process, allowing it to adapt its response based on observed outcomes.

---

# 🔥 Key Innovation

## Verification-Driven Autonomous Response

The core innovation of Sentinel SOC is that **response actions are not considered successful until they are independently verified**.

### Example

A simulated attacker initially connects from:

```text
10.0.0.31
```

Sentinel identifies an active SMB compromise against:

```text
Host: FILE-01
IP: 10.0.0.15
Service: SMB
Port: 445
```

The agent initially decides to block:

```text
10.0.0.31
```

The attacker then rotates to:

```text
10.0.0.44
```

Verification detects that malicious traffic is still active.

Sentinel classifies the failure:

```text
VERIFICATION FAILURE
Failure Type: IP ROTATION
```

Instead of repeatedly blocking IP addresses, the agent replans and escalates to:

```text
HOST QUARANTINE
```

The next verification succeeds.

The incident is then marked:

```text
RESOLVED
```

This demonstrates adaptive autonomous response rather than static automation.

---

# 🧠 System Architecture

```text
                    ┌─────────────────────────┐
                    │     External Systems     │
                    │                         │
                    │  NIDS                    │
                    │  Server Logs             │
                    │  CVE Intelligence        │
                    │  Network State           │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    Retrieval Layer      │
                    │ Evidence Collection &    │
                    │ Correlation              │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     Memory / State      │
                    │                         │
                    │ Evidence                │
                    │ Hypotheses              │
                    │ Actions                 │
                    │ Verifications           │
                    │ State Transitions       │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    Agent / Controller   │
                    │                         │
                    │ Qwen3 8B / Ollama       │
                    │ Gemini Backup            │
                    │ Deterministic Fallback   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Policy-Controlled Tools │
                    │                         │
                    │ Firewall Block           │
                    │ Host Quarantine          │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Evaluation / Verification│
                    └────────────┬────────────┘
                                 │
                         ┌───────┴───────┐
                         │               │
                       SUCCESS         FAILURE
                         │               │
                         ▼               ▼
                     RESOLVE       Failure Analysis
                                         │
                                         ▼
                                     Replanning
                                         │
                                         └──────► Agent
```

A SOC operator can observe the investigation and response process through the command-center interface.

---

# 🔄 Autonomous Response Loop

Sentinel SOC follows:

```text
EVIDENCE
   ↓
INVESTIGATION
   ↓
HYPOTHESIS
   ↓
DECISION
   ↓
ACTION
   ↓
VERIFICATION
   ↓
SUCCESS? ───────────── YES ──→ RESOLVED
   │
   NO
   ↓
FAILURE CLASSIFICATION
   ↓
HYPOTHESIS UPDATE
   ↓
REPLANNING
   ↓
NEW ACTION
   ↓
VERIFICATION
```

This enables the system to respond to changing attacker behavior rather than relying on a single predetermined playbook.

---

# 📊 Investigation Evidence

Sentinel SOC correlates evidence from multiple security sources:

| Source           | Purpose                                     |
| ---------------- | ------------------------------------------- |
| NIDS             | Detect suspicious network activity          |
| Server Logs      | Identify host-level activity                |
| CVE Intelligence | Provide vulnerability context               |
| Network State    | Verify active connectivity and containment  |
| Incident State   | Maintain the complete investigation history |

The agent uses these sources to construct and update its current hypothesis.

---

# 🤖 AI Architecture

Sentinel SOC uses a layered reasoning strategy:

```text
             ┌────────────────┐
             │    Qwen3 8B    │
             │    Ollama      │
             └───────┬────────┘
                     │
                  Primary
                  Reasoning
                     │
                     ▼
             ┌────────────────┐
             │ Gemini Backup  │
             └───────┬────────┘
                     │
                  Fallback
                     │
                     ▼
             ┌────────────────┐
             │ Deterministic  │
             │    Fallback    │
             └────────────────┘
```

This provides resilience when the preferred reasoning model or external API is unavailable.

---

# 🗄️ Backend

The backend is implemented using:

* **FastAPI**
* **SQLAlchemy**
* **SQLite**
* **Pydantic**
* **Python**

The backend maintains structured incident information including:

* Incidents
* Evidence
* Hypotheses
* Actions
* Verification results
* State transitions

---

# 🌐 Frontend

The Sentinel SOC command center provides visibility into the complete investigation.

### Dashboard components include:

* Incident Queue
* Incident Overview
* Security Metrics
* Threat Correlation Chain
* Evidence Ledger
* Current Hypothesis
* Response Controls
* Containment State
* Agent Trace
* Investigation Timeline
* Network / Host State
* Final Outcome
* Evidence Details

The frontend communicates with the live backend rather than relying solely on static mock data.

---

# 🧪 Demonstration Scenario

The primary demonstration simulates an SMB compromise.

### Victim

```text
Host: FILE-01
IP: 10.0.0.15
Service: SMB
Port: 445
```

### Initial attacker

```text
10.0.0.31
```

### Adaptive attacker

```text
10.0.0.44
```

### Sentinel response

```text
1. Detect suspicious SMB activity
2. Correlate NIDS + server + CVE + network evidence
3. Form high-confidence hypothesis
4. Block attacker IP
5. Verify containment
6. Detect continued activity
7. Classify IP rotation
8. Replan
9. Quarantine the affected host
10. Verify containment
11. Resolve incident
```

---

# 📈 Example Result

Demo incident:

```text
LLM-DEMO-20260913-020652
```

Outcome:

```text
STATUS: RESOLVED

Evidence Sources:       4
Containment Attempts:   2
Verification Checks:    2
Confidence:             94%
```

The important result is not simply that two actions were executed.

The system demonstrated:

```text
Initial Action
      ↓
Failure Detected
      ↓
Failure Classified
      ↓
Strategy Adapted
      ↓
Containment Verified
      ↓
Incident Resolved
```

---

# 🛠️ Technology Stack

| Layer           | Technology              |
| --------------- | ----------------------- |
| Backend         | FastAPI                 |
| Language        | Python                  |
| ORM             | SQLAlchemy              |
| Database        | SQLite                  |
| Validation      | Pydantic                |
| AI              | Qwen3 8B / Ollama       |
| AI Backup       | Gemini                  |
| Frontend        | Web-based SOC dashboard |
| Deployment      | Render                  |
| Version Control | Git / GitHub            |

---

# 🚀 Running Locally

## 1. Clone the repository

```bash
git clone https://github.com/asoneinstein-design/Sentinel-SOC.git
cd Sentinel-SOC
```

## 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

### macOS / Linux

```bash
source .venv/bin/activate
```

### Windows

```bash
.venv\Scripts\activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Configure environment variables

Copy:

```text
.env.example
```

to:

```text
.env
```

Then configure your Gemini API key if Gemini fallback is being used.

**Never commit your real API key to GitHub.**

## 5. Start the application

Run the FastAPI application using the project's configured entry point.

For a standard FastAPI/Uvicorn deployment:

```bash
uvicorn app.main:app --reload
```

The exact application entry point may vary with the deployment configuration.

---

# ☁️ Live Demo

### Sentinel SOC Dashboard

**https://sentinel-soc-ue59.onrender.com**

### GitHub Repository

**https://github.com/asoneinstein-design/Sentinel-SOC**

---

# 🔐 Security Considerations

Sentinel SOC is currently a controlled hackathon prototype.

The response tools are designed for a simulated environment and should not be connected directly to production infrastructure without additional authorization, policy enforcement, auditing, and safety controls.

Important production requirements would include:

* Strong authentication and authorization
* Role-based access control
* Tool permission boundaries
* Human approval for high-impact actions
* Comprehensive audit logging
* Secrets management
* Rate limiting
* Network segmentation
* Safe rollback mechanisms
* Production-grade persistent storage

---

# ⚠️ Current Limitations

The current implementation is primarily a controlled demonstration of autonomous investigation and adaptive response.

Future production versions should expand:

* Real NIDS integrations
* Real EDR integrations
* SIEM connectors
* Production databases
* Distributed incident state
* More containment tools
* Advanced attack-chain correlation
* Continuous evaluation
* Multi-agent investigation
* Human approval policies
* Long-term threat intelligence memory

---

# 🔮 Future Scope

Sentinel SOC can evolve into a complete autonomous SOC platform with:

### Multi-Agent Security Operations

Specialized agents for:

```text
Detection
Investigation
Threat Intelligence
Response
Forensics
Verification
```

### Real Infrastructure Integrations

Integration with:

```text
SIEM
EDR
Firewall
IDS / IPS
Cloud Security
Identity Systems
Ticketing Systems
```

### Adaptive Threat Response

The system can learn from previous containment failures and build a stronger response strategy for future incidents.

### Continuous Security Validation

Every response action can be continuously verified rather than being treated as successful by default.

---

# 🏆 Why Sentinel SOC?

Most security automation focuses on:

> **"What action should we execute?"**

Sentinel SOC focuses on:

> **"Did the action actually solve the problem?"**

That difference creates a closed-loop security system capable of:

```text
Investigating
     ↓
Reasoning
     ↓
Acting
     ↓
Verifying
     ↓
Detecting Failure
     ↓
Adapting
     ↓
Resolving
```

## Sentinel SOC

> **Don't just respond. Verify the response.**
