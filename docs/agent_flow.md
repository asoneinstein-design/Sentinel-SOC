# Sentinel SOC — Agent Flow

## 1. Overview

Sentinel SOC is designed as a closed-loop autonomous Security Operations Center (SOC) agent.

Traditional security automation often stops after executing a response action:

```text
Detect → Decide → Act
```

Sentinel SOC extends this model into a verification-driven autonomous loop:

```text
Investigate
    ↓
Decide
    ↓
Act
    ↓
Verify
    ↓
Adapt
    ↓
Resolve
```

The central principle is:

> **A response action is not considered successful until its security effect has been verified.**

This allows Sentinel SOC to react to adaptive attackers instead of assuming that the first containment action solved the incident.

---

# 2. Agent Responsibilities

The Sentinel SOC agent performs six major responsibilities:

1. **Incident investigation**
2. **Evidence correlation**
3. **Hypothesis generation**
4. **Response planning**
5. **Containment execution**
6. **Verification and adaptive replanning**

The agent operates over structured evidence rather than relying on a single log source.

---

# 3. Investigation Flow

When an incident is created, Sentinel SOC gathers available evidence.

### Evidence Sources

```text
              ┌─────────────────────┐
              │        NIDS         │
              │ Network Detection   │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │    Server Logs      │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   CVE Intelligence  │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   Network State     │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ Evidence Correlation │
              └─────────────────────┘
```

The agent correlates these sources to establish:

* affected host
* suspicious source
* target service
* attack indicators
* vulnerabilities
* network state
* temporal relationships
* confidence in the current hypothesis

---

# 4. Hypothesis Generation

The agent converts evidence into a current security hypothesis.

Example:

```text
Host:
FILE-01

Victim IP:
10.0.0.15

Service:
SMB / TCP 445

Initial suspicious source:
10.0.0.31
```

The agent may produce a hypothesis such as:

```text
An external host is attempting to compromise FILE-01
through SMB-related activity.

Confidence:
94%
```

The hypothesis is not treated as permanent truth.

It is continuously updated as new evidence becomes available.

---

# 5. Decision Process

The agent evaluates possible response actions based on:

* severity
* confidence
* affected asset
* attacker behavior
* available containment tools
* expected impact
* verification requirements

Conceptually:

```text
Evidence
   ↓
Threat Hypothesis
   ↓
Risk Assessment
   ↓
Candidate Actions
   ↓
Policy Check
   ↓
Selected Action
```

The agent should prefer the **least disruptive action capable of achieving reliable containment**, unless the severity of the incident requires stronger isolation.

---

# 6. Response Planning

For the demonstration scenario, the agent initially selects:

```text
ACTION 1:
Block suspicious source IP
10.0.0.31
```

The purpose of this action is to prevent further communication between the suspicious source and the victim.

The action is recorded in the incident timeline.

---

# 7. Action Execution

The response controller executes the selected security tool.

Example:

```text
Firewall Block
Source: 10.0.0.31
Target: FILE-01
Service: SMB
```

The agent does not immediately mark the incident as resolved.

Instead:

```text
Action Executed
      ↓
Verification Required
```

---

# 8. Verification

Verification is one of the defining features of Sentinel SOC.

After executing a response, the system checks whether the intended security condition actually exists.

For example:

```text
Expected:
10.0.0.31 cannot communicate with FILE-01

Observed:
New malicious traffic detected
from 10.0.0.44
```

The system therefore determines:

```text
Containment Status:
FAILED
```

This prevents false success reporting.

---

# 9. Failure Classification

A verification failure is analyzed to determine why containment failed.

The system can classify failures such as:

### Attacker Adaptation

The attacker changes infrastructure or source identity.

Example:

```text
10.0.0.31
     ↓
BLOCKED
     ↓
Attacker changes source
     ↓
10.0.0.44
```

### Incomplete Containment

The selected control stopped one communication path but did not isolate the affected asset.

### Incorrect Hypothesis

The initial assumption about the attack was incomplete or incorrect.

### Tool Failure

The security control did not execute successfully.

### Verification Failure

The action may have executed, but available evidence cannot confirm successful containment.

---

# 10. Adaptive Replanning

After a failed containment attempt, Sentinel SOC does not simply repeat the same action.

It updates the incident state:

```text
Original Hypothesis
        ↓
Verification Failure
        ↓
New Evidence
        ↓
Failure Classification
        ↓
Updated Hypothesis
        ↓
New Response Plan
```

In the demonstration:

```text
Block 10.0.0.31
       ↓
Verification
       ↓
FAILURE
       ↓
IP rotation detected
       ↓
Replanning
       ↓
Quarantine FILE-01
```

---

# 11. Stronger Containment

The second response changes the containment target.

Instead of trying to block individual attacker infrastructure, Sentinel SOC isolates the affected host.

```text
Target:
FILE-01

Action:
Host Quarantine
```

This prevents the attacker from continuing to access the asset even if the source address changes.

---

# 12. Second Verification

The system performs another verification cycle.

Expected state:

```text
FILE-01 isolated
No malicious communication
No active attacker path
```

If verification succeeds:

```text
Containment:
SUCCESS
```

The incident can then transition to:

```text
RESOLVED
```

---

# 13. Complete Agent Loop

The complete demonstration flow is:

```text
┌───────────────┐
│    INCIDENT   │
└───────┬───────┘
        ↓
┌───────────────┐
│  INVESTIGATE  │
│ Gather evidence
└───────┬───────┘
        ↓
┌───────────────┐
│     DECIDE    │
│ Build hypothesis
└───────┬───────┘
        ↓
┌───────────────┐
│      ACT      │
│ Firewall block
└───────┬───────┘
        ↓
┌───────────────┐
│     VERIFY    │
└───────┬───────┘
        ↓
     FAILED
        ↓
┌───────────────┐
│     ADAPT     │
│ Reclassify threat
└───────┬───────┘
        ↓
┌───────────────┐
│      ACT      │
│ Host quarantine
└───────┬───────┘
        ↓
┌───────────────┐
│     VERIFY    │
└───────┬───────┘
        ↓
     SUCCESS
        ↓
┌───────────────┐
│    RESOLVED   │
└───────────────┘
```

---

# 14. Agent State

Each incident maintains a state that evolves throughout the investigation.

Example:

```text
NEW
 ↓
INVESTIGATING
 ↓
HYPOTHESIS_FORMED
 ↓
ACTION_PLANNED
 ↓
ACTION_EXECUTED
 ↓
VERIFYING
 ↓
CONTAINMENT_FAILED
 ↓
REPLANNING
 ↓
ACTION_EXECUTED
 ↓
VERIFYING
 ↓
RESOLVED
```

This state model provides traceability and makes autonomous decisions auditable.

---

# 15. Human Oversight

Sentinel SOC is designed for autonomous investigation while maintaining controlled security boundaries.

High-impact actions can be placed behind policy controls or human approval depending on deployment requirements.

The architecture therefore separates:

```text
AI Decision
     ↓
Policy
     ↓
Tool Execution
```

The AI does not receive unrestricted access to the infrastructure.

---

# 16. Design Principle

The most important design principle of the agent is:

> **Never confuse action execution with successful containment.**

Sentinel SOC continuously asks:

`
