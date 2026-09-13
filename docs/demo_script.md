# Sentinel SOC — Demonstration Script

## 1. Demo Objective

The purpose of this demonstration is to show that Sentinel SOC can autonomously:

1. investigate a security incident
2. correlate evidence
3. form a threat hypothesis
4. execute a containment action
5. verify whether containment worked
6. detect attacker adaptation
7. replan the response
8. execute stronger containment
9. verify successful containment
10. resolve the incident

The central message of the demonstration is:

> **Sentinel SOC does not assume that containment worked. It verifies it.**

---

# 2. Demonstration Environment

### Victim

```text
Host: FILE-01
IP: 10.0.0.15
Service: SMB
Port: TCP 445
```

### Initial attacker

```text
10.0.0.31
```

### Adaptive attacker

```text
10.0.0.44
```

---

# 3. Step 1 — Incident Detection

The SOC dashboard displays a new incident.

The incident contains evidence from multiple sources:

```text
NIDS
Server Logs
CVE Intelligence
Network State
```

The operator opens the incident.

### Narration

> "We begin with a suspicious activity alert involving FILE-01, an internal file server exposing SMB. Instead of immediately executing a response, Sentinel SOC first investigates the available evidence."

---

# 4. Step 2 — Evidence Correlation

The dashboard displays the supporting evidence.

The agent correlates:

* suspicious network traffic
* server-side activity
* vulnerability intelligence
* current network state

The agent generates a security hypothesis.

Example:

```text
Current Hypothesis:
FILE-01 is being targeted through suspicious SMB activity.

Confidence:
94%
```

### Narration

> "The agent correlates four independent evidence sources and builds a working hypothesis with 94 percent confidence."

---

# 5. Step 3 — First Response

The agent selects the first containment action:

```text
BLOCK SOURCE IP

10.0.0.31
```

The action is executed through the controlled response layer.

### Narration

> "The first response is intentionally targeted. Sentinel SOC blocks the suspicious source rather than immediately isolating the entire server."

---

# 6. Step 4 — Verification

The system does not immediately mark the incident as resolved.

Instead, it verifies the expected network state.

Expected:

```text
10.0.0.31
      X
FILE-01
```

But the system detects new suspicious activity.

New source:

```text
10.0.0.44
```

Verification result:

```text
FAILED
```

### Narration

> "This is the critical moment. The firewall action executed successfully, but containment itself failed. The attacker adapted by changing its source address."

---

# 7. Step 5 — Failure Classification

The agent classifies the failure:

```text
Attacker Adaptation
```

The incident state changes from:

```text
CONTAINMENT ATTEMPT
```

to:

```text
REPLANNING
```

### Narration

> "Instead of repeating the same firewall rule, the agent recognizes that the failure was caused by attacker adaptation."

---

# 8. Step 6 — Adaptive Replanning

The agent generates a stronger containment strategy.

Instead of targeting the attacker:

```text
Block attacker IP
```

it targets the affected asset:

```text
Quarantine FILE-01
```

### Narration

> "Because the attacker can rotate its source address, the agent changes the containment strategy. It now isolates the affected host itself."

---

# 9. Step 7 — Second Response

The host quarantine action is executed.

Expected state:

```text
FILE-01
    ↓
ISOLATED
```

The attacker should no longer have an active communication path to the asset.

---

# 10. Step 8 — Second Verification

The system performs another verification cycle.

Expected:

```text
No active malicious communication
FILE-01 isolated
Attack path removed
```

Observed:

```text
Containment confirmed
```

Result:

```text
SUCCESS
```

---

# 11. Step 9 — Incident Resolution

The incident transitions to:

```text
RESOLVED
```

The dashboard shows:

```text
Confidence:
94%

Evidence Sources:
4

Containment Attempts:
2

Verification Checks:
2

Final Status:
RESOLVED
```

### Narration

> "Only after successful verification does Sentinel SOC mark the incident as resolved."

---

# 12. Final Message to Judges

End the demonstration with:

> "The important difference is that Sentinel SOC is not simply an automated playbook. It forms a hypothesis, takes an action, checks whether that action actually worked, recognizes when the attacker adapts, replans the response, and verifies the new containment state."

Then show the complete loop:

```text
INVESTIGATE
      ↓
DECIDE
      ↓
ACT
      ↓
VERIFY
      ↓
ADAPT
      ↓
ACT AGAIN
      ↓
VERIFY
      ↓
RESOLVED
```

---

# 13. Demo Backup Plan

If live AI inference or external services become unavailable, the demonstration should use the deterministic fallback scenario.

The expected sequence remains:

```text
Incident
 ↓
Evidence
 ↓
94% Hypothesis
 ↓
Firewall Block
 ↓
Verification Failure
 ↓
IP Rotation
 ↓
Replanning
 ↓
Host Quarantine
 ↓
Verification Success
 ↓
RESOLVED
```

This ensures that the core security workflow remains demonstrable even if an external AI provider is unavailable.

---

# 14. Demo Success Criteria

The demonstration is considered successful if judges can clearly observe:

* multiple evidence sources
* AI-generated hypothesis
* confidence score
* response action
* verification result
* containment failure
* attacker adaptation
* response replanning
* second containment action
* successful verification
* final resolution

The strongest moment of the demonstration is the transition:

```text
Firewall Block
      ↓
Verification FAILED
      ↓
Attacker Adaptation
      ↓
Replanning
```

This is the key differentiator of Sentinel SOC.
