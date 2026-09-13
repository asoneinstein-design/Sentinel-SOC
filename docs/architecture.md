# Sentinel SOC — System Architecture

## Overview

Sentinel SOC is an autonomous SOC investigation and response platform built around a closed-loop security workflow.

The system combines security telemetry, evidence retrieval, incident state, AI-assisted planning, controlled response tools, verification, and adaptive replanning.

The core architecture is:

```text
External Security Systems
        ↓
Evidence Retrieval
        ↓
Incident Memory / State
        ↓
Planning
        ↓
Agent / Controller
        ↓
Policy-Controlled Tools
        ↓
Verification
        ↓
 ┌──────────────┐
 │              │
SUCCESS       FAILURE
 │              │
 ↓              ↓
RESOLVE    Failure Classification
                ↓
          Update Incident State
                ↓
              Replan
                ↓
          New Response Action
                ↓
             Verify
