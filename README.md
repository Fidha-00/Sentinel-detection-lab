# Sentinel Detection Lab

Detection-as-code lab for Microsoft Sentinel: custom KQL analytics rules mapped to MITRE ATT&CK, deployed from GitHub, and validated with real attack simulations (Atomic Red Team) in an Azure lab.

> Status: 🚧 In progress

## Architecture

_Diagram goes here (`docs/architecture.png`): data sources → Log Analytics workspace → Sentinel analytics rules → incidents, with GitHub Actions deploying the rules._

## Data sources

| Source | Table | How it's collected |
| --- | --- | --- |
| Entra ID sign-ins | `SigninLogs` | Entra ID diagnostic settings |
| Entra ID audit | `AuditLogs` | Entra ID diagnostic settings |
| Azure activity | `AzureActivity` | Azure Activity connector |
| Windows VM security events | `SecurityEvent` | Azure Monitor Agent + data collection rule (filtered by Event ID) |

## Detections

| # | Rule | ATT&CK | Data source | Tested |
| --- | --- | --- | --- | --- |
| 1 | | | | ⬜ |

## Repository layout

```
detections/
  identity/<rule-name>/   query.kql, rule.yaml, rule.json (ARM template)
  endpoint/<rule-name>/   query.kql, rule.yaml, rule.json
tests/                    attack simulation commands and results
docs/                     architecture diagram, coverage map, screenshots, tuning and cost notes
.github/workflows/        validation and deployment pipeline
```

## How to deploy

_To be completed in Phase 3._

## How to test

_To be completed in Phase 3._

## Results

_Detection results and false-positive tuning (before vs after) go here._

## Lessons learned

_What broke and how it was fixed._
