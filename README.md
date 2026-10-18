# Sentinel Detection Lab

A small, working Microsoft Sentinel lab: Windows security events collected from an Azure VM, a custom KQL password-spray detection mapped to MITRE ATT&CK, and a Logic App playbook that enriches the resulting incident with an IP reputation lookup.

Everything listed as done below was run and checked in my own Azure lab, with screenshots in [`screenshots/`](screenshots/). Things I have not built yet are listed under [Roadmap](#roadmap) and are not claimed anywhere else.

> Status: in progress. Detection and enrichment playbook working end to end.

## What it does

```
Windows VM (test) --AMA + DCR (EventID 4624/4625)--> Log Analytics workspace (SecurityEvent)
   --> Sentinel scheduled analytics rule (password spray) --> incident
   --> automation rule (on incident created) --> Logic App playbook
   --> AbuseIPDB lookup on the attacker IP --> enrichment comment on the incident
```

## Data collection

| Source | Table | How it is collected |
| --- | --- | --- |
| Windows VM security events | `SecurityEvent` | Azure Monitor Agent with a data collection rule, filtered by XPath to Event IDs 4624 and 4625 only |

Check that the filter works: `SecurityEvent | distinct EventID` returns only 4624 and 4625.

## Detection

| Rule | Severity | ATT&CK | Data source | Tested |
| --- | --- | --- | --- | --- |
| Password Spray - Windows VM | Medium | T1110.003 Password Spraying (Credential Access) | `SecurityEvent` (4625) | Yes, see below |

Logic: failed logons (Event 4625, LogonType 3, user accounts) from a single source IP against 3 or more distinct accounts within a 10-minute bin, which is a spray, as opposed to many attempts against one account (brute force). Details, thresholds and entity mapping are in [`detections/endpoint/password-spray-single-ip/`](detections/endpoint/password-spray-single-ip/).

Schedule: runs every 10 minutes over a 30-minute lookback. The lookback is longer than the frequency on purpose, so events that are ingested late are not missed. The overlap can produce repeat alerts, which are grouped by IP entity into one incident.

How I tested it:
- **Negative test:** many failed logons against one account did not fire the rule.
- **Positive test:** failed logons against several different account names from one IP fired the rule and created an incident.

Windows detail worth knowing: with Network Level Authentication, a failed RDP logon is logged as LogonType 3 (a successful interactive RDP logon is type 10), so the rule filters on type 3.

## Enrichment playbook

Logic App `playbook-enrich-ip` ([`playbooks/README.md`](playbooks/README.md)):
1. Trigger: Microsoft Sentinel incident.
2. Get the IP entities from the incident.
3. For each IP, call the AbuseIPDB `check` API (GET, API key in a header).
4. Parse the JSON reply.
5. Add a comment to the incident with the IP, abuse confidence score, country, ISP, total reports and last reported date.

An automation rule runs the playbook when an incident is created from this analytics rule. I confirmed it end to end: a new incident was created and the enrichment comment appeared with no manual step.

Access model: the playbook's system-assigned managed identity has the Microsoft Sentinel Responder role on the lab resource group only. Sentinel itself was granted permission to run playbooks on the same resource group.

## Safety and cost notes

- RDP on the test VM is restricted to my own IP. It is never open to Any.
- The VM is a throwaway test machine, deallocated when not in use. Playbooks only run against test data.
- The AbuseIPDB key is stored outside the repository and does not appear in any screenshot.
- Screenshots have the public IP, account email, tenant and subscription IDs blurred or cropped.
- Costs are monitored with a budget alert.

## Screenshots

Identifying details (public IP, account email, tenant and subscription IDs) are covered with solid boxes.

| What it shows | File |
| --- | --- |
| Only Event IDs 4624 and 4625 reach the workspace | [`06-distinct-eventid-redacted.png`](screenshots/06-distinct-eventid-redacted.png) |
| Raw Windows security events in `SecurityEvent` (successful and failed logons) | [`07-securityevent-sample-redacted.png`](screenshots/07-securityevent-sample-redacted.png) |
| Final detection query and its result (6 distinct accounts from one IP) | [`05-spray-query-result-redacted.png`](screenshots/05-spray-query-result-redacted.png) |
| Incident created by the rule, with the IP entity, MITRE mapping and rule description | [`04-incident-overview-redacted.png`](screenshots/04-incident-overview-redacted.png) |
| Automation rule that runs the playbook on new incidents | [`03-automation-rule.png`](screenshots/03-automation-rule.png) |
| Playbook run history (all runs succeeded) | [`01-logic-app-run-history-redacted.png`](screenshots/01-logic-app-run-history-redacted.png) |
| Enrichment comment written to the incident by the playbook | [`02-enrichment-comment-redacted.png`](screenshots/02-enrichment-comment-redacted.png) |

## Limitations

- Single test VM and a single source IP, so false-positive tuning against realistic noise has not been done.
- The attacker IP in testing was my own, so the reputation score in the demo is 0. The enrichment path is proven, not the scoring thresholds.
- Rules are created in the portal; they are not yet deployed from this repository.

## Roadmap

- Tag or raise severity on the incident based on the abuse score.
- Detection for a successful sign-in after repeated failures.
- Export the rule as code and deploy it from GitHub Actions.
- A second playbook for identity response on a test Entra user.

## Lessons learned

- A rule's lookback has to be longer than its frequency, otherwise there are gaps between runs.
- The data collection rule filter is worth verifying with `distinct EventID` before trusting any detection built on top of it.
- Sentinel needs two separate permissions for playbooks: the playbook's identity needs a role on Sentinel, and Sentinel needs permission to run the playbook.
