# Test results

| Rule | ATT&CK | Test run | Fired? | Attack → incident time | Notes / fix |
| --- | --- | --- | --- | --- | --- |
| Password Spray - Windows VM | T1110.003 | Negative: repeated failed RDP logons, one account | No | n/a | Correct: one account is brute force, not a spray |
| Password Spray - Windows VM | T1110.003 | Positive: failed RDP logons, several account names, one IP | Yes | not measured | Needed LogonType 3 filter (NLA logs failed RDP as type 3); excluded empty and "-" IPs |
| Automation + playbook-enrich-ip | n/a | New incident created by the rule | Yes, playbook ran with no manual step | not measured | Enrichment comment added to the incident |
