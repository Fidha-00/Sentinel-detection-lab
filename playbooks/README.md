# playbook-enrich-ip

Logic App (Consumption) triggered from a Microsoft Sentinel incident. It enriches the incident with an IP reputation lookup.

## Flow

1. **Microsoft Sentinel incident** trigger.
2. **Entities - Get IPs** returns the IP entities on the incident.
3. **For each** IP:
   - **HTTP** GET `https://api.abuseipdb.com/api/v2/check`
     - Headers: `Key` (API key, kept outside the repo), `Accept: application/json`
     - Query: `ipAddress` (the IP from the loop), `maxAgeInDays` = 90
   - **Parse JSON** on the response body, using a schema generated from a sample reply.
   - **Add comment to incident (V3)** with IP, abuse confidence score, country, ISP, total reports and last reported date.

## How it is started

An automation rule triggers on "incident created", filtered to the Password Spray - Windows VM incidents, and runs this playbook.

## Permissions

- Playbook identity: system-assigned managed identity with Microsoft Sentinel Responder on the lab resource group.
- Sentinel was granted permission to run playbooks on the same resource group.

## Notes

- The API key must be added in your own copy; it is not stored in this repository.
- The IP in the demo screenshot is blurred.
