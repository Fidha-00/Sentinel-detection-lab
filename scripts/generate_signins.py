"""Generate a synthetic sign-in log for practising detections in Azure Data Explorer.

The output CSV uses the same column names as the Microsoft Sentinel SigninLogs
table, so KQL written against it only needs the table name changed later.

It contains normal sign-ins plus four planted attacks:
  1. Password spray    - one IP fails against many users   (T1110.003)
  2. MFA fatigue       - many MFA denials for one user     (T1621)
  3. Impossible travel - one user, two countries, minutes apart (T1078)
  4. Success after failures - brute force that works      (T1110)

All users, IPs and domains are fictional. Usage:
    python generate_signins.py            # writes signins_lab.csv
    python generate_signins.py --days 3 --seed 7
"""

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone

DOMAIN = "contoso-lab.example"
USERS = [f"{name}@{DOMAIN}" for name in (
    "anna", "ben", "chitra", "dev", "elena", "farid", "gita", "hari",
    "irene", "jose", "kiran", "leela", "manu", "nisha", "omar", "priya",
)]
APPS = ["Office 365 Exchange Online", "Microsoft Teams", "Azure Portal", "SharePoint Online"]
# Normal users sign in from a home IP in India.
HOME = {u: (f"49.37.{i}.{10 + i}", "IN", "Thiruvananthapuram") for i, u in enumerate(USERS)}

# Sentinel ResultType values used below.
SUCCESS = "0"
BAD_PASSWORD = "50126"
MFA_DENIED = "500121"

FIELDS = [
    "TimeGenerated", "UserPrincipalName", "IPAddress", "Location", "City",
    "ResultType", "ResultDescription", "AuthenticationRequirement",
    "AppDisplayName", "ClientAppUsed", "Scenario",
]
DESCRIPTIONS = {
    SUCCESS: "Success",
    BAD_PASSWORD: "Invalid username or password",
    MFA_DENIED: "Authentication failed during strong authentication request",
}


def row(ts, user, ip, country, city, result, mfa="singleFactorAuthentication", scenario="normal"):
    return {
        "TimeGenerated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UserPrincipalName": user,
        "IPAddress": ip,
        "Location": country,
        "City": city,
        "ResultType": result,
        "ResultDescription": DESCRIPTIONS[result],
        "AuthenticationRequirement": mfa,
        "AppDisplayName": random.choice(APPS),
        "ClientAppUsed": "Browser",
        # Label column for checking your rules; drop it when you are testing blind.
        "Scenario": scenario,
    }


def normal_activity(start, days):
    rows = []
    for day in range(days):
        for user in USERS:
            ip, country, city = HOME[user]
            for _ in range(random.randint(2, 5)):
                ts = start + timedelta(days=day, hours=random.randint(3, 13), minutes=random.randint(0, 59))
                # Occasional honest typo followed by a success.
                if random.random() < 0.1:
                    rows.append(row(ts, user, ip, country, city, BAD_PASSWORD))
                    ts += timedelta(seconds=random.randint(20, 90))
                rows.append(row(ts, user, ip, country, city, SUCCESS, "multiFactorAuthentication"))
    return rows


def attacks(start, days):
    rows = []
    last_day = start + timedelta(days=days - 1)

    # 1. Password spray: one foreign IP, 12 users, 1 attempt each over ~20 minutes.
    t = last_day + timedelta(hours=2)
    for user in random.sample(USERS, 12):
        t += timedelta(seconds=random.randint(60, 120))
        rows.append(row(t, user, "185.220.101.45", "NL", "Amsterdam", BAD_PASSWORD, scenario="password_spray"))

    # 2. MFA fatigue: correct password, 8 MFA denials in 10 minutes, then an approval.
    victim = "priya@" + DOMAIN
    t = last_day + timedelta(hours=5)
    for _ in range(8):
        t += timedelta(seconds=random.randint(45, 80))
        rows.append(row(t, victim, "102.89.34.7", "NG", "Lagos", MFA_DENIED,
                        "multiFactorAuthentication", "mfa_fatigue"))
    t += timedelta(seconds=60)
    rows.append(row(t, victim, "102.89.34.7", "NG", "Lagos", SUCCESS, "multiFactorAuthentication", "mfa_fatigue"))

    # 3. Impossible travel: India, then the US 12 minutes later.
    traveller = "dev@" + DOMAIN
    ip, country, city = HOME[traveller]
    t = last_day + timedelta(hours=8)
    rows.append(row(t, traveller, ip, country, city, SUCCESS, "multiFactorAuthentication", "impossible_travel"))
    rows.append(row(t + timedelta(minutes=12), traveller, "23.94.12.201", "US", "Dallas", SUCCESS,
                    "multiFactorAuthentication", "impossible_travel"))

    # 4. Success after failures: 9 wrong passwords then a success from the same IP.
    target = "manu@" + DOMAIN
    t = last_day + timedelta(hours=10)
    for _ in range(9):
        t += timedelta(seconds=random.randint(5, 15))
        rows.append(row(t, target, "91.240.118.33", "RU", "Moscow", BAD_PASSWORD, scenario="success_after_failures"))
    rows.append(row(t + timedelta(seconds=10), target, "91.240.118.33", "RU", "Moscow", SUCCESS,
                    scenario="success_after_failures"))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--days", type=int, default=3, help="days of normal activity (default 3)")
    parser.add_argument("--seed", type=int, default=42, help="random seed, for repeatable output")
    parser.add_argument("--out", default="signins_lab.csv", help="output CSV path")
    args = parser.parse_args()

    random.seed(args.seed)
    start = (datetime.now(timezone.utc) - timedelta(days=args.days)).replace(hour=0, minute=0, second=0, microsecond=0)
    rows = sorted(normal_activity(start, args.days) + attacks(start, args.days), key=lambda r: r["TimeGenerated"])

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    attack_rows = sum(r["Scenario"] != "normal" for r in rows)
    print(f"Wrote {len(rows)} sign-ins ({attack_rows} attack rows) to {args.out}")


if __name__ == "__main__":
    main()
