"""
SecOpsAI — Configuration Validator
Run this before starting the stack to verify all integrations are configured.
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def check(name, env_var, required, how_to_get):
    value = os.getenv(env_var, "")
    if value and value != "changeme":
        print(f"{GREEN}✅ {name}{RESET}")
        return True
    elif required:
        print(f"{RED}❌ {name} — REQUIRED{RESET}")
        print(f"   Set {env_var} in your .env file")
        print(f"   How to get it: {how_to_get}")
        return False
    else:
        print(f"{YELLOW}⚠️  {name} — optional, skipping enrichment{RESET}")
        print(f"   Set {env_var} in your .env file")
        print(f"   How to get it: {how_to_get}")
        return True


print(f"\n{BOLD}SecOpsAI — Configuration Check{RESET}")
print("=" * 50)

checks = [
    check(
        "PostgreSQL Password",
        "POSTGRES_PASSWORD",
        required=True,
        how_to_get="Set any strong password"
    ),
    check(
        "JWT Secret Key",
        "JWT_SECRET_KEY",
        required=True,
        how_to_get="Run: openssl rand -hex 32"
    ),
    check(
        "Grafana Password",
        "GRAFANA_PASSWORD",
        required=True,
        how_to_get="Set any strong password"
    ),
    check(
        "Slack Webhook",
        "SLACK_WEBHOOK_URL",
        required=False,
        how_to_get="https://api.slack.com/apps → Create App → Incoming Webhooks"
    ),
    check(
        "VirusTotal API Key",
        "VIRUSTOTAL_API_KEY",
        required=False,
        how_to_get="https://www.virustotal.com → Sign up → API Key"
    ),
    check(
        "Shodan API Key",
        "SHODAN_API_KEY",
        required=False,
        how_to_get="https://account.shodan.io → API Key"
    ),
]

print("=" * 50)

if all(checks):
    print(f"\n{GREEN}{BOLD}✅ Configuration valid — ready to start{RESET}")
    print("Run: docker-compose up -d\n")
    sys.exit(0)
else:
    print(f"\n{RED}{BOLD}❌ Fix required fields before starting{RESET}\n")
    sys.exit(1)
