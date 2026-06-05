"""Generate workshop cohort user mappings.

The lab keeps expensive services shared, then gives each participant their own
mutable Foundry project, APIM API path, app URL, Search groups, and PostgreSQL
owner id. This helper emits the mapping used by docs, Terraform outputs, and
the instructor's Entra setup.

Examples:
  python -m src.scripts.setup_lab_users
  python -m src.scripts.setup_lab_users --count 60 --tenant-domain contoso.onmicrosoft.com --format csv
  python -m src.scripts.setup_lab_users --count 2 --emit-az-cli
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class LabUser:
    user_id: str
    upn: str
    customer_id: str
    owner_user_id: str
    retail_group: str
    private_group: str
    apim_gateway_base_path: str
    apim_openai_path: str


def build_users(count: int, prefix: str, tenant_domain: str) -> list[LabUser]:
    users: list[LabUser] = []
    for index in range(1, count + 1):
        user_id = f"{prefix}_{index}"
        safe_id = user_id.replace("_", "-")
        users.append(
            LabUser(
                user_id=user_id,
                upn=f"{user_id}@{tenant_domain}" if tenant_domain else user_id,
                customer_id=f"CUST-{index:04d}",
                owner_user_id=user_id,
                retail_group=f"zava-{user_id}-retail",
                private_group=f"zava-{user_id}-private",
                apim_gateway_base_path=f"/{safe_id}",
                apim_openai_path=f"/{safe_id}/openai",
            )
        )
    return users


def emit_json(users: list[LabUser]) -> None:
    print(json.dumps([asdict(user) for user in users], indent=2))


def emit_csv(users: list[LabUser]) -> None:
    writer = csv.DictWriter(sys.stdout, fieldnames=list(asdict(users[0]).keys()))
    writer.writeheader()
    for user in users:
        writer.writerow(asdict(user))


def emit_az_cli(users: list[LabUser]) -> None:
    print("# Review before running. Requires Microsoft Graph permissions to create users/groups.")
    for user in users:
        display = user.user_id.replace("_", " ").title()
        print(f"az ad user create --display-name \"Zava {display}\" --user-principal-name {user.upn} --password <TEMP_PASSWORD> --force-change-password-next-sign-in true")
        print(f"az ad group create --display-name {user.retail_group} --mail-nickname {user.retail_group}")
        print(f"az ad group create --display-name {user.private_group} --mail-nickname {user.private_group}")
        print(f"az ad group member add --group {user.retail_group} --member-id $(az ad user show --id {user.upn} --query id -o tsv)")
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Zava cohort user mappings.")
    parser.add_argument("--count", type=int, default=2, help="Number of users to generate.")
    parser.add_argument("--prefix", default="user", help="Generated user prefix, e.g. user -> user_1.")
    parser.add_argument("--tenant-domain", default="example.onmicrosoft.com", help="Tenant domain for generated UPNs.")
    parser.add_argument("--format", choices=("json", "csv"), default="json", help="Mapping output format.")
    parser.add_argument("--emit-az-cli", action="store_true", help="Also print Azure CLI commands to create Entra users/groups.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.count < 1 or args.count > 100:
        raise SystemExit("--count must be between 1 and 100.")
    users = build_users(args.count, args.prefix, args.tenant_domain)
    if args.format == "csv":
        emit_csv(users)
    else:
        emit_json(users)
    if args.emit_az_cli:
        print()
        emit_az_cli(users)


if __name__ == "__main__":
    main()