"""Generate workshop cohort user mappings.

The lab keeps expensive services shared, then gives each participant their own
mutable Foundry project, APIM API path, app URL, Search groups, and PostgreSQL
owner id. This helper emits the mapping used by docs, Terraform outputs, and
the instructor's Entra setup.

Examples:
  python -m src.scripts.setup_lab_users
  python -m src.scripts.setup_lab_users --count 60 --tenant-domain contoso.onmicrosoft.com --format csv
  python -m src.scripts.setup_lab_users --count 2 --emit-az-cli
    python -m src.scripts.setup_lab_users --count 2 --emit-az-cli --group-assignment round-robin
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from dataclasses import asdict, dataclass


CONTENT_GROUPS = ("retail-customers", "private-client")
ADMIN_GROUP = "zava-admins"


@dataclass(frozen=True)
class LabUser:
    user_id: str
    upn: str
    customer_id: str
    owner_user_id: str
    retail_group: str
    private_group: str
    assigned_groups: list[str]
    is_admin: bool
    apim_gateway_base_path: str
    apim_openai_path: str


def _assigned_groups(index: int, mode: str, rng: random.Random) -> list[str]:
    if mode == "all-retail":
        return ["retail-customers"]
    if mode == "random":
        return [rng.choice(CONTENT_GROUPS)]
    return [CONTENT_GROUPS[(index - 1) % len(CONTENT_GROUPS)]]


def build_users(count: int, prefix: str, tenant_domain: str, group_assignment: str = "round-robin", seed: int = 42) -> list[LabUser]:
    users: list[LabUser] = []
    rng = random.Random(seed)
    for index in range(1, count + 1):
        user_id = f"{prefix}_{index}"
        safe_id = user_id.replace("_", "-")
        users.append(
            LabUser(
                user_id=user_id,
                upn=f"{user_id}@{tenant_domain}" if tenant_domain else user_id,
                customer_id=f"CUST-{1000 + index}",
                owner_user_id=user_id,
                retail_group=f"zava-{user_id}-retail",
                private_group=f"zava-{user_id}-private",
                assigned_groups=_assigned_groups(index, group_assignment, rng),
                is_admin=False,
                apim_gateway_base_path=f"/{safe_id}",
                apim_openai_path=f"/{safe_id}/openai",
            )
        )
    users.append(
        LabUser(
            user_id="admin",
            upn=f"admin@{tenant_domain}" if tenant_domain else "admin",
            customer_id="*",
            owner_user_id="admin",
            retail_group="zava-admin-retail",
            private_group="zava-admin-private",
            assigned_groups=[*CONTENT_GROUPS, ADMIN_GROUP],
            is_admin=True,
            apim_gateway_base_path="/admin",
            apim_openai_path="/admin/openai",
        )
    )
    return users


def emit_json(users: list[LabUser]) -> None:
    print(json.dumps([asdict(user) for user in users], indent=2))


def emit_csv(users: list[LabUser]) -> None:
    rows = [asdict(user) | {"assigned_groups": ",".join(user.assigned_groups)} for user in users]
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


def emit_az_cli(users: list[LabUser], private_users: set[str]) -> None:
    print("# Review before running. Requires Microsoft Graph permissions to create users/groups.")
    print("# Learners are added to content groups used by AI Search group_ids. Admin is added to every content group plus zava-admins.")
    group_vars: dict[str, str] = {}
    for group in (*CONTENT_GROUPS, ADMIN_GROUP):
        var = group.replace("-", "_") + "_group_id"
        group_vars[group] = var
        print(f"${var} = az ad group create --display-name {group} --mail-nickname {group} --query id -o tsv")
    print()
    for user in users:
        display = user.user_id.replace("_", " ").title()
        user_var = f"{user.user_id}_id".replace("-", "_")
        retail_var = f"{user.user_id}_retail_group_id".replace("-", "_")
        private_var = f"{user.user_id}_private_group_id".replace("-", "_")
        print(f"az ad user create --display-name \"Zava {display}\" --user-principal-name {user.upn} --password <TEMP_PASSWORD> --force-change-password-next-sign-in true")
        print(f"${user_var} = az ad user show --id {user.upn} --query id -o tsv")
        print(f"${retail_var} = az ad group create --display-name {user.retail_group} --mail-nickname {user.retail_group} --query id -o tsv")
        print(f"${private_var} = az ad group create --display-name {user.private_group} --mail-nickname {user.private_group} --query id -o tsv")
        print(f"az ad group member add --group ${retail_var} --member-id ${user_var}")
        if user.user_id in private_users or user.is_admin:
            print(f"az ad group member add --group ${private_var} --member-id ${user_var}")
        else:
            print(f"# Optional private-doc access: az ad group member add --group ${private_var} --member-id ${user_var}")
        for group in user.assigned_groups:
            print(f"az ad group member add --group ${group_vars[group]} --member-id ${user_var}")
        print()


def parse_private_users(value: str, users: list[LabUser]) -> set[str]:
    if not value:
        return set()
    requested = {item.strip() for item in value.split(",") if item.strip()}
    valid = {user.user_id for user in users}
    if requested == {"all"}:
        return valid
    unknown = requested - valid
    if unknown:
        raise SystemExit(f"Unknown --private-users value(s): {', '.join(sorted(unknown))}.")
    return requested


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Zava cohort user mappings.")
    parser.add_argument("--count", type=int, default=2, help="Number of users to generate.")
    parser.add_argument("--prefix", default="user", help="Generated user prefix, e.g. user -> user_1.")
    parser.add_argument("--tenant-domain", default="example.onmicrosoft.com", help="Tenant domain for generated UPNs.")
    parser.add_argument("--format", choices=("json", "csv"), default="json", help="Mapping output format.")
    parser.add_argument("--group-assignment", choices=("round-robin", "random", "all-retail"), default="round-robin", help="How learner content groups are assigned for AI Search ACL demos.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed when --group-assignment=random.")
    parser.add_argument("--emit-az-cli", action="store_true", help="Also print Azure CLI commands to create Entra users/groups.")
    parser.add_argument(
        "--private-users",
        default="",
        help="Comma-separated generated user IDs, or 'all', to also add to their private group in emitted Azure CLI.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.count < 1 or args.count > 100:
        raise SystemExit("--count must be between 1 and 100.")
    users = build_users(args.count, args.prefix, args.tenant_domain, args.group_assignment, args.seed)
    if args.format == "csv":
        emit_csv(users)
    else:
        emit_json(users)
    if args.emit_az_cli:
        print()
        emit_az_cli(users, parse_private_users(args.private_users, users))


if __name__ == "__main__":
    main()