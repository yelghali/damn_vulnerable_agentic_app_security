"""Delete generated Zava Entra lab users after a workshop.

This script intentionally refuses to delete tenant admin accounts or arbitrary
users. It only targets generated Zava learner users such as user_1/user_2 and
the zava_manager lab account whose Entra display name starts with "Zava ". Use
--yes to perform deletion.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from src.scripts.setup_lab_users import MANAGER_USER_ID, build_users


def _az() -> str:
    found = shutil.which("az")
    if found:
        return found
    windows = Path(r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd")
    if windows.exists():
        return str(windows)
    raise SystemExit("Azure CLI not found. Install Azure CLI or add az to PATH.")


def _run(args: list[str], *, input_json: dict[str, Any] | None = None) -> str:
    cmd = [_az(), *args]
    kwargs: dict[str, Any] = {"text": True, "capture_output": True}
    if input_json is not None:
        kwargs["input"] = json.dumps(input_json)
    proc = subprocess.run(cmd, **kwargs)  # noqa: S603 - controlled az invocation
    if proc.returncode != 0:
        raise SystemExit(f"Command failed: {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc.stdout.strip()


def _json(args: list[str], *, input_json: dict[str, Any] | None = None) -> Any:
    out = _run([*args, "-o", "json"], input_json=input_json)
    return json.loads(out) if out else None


def _graph_get(url: str) -> Any:
    return _json(["rest", "--method", "GET", "--url", url])


def _graph_delete(url: str) -> None:
    _run(["rest", "--method", "DELETE", "--url", url, "-o", "none"])


def _is_generated_zava_upn(upn: str, prefix: str, tenant_domain: str, *, include_manager: bool = True) -> bool:
    normalized = upn.lower()
    learner_pattern = rf"^{re.escape(prefix)}_\d+@{re.escape(tenant_domain)}$"
    manager_upn = f"{MANAGER_USER_ID}@{tenant_domain}".lower()
    return bool(re.fullmatch(learner_pattern, normalized)) or bool(include_manager and normalized == manager_upn)


def _load_target_upns(args: argparse.Namespace) -> list[str]:
    credentials_path = Path(args.credentials_file)
    if credentials_path.exists():
        data = json.loads(credentials_path.read_text(encoding="utf-8"))
        users = data.get("users", [])
        return [
            str(user["upn"])
            for user in users
            if not user.get("is_admin") and _is_generated_zava_upn(str(user.get("upn", "")), args.prefix, args.tenant_domain)
        ]
    return [
        user.upn
        for user in build_users(args.count, args.prefix, args.tenant_domain, include_manager=not args.skip_manager)
    ]


def _get_user(upn: str) -> dict[str, Any] | None:
    result = _graph_get(
        "https://graph.microsoft.com/v1.0/users?"
        f"$filter=userPrincipalName eq '{upn}'&$select=id,userPrincipalName,displayName"
    )
    values = result.get("value", [])
    return values[0] if values else None


def _assert_safe_to_delete(user: dict[str, Any], prefix: str, tenant_domain: str) -> None:
    upn = str(user.get("userPrincipalName", "")).lower()
    display_name = str(user.get("displayName", ""))
    if upn.startswith("admin@"):
        raise SystemExit(f"Refusing to delete admin account '{upn}'.")
    if not _is_generated_zava_upn(upn, prefix, tenant_domain) or not display_name.startswith("Zava "):
        raise SystemExit(f"Refusing to delete non-Zava lab user '{upn}'.")


def _delete_role_assignments(principal_id: str) -> int:
    assignments = _json(["role", "assignment", "list", "--assignee", principal_id]) or []
    for assignment in assignments:
        _run(["role", "assignment", "delete", "--ids", assignment["id"], "-o", "none"])
    return len(assignments)


def _delete_auth_app(display_name: str) -> dict[str, int]:
    if not display_name.startswith("Zava "):
        raise SystemExit("Refusing to delete an app registration that does not start with 'Zava '.")
    apps = _graph_get(
        "https://graph.microsoft.com/v1.0/applications?"
        f"$filter=displayName eq '{display_name}'&$select=id,appId,displayName"
    )["value"]
    deleted_apps = 0
    deleted_sps = 0
    for app in apps:
        service_principals = _graph_get(
            "https://graph.microsoft.com/v1.0/servicePrincipals?"
            f"$filter=appId eq '{app['appId']}'&$select=id,appId,displayName"
        )["value"]
        for service_principal in service_principals:
            _graph_delete(f"https://graph.microsoft.com/v1.0/servicePrincipals/{service_principal['id']}")
            deleted_sps += 1
        _graph_delete(f"https://graph.microsoft.com/v1.0/applications/{app['id']}")
        deleted_apps += 1
    return {"applications": deleted_apps, "service_principals": deleted_sps}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Delete generated Zava Entra lab users.")
    parser.add_argument("--tenant-domain", required=True)
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--prefix", default="user")
    parser.add_argument("--credentials-file", default=".zava-lab-users.local.json")
    parser.add_argument("--app-display-name", default="Zava Local Lab Auth")
    parser.add_argument("--delete-app", action="store_true", help="Also delete the Zava local auth app registration/service principal.")
    parser.add_argument("--delete-credentials-file", action="store_true", help="Delete the local git-ignored credentials JSON after cleanup.")
    parser.add_argument("--skip-manager", action="store_true", help="Do not include zava_manager in the cleanup target list.")
    parser.add_argument("--yes", action="store_true", help="Actually delete users. Without this, prints a plan only.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target_upns = _load_target_upns(args)
    plan = {"users": target_upns, "delete_app": bool(args.delete_app), "credentials_file": args.credentials_file}
    if not args.yes:
        print(json.dumps({"dry_run": True, "plan": plan}, indent=2))
        print("Re-run with --yes to delete these generated Zava lab users.")
        return

    deleted_users = 0
    deleted_role_assignments = 0
    for upn in target_upns:
        graph_user = _get_user(upn)
        if not graph_user:
            continue
        _assert_safe_to_delete(graph_user, args.prefix, args.tenant_domain)
        deleted_role_assignments += _delete_role_assignments(graph_user["id"])
        _graph_delete(f"https://graph.microsoft.com/v1.0/users/{graph_user['id']}")
        deleted_users += 1

    deleted_app = _delete_auth_app(args.app_display_name) if args.delete_app else {"applications": 0, "service_principals": 0}
    credentials_path = Path(args.credentials_file)
    if args.delete_credentials_file and credentials_path.exists():
        credentials_path.unlink()

    print(
        json.dumps(
            {
                "deleted_users": deleted_users,
                "deleted_azure_role_assignments": deleted_role_assignments,
                "deleted_app": deleted_app,
                "deleted_credentials_file": bool(args.delete_credentials_file and not credentials_path.exists()),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)