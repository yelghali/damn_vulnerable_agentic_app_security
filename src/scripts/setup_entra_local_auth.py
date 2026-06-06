"""Create real Entra users and a localhost auth app for Zava lab testing.

This script intentionally uses Microsoft Graph and Azure RBAC through the signed-in
Azure CLI identity. It creates:
  * one public-client app registration for localhost PKCE login;
  * app roles matching Zava authorization groups;
    * learner users (user_1, user_2, ... by default);
    * an optional zava_manager account for elevated lab operations;
  * app-role assignments so ID tokens contain roles like retail-customers.
    * optional lab resource-group RBAC so users can inspect the Azure setup.

The generated password file is ignored by git. Treat it as sensitive and delete
it when the lab is done.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.scripts.setup_lab_users import CONTENT_GROUPS, MANAGER_GROUP, MANAGER_USER_ID, LabUser, build_users


ROLE_IDS = {
    "retail-customers": "11111111-1111-4111-8111-111111111111",
    "private-client": "22222222-2222-4222-8222-222222222222",
    "zava-managers": "33333333-3333-4333-8333-333333333333",
}


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


def _graph_post(url: str, body: dict[str, Any]) -> Any:
    return _json(["rest", "--method", "POST", "--url", url, "--body", "@-"], input_json=body)


def _graph_patch(url: str, body: dict[str, Any]) -> None:
    _run(["rest", "--method", "PATCH", "--url", url, "--body", "@-", "-o", "none"], input_json=body)


def _role_payload() -> list[dict[str, Any]]:
    payload = []
    for role in (*CONTENT_GROUPS, MANAGER_GROUP):
        payload.append(
            {
                "allowedMemberTypes": ["User"],
                "description": f"Zava lab role {role}",
                "displayName": role,
                "id": ROLE_IDS[role],
                "isEnabled": True,
                "value": role,
            }
        )
    return payload


def _validate_password(password: str) -> None:
    checks = (
        len(password) >= 8,
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(char in "!#$%*-_+=" for char in password),
    )
    if not all(checks):
        raise SystemExit(
            "Password template must produce at least 8 characters with upper, lower, digit, and special characters."
        )


def _password_from_template(template: str, user: LabUser, index: int) -> str:
    try:
        password = template.format(index=index, user_id=user.user_id, safe_user_id=user.user_id.replace("_", "-"))
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"Invalid --password-template: {exc}") from exc
    _validate_password(password)
    return password


def _assert_generated_zava_user(user: LabUser) -> None:
    if user.user_id == "admin" or user.upn.lower().startswith("admin@"):
        raise SystemExit(f"Refusing to create or modify admin account '{user.upn}'. This script manages Zava lab users only.")
    if user.is_manager and user.user_id != MANAGER_USER_ID:
        raise SystemExit(f"Refusing unexpected manager account '{user.upn}'. Expected {MANAGER_USER_ID} only.")
    if not user.is_manager and not user.user_id.startswith("user_"):
        raise SystemExit(f"Refusing non-learner lab account '{user.upn}'. Expected user_N or {MANAGER_USER_ID}.")


def _assert_existing_user_is_zava_lab_user(user: LabUser, graph_user: dict[str, Any]) -> None:
    display_name = str(graph_user.get("displayName") or "")
    upn = str(graph_user.get("userPrincipalName") or user.upn).lower()
    expected_upn = user.upn.lower()
    if upn != expected_upn or not display_name.startswith("Zava "):
        raise SystemExit(
            "Refusing to modify existing non-Zava user "
            f"'{graph_user.get('userPrincipalName', user.upn)}'. "
            "Use a generated Zava learner account such as user_1/user_2."
        )


def ensure_app(display_name: str, redirect_uris: list[str]) -> dict[str, Any]:
    existing = _graph_get(
        "https://graph.microsoft.com/v1.0/applications?"
        f"$filter=displayName eq '{display_name}'&$select=id,appId,displayName"
    )["value"]
    app = existing[0] if existing else _graph_post(
        "https://graph.microsoft.com/v1.0/applications",
        {
            "displayName": display_name,
            "signInAudience": "AzureADMyOrg",
            "isFallbackPublicClient": True,
            "publicClient": {"redirectUris": redirect_uris},
            "appRoles": _role_payload(),
        },
    )
    _graph_patch(
        f"https://graph.microsoft.com/v1.0/applications/{app['id']}",
        {
            "isFallbackPublicClient": True,
            "publicClient": {"redirectUris": redirect_uris},
            "appRoles": _role_payload(),
        },
    )
    service_principals = _graph_get(
        "https://graph.microsoft.com/v1.0/servicePrincipals?"
        f"$filter=appId eq '{app['appId']}'&$select=id,appId,displayName"
    )["value"]
    if service_principals:
        sp = service_principals[0]
    else:
        sp = _graph_post("https://graph.microsoft.com/v1.0/servicePrincipals", {"appId": app["appId"]})
    return {"app": app, "servicePrincipal": sp}


def ensure_user(user: LabUser, password: str, reset_password: bool) -> tuple[dict[str, Any], bool]:
    _assert_generated_zava_user(user)
    existing = _graph_get(
        "https://graph.microsoft.com/v1.0/users?"
        f"$filter=userPrincipalName eq '{user.upn}'&$select=id,userPrincipalName,displayName"
    )["value"]
    if existing:
        graph_user = existing[0]
        _assert_existing_user_is_zava_lab_user(user, graph_user)
        if reset_password:
            _graph_patch(
                f"https://graph.microsoft.com/v1.0/users/{graph_user['id']}",
                {"passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False}},
            )
        return graph_user, reset_password
    graph_user = _graph_post(
        "https://graph.microsoft.com/v1.0/users",
        {
            "accountEnabled": True,
            "displayName": "Zava Manager" if user.is_manager else f"Zava {user.user_id.replace('_', ' ').title()}",
            "mailNickname": user.user_id.replace("_", ""),
            "userPrincipalName": user.upn,
            "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
        },
    )
    return graph_user, True


def ensure_assignment(sp_id: str, principal_id: str, role: str) -> None:
    role_id = ROLE_IDS[role]
    existing = _graph_get(
        f"https://graph.microsoft.com/v1.0/users/{principal_id}/appRoleAssignments?"
        f"$filter=resourceId eq {sp_id}"
    )["value"]
    if any(item.get("appRoleId") == role_id for item in existing):
        return
    _graph_post(
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignedTo",
        {"principalId": principal_id, "resourceId": sp_id, "appRoleId": role_id},
    )


def _subscription_id() -> str:
    return _json(["account", "show", "--query", "id"])


def _resource_group_scope(subscription_id: str, resource_group: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"


def _list_resources(resource_group: str, resource_type: str) -> list[dict[str, Any]]:
    return _json(["resource", "list", "--resource-group", resource_group, "--resource-type", resource_type]) or []


def _role_exists(role: str) -> bool:
    return bool(_json(["role", "definition", "list", "--name", role]))


def ensure_azure_role_assignment(principal_id: str, role: str, scope: str) -> bool:
    if not _role_exists(role):
        print(f"Skipping Azure RBAC role '{role}' because it is not available in this cloud/tenant.", file=sys.stderr)
        return False
    existing = _json(["role", "assignment", "list", "--assignee", principal_id, "--role", role, "--scope", scope])
    if existing:
        return True
    _run(
        [
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            principal_id,
            "--assignee-principal-type",
            "User",
            "--role",
            role,
            "--scope",
            scope,
            "-o",
            "none",
        ]
    )
    return True


def ensure_lab_azure_rbac(principal_id: str, resource_group: str, *, elevated: bool = False) -> list[dict[str, str]]:
    subscription_id = _subscription_id()
    rg_scope = _resource_group_scope(subscription_id, resource_group)
    assignments: list[dict[str, str]] = []

    default_assignments = [
        ("Reader", rg_scope, "View only the lab resource group in Azure Portal."),
    ]
    if elevated:
        cognitive_accounts = _list_resources(resource_group, "Microsoft.CognitiveServices/accounts")
        for account in cognitive_accounts:
            default_assignments.extend(
                [
                    (
                        "Azure AI Developer",
                        account["id"],
                        "Use Azure AI Foundry project/deployment assets and adjust lab guardrail setup.",
                    ),
                    (
                        "Cognitive Services Contributor",
                        account["id"],
                        "Manage Foundry/Azure AI guardrail and deployment configuration without subscription-wide access.",
                    ),
                ]
            )

    search_services = _list_resources(resource_group, "Microsoft.Search/searchServices")
    for service in search_services:
        default_assignments.append(
            ("Search Index Data Reader", service["id"], "Inspect AI Search index data used by RAG without editing indexes.")
        )

    for role, scope, reason in default_assignments:
        if ensure_azure_role_assignment(principal_id, role, scope):
            assignments.append({"role": role, "scope": scope, "reason": reason})
    return assignments


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Entra local-login users/app for Zava.")
    parser.add_argument("--tenant-domain", required=True)
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--prefix", default="user")
    parser.add_argument("--app-display-name", default="Zava Local Lab Auth")
    parser.add_argument("--redirect-uri", action="append", default=["http://127.0.0.1:8003/auth/callback"])
    parser.add_argument("--credentials-file", default=".zava-lab-users.local.json")
    parser.add_argument("--reset-passwords", action="store_true")
    parser.add_argument(
        "--password-template",
        default="ZavaLab!{index:02d}",
        help="Lab password template. Available fields: {index}, {user_id}, {safe_user_id}.",
    )
    parser.add_argument(
        "--resource-group",
        default="",
        help="Optional lab resource group. When set, assigns constrained Azure Portal RBAC to each Zava lab user.",
    )
    parser.add_argument(
        "--skip-azure-rbac",
        action="store_true",
        help="Do not assign Azure RBAC even when --resource-group is provided.",
    )
    parser.add_argument(
        "--skip-manager",
        action="store_true",
        help="Do not create the zava_manager account. By default it is created for elevated lab setup tasks.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    users = build_users(
        args.count,
        args.prefix,
        args.tenant_domain,
        group_assignment="round-robin",
        include_manager=not args.skip_manager,
    )
    app_info = ensure_app(args.app_display_name, args.redirect_uri)
    sp_id = app_info["servicePrincipal"]["id"]
    credentials: list[dict[str, Any]] = []
    for index, user in enumerate(users, start=1):
        password = _password_from_template(args.password_template, user, index)
        graph_user, password_applied = ensure_user(user, password, args.reset_passwords)
        for role in user.assigned_groups:
            ensure_assignment(sp_id, graph_user["id"], role)
        azure_rbac = []
        if args.resource_group and not args.skip_azure_rbac:
            azure_rbac = ensure_lab_azure_rbac(graph_user["id"], args.resource_group, elevated=user.is_manager)
        credentials.append(
            asdict(user)
            | {
                "object_id": graph_user["id"],
                "password": password if password_applied else None,
                "password_applied": password_applied,
                "password_reset": bool(args.reset_passwords and password_applied),
                "azure_rbac": azure_rbac,
            }
        )
    output = {
        "tenant_domain": args.tenant_domain,
        "app_display_name": args.app_display_name,
        "client_id": app_info["app"]["appId"],
        "service_principal_id": sp_id,
        "redirect_uris": args.redirect_uri,
        "resource_group": args.resource_group or None,
        "users": credentials,
        "env": {
            "AZURE_TENANT_ID": _json(["account", "show", "--query", "tenantId"]),
            "ENTRA_API_CLIENT_ID": app_info["app"]["appId"],
            "ENTRA_REDIRECT_URI": args.redirect_uri[0],
        },
    }
    path = Path(args.credentials_file)
    path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({k: output[k] for k in ("client_id", "service_principal_id", "redirect_uris", "env")}, indent=2))
    print(f"Wrote sensitive lab credentials to {path}. This file is git-ignored; delete it after testing.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
