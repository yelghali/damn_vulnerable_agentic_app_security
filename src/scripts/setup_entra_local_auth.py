"""Create real Entra users and a localhost auth app for Zava lab testing.

This script intentionally uses Microsoft Graph through the signed-in Azure CLI
identity. It creates:
  * one public-client app registration for localhost PKCE login;
  * app roles matching Zava authorization groups;
  * learner/admin users;
  * app-role assignments so ID tokens contain roles like retail-customers.

The generated password file is ignored by git. Treat it as sensitive and delete
it when the lab is done.
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import string
import subprocess
import sys
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.scripts.setup_lab_users import ADMIN_GROUP, CONTENT_GROUPS, LabUser, build_users


ROLE_IDS = {
    "retail-customers": "11111111-1111-4111-8111-111111111111",
    "private-client": "22222222-2222-4222-8222-222222222222",
    "zava-admins": "33333333-3333-4333-8333-333333333333",
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
    for role in (*CONTENT_GROUPS, ADMIN_GROUP):
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


def _password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!#$%*-_+="
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all((any(c.islower() for c in candidate), any(c.isupper() for c in candidate), any(c.isdigit() for c in candidate), any(c in "!#$%*-_+=" for c in candidate))):
            return candidate


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


def ensure_user(user: LabUser, password: str, reset_password: bool) -> dict[str, Any]:
    existing = _graph_get(
        "https://graph.microsoft.com/v1.0/users?"
        f"$filter=userPrincipalName eq '{user.upn}'&$select=id,userPrincipalName,displayName"
    )["value"]
    if existing:
        graph_user = existing[0]
        if reset_password:
            _graph_patch(
                f"https://graph.microsoft.com/v1.0/users/{graph_user['id']}",
                {"passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False}},
            )
        return graph_user
    return _graph_post(
        "https://graph.microsoft.com/v1.0/users",
        {
            "accountEnabled": True,
            "displayName": f"Zava {user.user_id.replace('_', ' ').title()}",
            "mailNickname": user.user_id.replace("_", ""),
            "userPrincipalName": user.upn,
            "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
        },
    )


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
        "--include-admin",
        action="store_true",
        help="Also create a lab admin user. By default this is skipped to avoid colliding with tenant admin accounts.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    users = build_users(args.count, args.prefix, args.tenant_domain, group_assignment="round-robin")
    if not args.include_admin:
        users = [user for user in users if not user.is_admin]
    app_info = ensure_app(args.app_display_name, args.redirect_uri)
    sp_id = app_info["servicePrincipal"]["id"]
    credentials: list[dict[str, Any]] = []
    for user in users:
        password = _password()
        graph_user = ensure_user(user, password, args.reset_passwords)
        for role in user.assigned_groups:
            ensure_assignment(sp_id, graph_user["id"], role)
        credentials.append(
            asdict(user)
            | {
                "object_id": graph_user["id"],
                "password": password,
                "password_reset": args.reset_passwords,
            }
        )
    output = {
        "tenant_domain": args.tenant_domain,
        "app_display_name": args.app_display_name,
        "client_id": app_info["app"]["appId"],
        "service_principal_id": sp_id,
        "redirect_uris": args.redirect_uri,
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
