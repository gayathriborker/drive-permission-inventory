import os
import datetime
from typing import List, Dict, Any

import yaml
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# ========== CONFIG LOADING ==========

def load_config(path: str = None) -> Dict[str, Any]:
    config_path = path or os.environ.get("CONFIG_PATH", "config/workspace_config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ========== AUTH HELPERS ==========

def get_base_creds(service_account_file: str, scopes: List[str]):
    return service_account.Credentials.from_service_account_file(
        service_account_file,
        scopes=scopes,
    )


def get_directory_service(base_creds, delegated_admin: str):
    admin_creds = base_creds.with_subject(delegated_admin)
    return build("admin", "directory_v1", credentials=admin_creds)


def get_sheets_service(base_creds, delegated_admin: str):
    admin_creds = base_creds.with_subject(delegated_admin)
    return build("sheets", "v4", credentials=admin_creds)


def get_drive_service_for_subject(base_creds, subject_email: str):
    subject_creds = base_creds.with_subject(subject_email)
    return build("drive", "v3", credentials=subject_creds)


# ========== DIRECTORY HELPERS ==========

def get_all_active_users(directory_service, domain: str) -> List[str]:
    users: List[str] = []
    page_token = None

    while True:
        resp = directory_service.users().list(
            customer="my_customer",
            domain=domain,
            maxResults=200,
            pageToken=page_token,
            orderBy="email",
        ).execute()

        for u in resp.get("users", []):
            if not u.get("suspended", False):
                users.append(u["primaryEmail"].lower())

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return users


# ========== DRIVE HELPERS: MY DRIVE ==========

def list_files_in_user_mydrive(drive_service):
    """List files in a user's My Drive (excluding trashed)."""
    files = []
    page_token = None

    while True:
        resp = drive_service.files().list(
            q="trashed = false",
            spaces="drive",
            corpora="user",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            pageSize=1000,
            pageToken=page_token,
            fields="nextPageToken, files(id, name, mimeType, owners(emailAddress,displayName))",
        ).execute()

        files.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return files


# ========== DRIVE HELPERS: SHARED DRIVES ==========

def list_shared_drives(drive_service):
    drives = []
    page_token = None

    while True:
        resp = drive_service.drives().list(
            pageSize=100,
            pageToken=page_token,
            useDomainAdminAccess=True,
        ).execute()

        drives.extend(resp.get("drives", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return drives


def list_files_in_shared_drive(drive_service, drive_id: str):
    files = []
    page_token = None

    while True:
        resp = drive_service.files().list(
            corpora="drive",
            driveId=drive_id,
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            q="trashed = false",
            pageSize=1000,
            pageToken=page_token,
            fields="nextPageToken, files(id, name, mimeType, owners(emailAddress,displayName))",
            useDomainAdminAccess=True,
        ).execute()

        files.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return files


# ========== DRIVE HELPERS: PERMISSIONS ==========

def list_permissions_for_file(drive_service, file_id: str):
    perms = []
    page_token = None

    while True:
        resp = drive_service.permissions().list(
            fileId=file_id,
            supportsAllDrives=True,
            pageToken=page_token,
            fields="nextPageToken, permissions(id, type, role, emailAddress, domain)",
        ).execute()

        perms.extend(resp.get("permissions", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return perms


# ========== SHEETS HELPERS ==========

def clear_sheet(sheets_service, spreadsheet_id: str, sheet_name: str):
    range_all = f"{sheet_name}!A:Z"
    sheets_service.spreadsheets().values().clear(
        spreadsheetId=spreadsheet_id,
        range=range_all,
        body={},
    ).execute()


def write_rows_to_sheet(sheets_service, spreadsheet_id: str, sheet_name: str, rows):
    range_start = f"{sheet_name}!A1"
    body = {"values": rows}
    sheets_service.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id,
        range=range_start,
        valueInputOption="RAW",
        body=body,
    ).execute()


# ========== MAIN INVENTORY LOGIC ==========

def main():
    config = load_config()

    workspace_cfg = config.get("workspace", {})
    my_cfg = config.get("my_drives", {})
    shared_cfg = config.get("shared_drives", {})

    domain = workspace_cfg["domain"]
    delegated_admin = workspace_cfg["delegated_admin"]
    spreadsheet_id = workspace_cfg["spreadsheet_id"]
    sheet_name = workspace_cfg.get("sheet_name", "Inventory")
    scan_all_users = bool(workspace_cfg.get("scan_all_users", False))

    my_enabled = bool(my_cfg.get("enabled", True))
    users_to_scan_cfg = my_cfg.get("users_to_scan", [])

    shared_enabled = bool(shared_cfg.get("enabled", True))
    shared_include_all = bool(shared_cfg.get("include_all", True))
    shared_include_ids = shared_cfg.get("include_drive_ids", []) or []

    scopes = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/spreadsheets",
    ]

    service_account_file = os.environ.get("SERVICE_ACCOUNT_FILE", "service-account.json")

    base_creds = get_base_creds(service_account_file, scopes)
    directory_service = get_directory_service(base_creds, delegated_admin)
    sheets_service = get_sheets_service(base_creds, delegated_admin)

    # Determine active users for classification (internal vs external)
    active_users_set = set(get_all_active_users(directory_service, domain))
    print(f"Active users in domain: {len(active_users_set)}")

    # Determine My Drive users to scan
    if my_enabled:
        if scan_all_users:
            users_to_scan = list(active_users_set)
            print(f"MyDrive: scanning ALL active users: {len(users_to_scan)}")
        else:
            users_to_scan = [u.lower() for u in users_to_scan_cfg]
            print(f"MyDrive: scanning specific users: {users_to_scan}")
    else:
        users_to_scan = []
        print("MyDrive scanning disabled in config.")

    # Prepare rows with unified schema
    rows = []

    header = [
        "run_timestamp",
        "container_type",         # MyDrive / SharedDrive
        "container_owner_email",  # user email for MyDrive; empty for SharedDrive
        "shared_drive_id",
        "shared_drive_name",
        "file_id",
        "file_name",
        "file_url",
        "owner_email",
        "permission_email",
        "permission_role",
        "permission_type",
        "permission_domain",
        "internal_or_external",
    ]
    rows.append(header)

    run_ts = datetime.datetime.utcnow().isoformat()

    # ========== MY DRIVES INVENTORY ==========
    for user_email in users_to_scan:
        print(f"\n=== Scanning My Drive for: {user_email} ===")
        try:
            drive_service = get_drive_service_for_subject(base_creds, user_email)
        except HttpError as e:
            print(f"  !! Failed to create Drive service for {user_email}: {e}")
            continue

        try:
            files = list_files_in_user_mydrive(drive_service)
        except HttpError as e:
            print(f"  !! Failed to list files for {user_email}: {e}")
            continue

        print(f"  MyDrive files found: {len(files)}")

        for f in files:
            file_id = f["id"]
            file_name = f.get("name", "")
            owners = f.get("owners", [])
            owner_email = owners[0].get("emailAddress") if owners else ""
            file_url = f"https://drive.google.com/file/d/{file_id}/view"

            try:
                perms = list_permissions_for_file(drive_service, file_id)
            except HttpError as e:
                print(f"    !! Failed to list perms for file {file_id}: {e}")
                continue

            for p in perms:
                perm_type = p.get("type")
                perm_role = p.get("role")
                perm_email = (p.get("emailAddress") or "").lower()
                perm_domain = p.get("domain", "")

                if perm_type == "user" and perm_email:
                    internal_or_external = (
                        "internal" if perm_email in active_users_set else "external"
                    )
                elif perm_type == "domain":
                    internal_or_external = "domain"
                elif perm_type == "anyone":
                    internal_or_external = "anyone"
                else:
                    internal_or_external = ""

                row = [
                    run_ts,
                    "MyDrive",
                    user_email,      # container_owner_email
                    "",              # shared_drive_id
                    "",              # shared_drive_name
                    file_id,
                    file_name,
                    file_url,
                    owner_email,
                    perm_email,
                    perm_role,
                    perm_type,
                    perm_domain,
                    internal_or_external,
                ]
                rows.append(row)

    # ========== SHARED DRIVES INVENTORY ==========
    if shared_enabled:
        print("\n=== Scanning Shared Drives ===")
        admin_drive_service = get_drive_service_for_subject(base_creds, delegated_admin)

        try:
            shared_drives = list_shared_drives(admin_drive_service)
        except HttpError as e:
            print(f"  !! Failed to list shared drives: {e}")
            shared_drives = []

        if not shared_drives:
            print("  No shared drives found.")
        else:
            print(f"  Shared drives found: {len(shared_drives)}")

        # Filter shared drives if include_drive_ids is specified
        for d in shared_drives:
            drive_id = d["id"]
            drive_name = d.get("name", "")

            if shared_include_ids and drive_id not in shared_include_ids:
                continue
            if not shared_include_all and not shared_include_ids:
                # If include_all is false and no explicit IDs, you can add name-based logic here later
                continue

            print(f"  Scanning shared drive: {drive_name} ({drive_id})")

            try:
                files = list_files_in_shared_drive(admin_drive_service, drive_id)
            except HttpError as e:
                print(f"    !! Failed to list files for shared drive {drive_id}: {e}")
                continue

            print(f"    Files in shared drive: {len(files)}")

            for f in files:
                file_id = f["id"]
                file_name = f.get("name", "")
                owners = f.get("owners", [])
                owner_email = owners[0].get("emailAddress") if owners else ""
                file_url = f"https://drive.google.com/file/d/{file_id}/view"

                try:
                    perms = list_permissions_for_file(admin_drive_service, file_id)
                except HttpError as e:
                    print(f"      !! Failed to list perms for file {file_id}: {e}")
                    continue

                for p in perms:
                    perm_type = p.get("type")
                    perm_role = p.get("role")
                    perm_email = (p.get("emailAddress") or "").lower()
                    perm_domain = p.get("domain", "")

                    if perm_type == "user" and perm_email:
                        internal_or_external = (
                            "internal" if perm_email in active_users_set else "external"
                        )
                    elif perm_type == "domain":
                        internal_or_external = "domain"
                    elif perm_type == "anyone":
                        internal_or_external = "anyone"
                    else:
                        internal_or_external = ""

                    row = [
                        run_ts,
                        "SharedDrive",
                        "",            # container_owner_email
                        drive_id,
                        drive_name,
                        file_id,
                        file_name,
                        file_url,
                        owner_email,
                        perm_email,
                        perm_role,
                        perm_type,
                        perm_domain,
                        internal_or_external,
                    ]
                    rows.append(row)
    else:
        print("Shared Drives scanning disabled in config.")

    # ========== WRITE TO SHEET ==========
    print("\nClearing sheet and writing data...")
    clear_sheet(sheets_service, spreadsheet_id, sheet_name)
    write_rows_to_sheet(sheets_service, spreadsheet_id, sheet_name, rows)

    print(f"Done. Wrote {len(rows) - 1} permission rows to sheet {spreadsheet_id}")


if __name__ == "__main__":
    main()

