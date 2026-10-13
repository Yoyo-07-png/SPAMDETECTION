from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = [
    "https://mail.google.com/"
]

AUTH_DIR = Path(__file__).resolve().parent
TOKEN_DIR = AUTH_DIR / "token files"


def create_service(client_secret_file, api_name, api_version, prefix=""):
    client_secret_path = Path(client_secret_file).expanduser()
    if not client_secret_path.is_absolute():
        client_secret_path = AUTH_DIR / client_secret_path

    if not client_secret_path.is_file():
        raise FileNotFoundError(f"Google client secret file not found: {client_secret_path}")

    creds = None
    token_file = TOKEN_DIR / f"token_{api_name}_{api_version}{prefix}.json"
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)

    if token_file.is_file():
        creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), SCOPES)
            creds = flow.run_local_server(port=0)

    with token_file.open("w", encoding="utf-8") as token:
        token.write(creds.to_json())

    return build(api_name, api_version, credentials=creds, static_discovery=False)


def main():
    create_service("client_secret.json", "gmail", "v1")


if __name__ == "__main__":
    main()
    