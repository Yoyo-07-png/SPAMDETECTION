from fastapi import APIRouter
from email.utils import parsedate_to_datetime
from auth.google_auth import create_service

from services.scanner import HeaderScanner
gmail_router = APIRouter()


def init_gmail_service(client_file, api_name="gmail", api_version="v1"):
    return create_service(client_file, api_name, api_version)

def helper_get_emails(service):
    msg_ids = service.users().messages().list(userId='me',
                                        maxResults=1,).execute()
    messages = msg_ids.get("messages", [])
    return messages

    
@gmail_router.get("/email/{email_id}")
async def read_email_test(email_id: str):
    
    try:
        service = init_gmail_service("client_secret.json")
        
        
        last_msgs = helper_get_emails(service)
        
        current_emails = []
        for msg in last_msgs:
            msg_data = service.users().messages().get(
                userId="me",
                id=msg["id"],
                format="raw"
            ).execute()

            current_emails.append(msg_data)            
        
        scanner = HeaderScanner(current_emails[0]["raw"])
        scanner.extract_email()
        
        check1 = scanner.check_authentication_results()
        check2 = scanner.check_received()
        check3 = scanner.check_domain_alignment()
        
        scanner.do_header_check()
        results = scanner.get_header_score()
        
        details = scanner.details
        
        return [check1, check2, check3, details, results]
    
    except Exception as e:
        return f"something went wrong: {e}"