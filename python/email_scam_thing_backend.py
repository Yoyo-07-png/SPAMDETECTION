import os
from dotenv import load_dotenv


from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from services.scanner import BodyScanner, HeaderScanner

load_dotenv()
MAX_EMAIL_SIZE = 10 * 1024 * 1024
extension_origins = [
    origin.strip()
    for origin in os.environ.get("CHROME_EXTENSION_ORIGINS", "").split(",")
    if origin.strip()
]

app = FastAPI(title="SPAMDETECTION Email Analysis API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=extension_origins,
    allow_methods=["POST"],
    allow_headers=["*"],
)


@app.post("/analyze")
async def analyze_email(eml: UploadFile = File(...)):
    raw_email = await eml.read(MAX_EMAIL_SIZE + 1)
    await eml.close()

    if not raw_email:
        raise HTTPException(status_code=400, detail="The uploaded EML file is empty.")
    if len(raw_email) > MAX_EMAIL_SIZE:
        raise HTTPException(status_code=413, detail="The EML file exceeds the 10 MiB limit.")

    header_scanner = HeaderScanner(raw_email)
    header_scanner.extract_email()
    if not header_scanner.email or not header_scanner.email.get("From"):
        raise HTTPException(
            status_code=422,
            detail="The uploaded file could not be parsed as an email with a From header.",
        )

    header_scanner.do_header_check()
    header_score = header_scanner.get_header_score()
    if isinstance(header_score, str):
        raise HTTPException(status_code=422, detail=header_score)

    body_scanner = BodyScanner(raw_email)
    body_scanner.extract_email()
    body_scanner.helper_get_subject()
    body_scanner.helper_get_body()

    return {
        "filename": eml.filename or "email.eml",
        "subject": body_scanner.subject or header_scanner.email.get("Subject", "(No subject)"),
        "header_score": header_score,
        "header_details": header_scanner.details,
        "body_analysis": body_scanner.get_model_analysis(),
    }
