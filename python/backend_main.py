from fastapi import FastAPI
from auth import google_auth

from routers.gmail_router import gmail_router

fast = FastAPI(
    
)

fast.include_router(gmail_router)