from typing import List
from fastapi import FastAPI, HTTPException, Query, Depends, Request, status
from fastapi.responses import JSONResponse
from jwt import PyJWTError
import jwt
from more_itertools import consume
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import requests
import os
import json
import base64
import uuid
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from models import Swipe, User, Transaction, Points
from models.database import SessionLocal
from decouple import config
import logging
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv

# === Load Environment Variables ===
load_dotenv()

# === App Initialization and Middleware ===
app = FastAPI()

user_service_url = os.getenv("USER_SERVICE_URL")
composite_service_url = os.getenv("COMPOSITE_SERVICE_URL")

# Correlation ID Middleware
class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cor_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        correlation_id.set(cor_id)

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cor_id
        return response
    
# Authorization Middleware
class AuthorizationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cor_id = correlation_id.get()
        logger.info(f"CorrelationID: {cor_id} | Headers: {dict(request.headers)}")

        # Public paths that don't require authentication
        # public_paths = ["/", "/docs", "/openapi.json", "/login", "/admin/users", "/admin/update-user"] # DELETE LAST PATH, USED FOR TESTING PURPOSES
        # public_paths = ["*"]
        public_paths = ["/", "/docs", "/openapi.json", "/login", "/favicon.ico"]

        if request.url.path not in public_paths:
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                logger.warning(f"CorrelationID: {cor_id} | Missing Authorization header for path: {request.url.path}")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Authorization header is missing"}
                )
            
            try:
                # Validate Authorization header format
                scheme, token = auth_header.split()
                if scheme.lower() != 'bearer':
                    logger.warning(f"CorrelationID: {cor_id} | Invalid authorization scheme")
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Invalid authorization scheme"}
                    )
                
                # Decode and verify JWT token
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                request.state.user = payload  # Store user info in the request state
                logger.info(f"CorrelationID: {cor_id} | User authenticated: {payload.get('sub')}")
            except (PyJWTError, ValueError) as e:
                logger.warning(f"CorrelationID: {cor_id} | Token validation error: {str(e)}")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid or expired token"}
                )

        response = await call_next(request)
        return response

# Add middleware to the FastAPI app
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(AuthorizationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000",f"{composite_service_url}"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# === Configuration ===
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="N/A")
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Logging filter to include Correlation ID
class CorrelationIdFilter(logging.Filter):
    def filter(self, record):
        record.correlation_id = correlation_id.get("N/A")
        return True

# Setup logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] [Correlation ID: %(correlation_id)s] %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)
logger.addFilter(CorrelationIdFilter())  
    

# USER_SERVICE_URL = "http://localhost:8002"

# === Database Dependency ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Models and Schemas ===
class DonateSwipeRequest(BaseModel):
    donor_id: str
    current_swipes: int
    is_relative: bool = True 

class DonatePointsRequest(BaseModel):
    donor_id: str
    points: int

class ReceiveSwipeRequest(BaseModel):
    recipient_id: str
    swipes_to_claim: int

class ReceivePointsRequest(BaseModel):
    recipient_id: str
    points: int

class DonatedSwipe(BaseModel):
    swipe_id: int
    uni: str
    is_donated: bool

    class Config:
        orm_mode = True

class DonatedSwipesResponse(BaseModel):
    message: str
    donated_swipes: List[DonatedSwipe]

# OAuth 2.0 Configuration
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
TOKEN_FILE = "token.json"

# === Utility Functions ===
def get_gmail_service():
    """Authenticate using OAuth 2.0 and return Gmail API service."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as token:
            creds_data = json.load(token)
            creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)

def send_email(to, subject, message_text):
    """Send an email using Gmail API."""
    try:
        service = get_gmail_service()
        message = MIMEText(message_text)
        message["to"] = to
        message["subject"] = subject
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        body = {"raw": raw_message}
        service.users().messages().send(userId="me", body=body).execute()
    except Exception as e:
        print(f"Error sending email: {e}")

# === Routes for Swipe and Point Operations ===
@app.post("/swipes/donate")
def donate_swipe(request: Request, donate_request: DonateSwipeRequest):
    user_info = request.state.user    
    donor_id = donate_request.donor_id
    swipes = donate_request.current_swipes  
    cor_id = correlation_id.get("N/A")
    logger.info(f"Processing donation for donor_id: {donor_id} with Correlation ID: {cor_id}")

    if user_info.get("sub") != donor_id:
        logger.error(f"Donor not found for donor_id: {donor_id}, Correlation ID: {cor_id}")
        raise HTTPException(
            status_code=403, detail="You are not authorized to donate on behalf of this user"
        )

    # Forward the Authorization header to the /users endpoint
    auth_header = request.headers.get("Authorization")
    response = requests.get(
        f"{user_service_url}/users/{donor_id}",
        headers={"Authorization": auth_header, "X-Correlation-ID": cor_id}
    )
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Donor not found")
    donor = response.json()

    if donor["current_swipes"] < swipes:
        raise HTTPException(status_code=400, detail="Not enough swipes available")
    with SessionLocal() as db:
        for _ in range(swipes):
            swipe_to_update = db.query(Swipe).filter(
                Swipe.uni == donor_id,
                Swipe.is_donated == False
            ).first()
            print(swipe_to_update)
            if not swipe_to_update:
                raise HTTPException(status_code=400, detail="No available swipes to donate")
            
            swipe_to_update.is_donated = True
            db.add(swipe_to_update)
            db.commit()

        db.commit()
    update_response = requests.put(
        f"{user_service_url}/users/{donor_id}",
        json={"current_swipes": -swipes},
        params={"is_relative": True},
        headers={
                "Authorization": auth_header,
                "X-Correlation-ID": cor_id  
            }        
    )
    if update_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to update swipe count")
    
    # Send email notification
    subject = "Thank You for Donating Swipes!"
    message_text = f"Hi {donor_id},\n\nThank you for donating {swipes} swipe(s). Your generosity is greatly appreciated!"
    send_email(donor["uni"], subject, message_text)

    return {"message": f"{swipes} swipe(s) donated successfully"}

@app.get("/swipes/donated", response_model=DonatedSwipesResponse)
def get_donated_swipes(db: Session = Depends(get_db)):
    try:
        donated_swipes = db.query(Swipe).filter(Swipe.is_donated == True).all()
        return {
            "message": "Donated swipes retrieved successfully",
            "donated_swipes": donated_swipes
        }
    except Exception as e:
        logger.error(f"Error retrieving donated swipes: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving donated swipes.")

@app.post("/swipes/claim")
def claim_swipe(request: Request, claim_request: ReceiveSwipeRequest):
    user_info = request.state.user
    recipient_id = claim_request.recipient_id
    swipes_to_claim = claim_request.swipes_to_claim 

    if user_info.get("sub") != recipient_id:
        raise HTTPException(
            status_code=403, detail="You are not authorized to claim swipes for this user"
        )

    # Access the Authorization header from the HTTP request
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header is missing")
    
    cor_id = correlation_id.get("N/A")  

    with SessionLocal() as db:
        donated_swipes = db.query(Swipe).filter(Swipe.is_donated == True).all()
        if len(donated_swipes) < swipes_to_claim:
            raise HTTPException(status_code=400, detail="No swipes available to claim")

        for i in range(swipes_to_claim):
            swipe = donated_swipes[i]
            swipe_id = swipe.swipe_id
            print(swipe_id)
            recipient = db.query(User).filter(User.uni == recipient_id).first()
            if not recipient:
                raise HTTPException(status_code=404, detail="Recipient not found")

            donor_id = swipe.uni
            swipe.is_donated = False
            swipe.uni = recipient_id
            recipient.swipes_received += 1
            db.commit()
            donor_update_response = requests.put(
                f"{user_service_url}/users/{donor_id}",
                json={"swipes_given": 1},
                params={"is_relative": "true"},
                headers={
                    "Authorization": auth_header,
                    "X-Correlation-ID": cor_id  
                }
            )
            recipient_update_response = requests.put(
                f"{user_service_url}/users/{recipient_id}",
                json={"current_swipes": 1, "swipes_received": 1},
                params={"is_relative": "true"},
                headers={
                    "Authorization": auth_header,
                    "X-Correlation-ID": cor_id  
                }
            )
            if donor_update_response.status_code != 200 or recipient_update_response.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to update donor or recipient statuses")
            
        subject = "Swipe Claim Successful!"
        message_text = f"Hi {recipient_id},\n\nYou have successfully claimed {swipes_to_claim} swipe(s). Enjoy your meal!"
        send_email(recipient.uni, subject, message_text)

        return {"message": f"{swipes_to_claim} swipe(s) claimed successfully", "swipe_id": swipe_id}

@app.post("/points/donate")
def donate_points(request: Request, donate_request: DonatePointsRequest):
    user_info = request.state.user
    donor_id = donate_request.donor_id
    points_to_donate = donate_request.points

    if user_info.get("sub") != donor_id:
        raise HTTPException(
            status_code=403, detail="You are not authorized to donate on behalf of this user"
        )

    # Access the Authorization header from the HTTP request
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header is missing")

    # Retrieve the Correlation ID
    cor_id = correlation_id.get("N/A")

    # Fetch donor information
    response = requests.get(
        f"{user_service_url}/users/{donor_id}",
        headers={
            "Authorization": auth_header,
            "X-Correlation-ID": cor_id 
        }
    )
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Donor not found")
    donor = response.json()

    if donor["current_points"] < points_to_donate:
        raise HTTPException(status_code=400, detail="Not enough points available")

    with SessionLocal() as db:
        points_row = db.query(Points).first()
        if not points_row:
            points_row = Points(points=0)  # Initialize if the table is empty
            db.add(points_row)
        
        points_row.points += points_to_donate
        db.commit()

    # Update donor's points using the centralized function
    update_response = requests.put(
        f"{user_service_url}/users/{donor_id}",
        json={"points": -points_to_donate, "points_given": points_to_donate},
        params={"is_relative": "true"},
        headers={
            "Authorization": auth_header,
            "X-Correlation-ID": cor_id  
        }
    )
    if update_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to update donor's points")
    
    # Send email notification
    subject = "Thank You for Donating Points!"
    message_text = f"Hi {donor_id},\n\nThank you for donating {points_to_donate} point(s). Your generosity is greatly appreciated!"
    send_email(donor["uni"], subject, message_text)

    return {"message": f"{points_to_donate} point(s) donated successfully"}

@app.post("/points/claim")
def claim_points(request: Request, claim_request: ReceivePointsRequest):
    user_info = request.state.user
    recipient_id = claim_request.recipient_id
    points = claim_request.points
    if user_info.get("sub") != claim_request.recipient_id:
        raise HTTPException(
            status_code=403, detail="You are not authorized to claim points for this user"
        )

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header is missing")
    
    # Retrieve the Correlation ID
    cor_id = correlation_id.get("N/A")

    with SessionLocal() as db:
        recipient = db.query(User).filter(User.uni == recipient_id).first()
        recipient_uni = recipient.uni
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")

        points_row = db.query(Points).first()
        if not points_row or points_row.points < points:
            raise HTTPException(status_code=400, detail="Not enough points available to claim")

        recipient.points_received += points
        points_row.points -= points
        db.commit()  

    update_response = requests.put(
        f"{user_service_url}/users/{recipient_id}",
        json={"points": points, "points_received": points},
        params={"is_relative": "true"},
        headers={
            "Authorization": auth_header,
            "X-Correlation-ID": cor_id  
        }
    )

    if update_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to update recipient's points")
    
    subject = "Point Claim Successful!"
    message_text = f"Hi {recipient_id},\n\nYou have successfully claimed {points} point(s). Enjoy your meal!"
    send_email(recipient_uni, subject, message_text)

    return {"message": f"{points} point(s) claimed successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
