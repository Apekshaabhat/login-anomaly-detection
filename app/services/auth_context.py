from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import User
from app.services.token_service import TokenService

token_service = TokenService()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth_header = request.headers.get("authorization") or ""
    token = None
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        user_id = token_service.decode_access_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user
