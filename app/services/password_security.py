import re
from typing import Dict, Any
from app.database.connection import SessionLocal
from app.database.models import PasswordBlacklist
from app.utils.helpers import hash_string

class PasswordSecurityEngine:
    def __init__(self):
        self.min_length = 8
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_symbols = True

    def validate_password(self, password: str) -> Dict[str, Any]:
        score = 0
        feedback = []

        length_ok = len(password) >= self.min_length
        if not length_ok:
            feedback.append(f"Password must be at least {self.min_length} characters long")

        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Include at least one uppercase letter")

        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Include at least one lowercase letter")

        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Include at least one digit")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Include at least one special character")

        db = SessionLocal()
        try:
            hashed = hash_string(password.lower())
            blacklist_entry = db.query(PasswordBlacklist).filter(PasswordBlacklist.password_hash == hashed).first()
            if blacklist_entry:
                score = 0
                feedback = ["Password is in the common passwords blacklist"]
        finally:
            db.close()

        is_valid = length_ok and score == 4 and not feedback

        return {
            "is_valid": is_valid,
            "score": score,
            "feedback": feedback,
            "strength_score": score * 25 if length_ok else min(score * 25, 75),
            "suggestions": feedback,
        }

    def add_to_blacklist(self, password: str):
        db = SessionLocal()
        try:
            hashed = hash_string(password.lower())
            if not db.query(PasswordBlacklist).filter(PasswordBlacklist.password_hash == hashed).first():
                blacklist_entry = PasswordBlacklist(password_hash=hashed)
                db.add(blacklist_entry)
                db.commit()
        finally:
            db.close()
