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
        suggestions = []

        # Length check
        if len(password) >= self.min_length:
            score += 20
        else:
            suggestions.append(f"Password must be at least {self.min_length} characters long")

        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 20
        else:
            suggestions.append("Include at least one uppercase letter")

        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 20
        else:
            suggestions.append("Include at least one lowercase letter")

        # Digits check
        if re.search(r'\d', password):
            score += 20
        else:
            suggestions.append("Include at least one digit")

        # Symbols check
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            suggestions.append("Include at least one special character")

        # Check blacklist
        db = SessionLocal()
        try:
            hashed = hash_string(password.lower())
            blacklist_entry = db.query(PasswordBlacklist).filter(PasswordBlacklist.password_hash == hashed).first()
            if blacklist_entry:
                score = 0
                suggestions = ["Password is in the common passwords blacklist"]
        finally:
            db.close()

        is_valid = score >= 80 and not suggestions

        return {
            "is_valid": is_valid,
            "strength_score": score,
            "suggestions": suggestions
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