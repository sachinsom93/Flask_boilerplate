"""
Class definition for User model.
"""

from datetime import date, datetime, timezone, timedelta
from flask import current_app
from sqlalchemy.ext.hybrid import hybrid_property

from uuid import uuid4
import jwt

from app import db, bcrypt
from app.utils.datetime_util import (
    get_local_utcoffset,
    localized_dt_string,
    make_tzaware,
    utc_now,
)
from app.utils.result import Result


class User(db.Model):
    """
    User model for storing user details
    """

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(2555), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=True)
    registered_on = db.Column(db.DateTime, default=utc_now)
    admin = db.Column(db.Boolean, default=False)
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid4()))

    def __repr__(self):
        """
        Offical way of representing user in db
        """
        return (
            f"<User email={self.email}, public_id={self.public_id}, admin={self.admin}"
        )

    @hybrid_property
    def registered_on_str(self):
        """
        storing registered_on as string
        """
        registered_on_utc = make_tzaware(
            self.registered_on, use_tz=timezone.utc, localize=False
        )
        return localized_dt_string(registered_on_utc, use_tz=get_local_utcoffset())

    @property
    def password(self):
        """
        Write only pasword field
        """
        raise AttributeError("password: write only access")

    @password.setter
    def password(self, password):
        log_rounds = current_app.config.get("BCRYPT_LOG_ROUNDS")
        hash_bytes = bcrypt.generate_password_hash(password, log_rounds)
        self.password_hash = hash_bytes.decode("utf-8")

    def check_password(self, passowrd):
        return bcrypt.check_password_hash(self.password_hash, passowrd)

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_public_id(cls, public_id):
        return cls.query.filter_by(public_id=public_id).first()

    def encode_access_token(self):
        """
        Generating access token
        """
        now = datetime.now(timezone.utc)
        token_age_h = current_app.config.get("TOKEN_EXPIRE_HOURS")
        token_age_m = current_app.config.get("TOKEN_EXPIRE_MINUTES")
        expires = now + timedelta(hours=token_age_h, minutes=token_age_m)
        if current_app.config["TESTING"]:
            expires = now + timedelta(seconds=5)
        payload = dict(exp=expires, iat=now, sub=self.public_id, admin=self.admin)
        key = current_app.config.get("SECRET_KEY")
        return jwt.encode(payload, key, algorithm="HS256")

    @staticmethod
    def decode_access_token(access_token):
        """
        Decoding access token
        """
        if isinstance(access_token, bytes):
            access_token = access_token.decode("ascii")
        if access_token.startswith("Bearer "):
            split = access_token.split("Bearer")
            access_token = split[1].strip()
        try:
            key = current_app.config.get("SECRET_KEY")
            payload = jwt.decode(access_token, key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            error = "Access token expired, Please login again."
            return Result.Fail(error_message=error)
        except jwt.InvalidTokenError:
            error = "Invalid token. Please  log in again."
            return Result.Fail(error_message=error)
        user_dict = dict(
            public_id=payload["sub"],
            admin=payload["admin"],
            token=access_token,
            expires_at=payload["exp"],
        )
        return Result.Ok(value=user_dict)
