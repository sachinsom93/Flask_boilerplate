"""
Business logic for /auth API endpoints.
"""
from http import HTTPStatus
from flask import current_app, jsonify
from flask_restx import abort
from app import db
from ...models.user import User
from ...models.token_blacklist import BlacklistedToken
from .decorators import token_required
from ...utils.datetime_util import remaining_fromtimestamp, format_timedelta_digits


def process_registration_request(email, password):
    if User.find_by_email(email):
        abort(HTTPStatus.CONFLICT, f"{email} is already registered.")
    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    access_token = new_user.encode_access_token()
    return _create_auth_successfull_response(
        access_token=access_token,
        message="Successfully registered.",
        status_code=HTTPStatus.CREATED,
    )


def process_login_request(email, password):
    user = User.find_by_email(email)
    if not user and not user.check_password(password):
        abort(HTTPStatus.UNAUTHORIZED, "email or password doesn't match", status="fail")
    access_token = user.encode_access_token()
    return _create_auth_successfull_response(
        access_token=access_token,
        message="Successfully logged in.",
        status_code=HTTPStatus.OK,
    )


def _create_auth_successfull_response(access_token, message, status_code):
    response = jsonify(
        status="success",
        message=message,
        access_token=access_token,
        token_type="bearer",
        expires_in=_get_token_expire_time(),
    )
    response.status_code = status_code
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _get_token_expire_time():
    token_age_h = current_app.config.get("TOKEN_EXPIRE_HOURS")
    token_age_m = current_app.config.get("TOKEN_EXPIRE_MINUTES")
    expires_in_seconds = token_age_h * 3600 + token_age_m * 60
    return expires_in_seconds if not current_app.config["TESTING"] else 5


@token_required
def get_logged_in_user():
    public_id = get_logged_in_user.public_id
    user = User.find_by_public_id(public_id)
    expires_at = get_logged_in_user.expires_at
    user.token_expires_in = format_timedelta_digits(remaining_fromtimestamp(expires_at))
    return user


@token_required
def process_logout_request():
    access_token = process_logout_request.token
    expires_at = process_logout_request.expires_at
    blacklisted_token = BlacklistedToken(token=access_token, expires_at=expires_at)
    db.session.add(blacklisted_token)
    db.session.commit()
    response_dict = dict(status="success", message="successfully logged out")
    return response_dict, HTTPStatus.OK
