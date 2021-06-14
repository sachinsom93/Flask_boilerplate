"""
Business logic for /auth API endpoints.
"""
from http import HTTPStatus
from flask import current_app, jsonify
from flask_restx import abort
from app import db
from ...models.user import User


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
