"""
API endpoints definition for /auth
"""
from http import HTTPStatus
from flask_restx import Namespace, Resource
from .dto import auth_reqparser, user_model
from .bussiness import (
    process_registration_request,
    process_login_request,
    get_logged_in_user,
)

auth_ns = Namespace(name="auth", validate=True)
auth_ns.models[user_model.name] = user_model


@auth_ns.route("/register", endpoint="auth_register")
class RegisterUser(Resource):
    @auth_ns.expect(auth_reqparser)
    @auth_ns.response(int(HTTPStatus.CREATED), "New user was successfully created.")
    @auth_ns.response(int(HTTPStatus.CONFLICT), "Email address is already registered.")
    @auth_ns.response(int(HTTPStatus.BAD_REQUEST), "Validation error.")
    @auth_ns.response(int(HTTPStatus.INTERNAL_SERVER_ERROR), "Internal server error.")
    def post(self):
        """Register a new user and return an access token."""
        request_data = auth_reqparser.parse_args()
        email = request_data.get("email")
        password = request_data.get("password")
        return process_registration_request(email, password)


@auth_ns.route("/login", endpoint="auth_login")
class LoginUser(Resource):
    @auth_ns.expect(auth_reqparser)
    @auth_ns.response(int(HTTPStatus.OK), "user has successfully logged in.")
    @auth_ns.response(int(HTTPStatus.UNAUTHORIZED), "email or password doesn't match")
    @auth_ns.response(int(HTTPStatus.BAD_REQUEST), "Validation error.")
    @auth_ns.response(int(HTTPStatus.INTERNAL_SERVER_ERROR), "Internal server error.")
    def post(self):
        """Handles HTTP login request"""
        request_data = auth_reqparser.parse_args()
        email = request_data.get("email")
        password = request_data.get("password")
        return process_login_request(email=email, password=password)


@auth_ns.route("/user", endpoint="auth_user")
class GetUser(Resource):
    """Handles HTTP requests."""

    @auth_ns.doc(security="Bearer")  # To mark the HTTPMethod as protected resource
    @auth_ns.response(int(HTTPStatus.OK), "Token is currectly valid.")
    @auth_ns.response(int(HTTPStatus.BAD_REQUEST), "Validation error.")
    @auth_ns.response(int(HTTPStatus.UNAUTHORIZED), "Token is invalid or expired.")
    @auth_ns.marshal_with(
        user_model
    )  # To filter the return data according to provided user_model
    def get(self):
        "Validate access token and return user info."
        return get_logged_in_user()
