"""
API endpoints definition for /auth
"""
from http import HTTPStatus
from flask_restx import Namespace, Resource
from .dto import auth_reqparser
from .bussiness import process_registration_request, process_login_request

auth_ns = Namespace(name="auth", validate=True)


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
