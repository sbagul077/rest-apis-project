import os
import secrets

from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from db import db
from blocklist import BLOCKLIST
import models

from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBlueprint
from resources.tag import blp as TagBlueprint
from resources.user import blp as UserBlueprint


def create_app(db_url=None):
    app = Flask(__name__)

    # Configuration options

    # PROPAGATE_EXCEPTIONS is a flask exception which tells that if there is an exception hidden inside an extension
    # of flask to propagate it inside the flask
    app.config["PROPAGATE_EXCEPTIONS"] = True
    # Title of the app in the documentations
    app.config["API_TITLE"] = "Stores REST API"
    # version of the API we are currently working on
    app.config["API_VERSION"] = "v1"
    # OPENAPI is the standard for API documentation. Here we tell Flask-Smorest to use version 3.0.3
    app.config["OPENAPI_VERSION"] = "3.0.3"
    # OPENAPI_URL_PREFIX tells flask-smorest where the root API is
    app.config["OPENAPI_URL_PREFIX"] = "/"
    # it tells flask-smorest to use swagger for API documentations
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    # Code to load swagger UI  http://localhost:5005/swagger-ui
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # this initializes the flask SQL-Alchemy extension, giving it our flask app so that it can connect flask app to SQL-Alchemy
    db.init_app(app)
    migrate = Migrate(app, db)
    api = Api(app)
    # This function will before our first request is processed in the app
    # So whenever the app starts and a request is made using postman or insomnia before that first request is tackled
    # Then it will run app.app_context():. This will create all the table in our database if they don't already exist.
    app.config["JWT_SECRET_KEY"] = "sanket"
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (jsonify(
            {"description": "The token has been revoked.", "error": "token_revoked"}
        ),
                401,
        )

    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {
                    "description": "The token is not fresh",
                    "error": "fresh_token_required"
                }
            ), 401
        )

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        if identity == 1:
            return {"is_admin": True}
        return {"is_admin": False}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}),
            401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify({"message": "Signature verification failed.", "error": "invalid token"}),
            401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify({
                "description": "Request does not contain an access token.",
                "error": "authorization_required",
            }),
            401,
        )

    # with app.app_context():
    #     db.create_all()
    #     # OR
    # we can write
    # @app.before_first_request
    # def create_table():
    #     db.create_all()

    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(TagBlueprint)
    api.register_blueprint(UserBlueprint)

    return app
