"""
Config settings for for development, testing and production environments.
"""
import os
from pathlib import Path


HERE = Path(__file__).parent
SQLITE_DEV = "sqlite:///" + str(HERE / "app_dev.db")
SQLITE_TEST = "sqlite:///" + str(HERE / "app_test.db")
SQLITE_PROD = "sqlite:///" + str(HERE / "app_prod.db")


class BaseConfig:
    """Base configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY", "it'smedefaultsecret")
    BCRYPT_LOG_ROUNDS = 4
    TOKEN_EXPIRE_HOURS = 0
    TOKEN_EXPIRE_MINUTES = 0
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    SWAGGER_UI_DOC_EXPANSION = "list"
    RESTX_MASK_SWAGGER = False
    JSON_SORT_KEYS = False


class TestingConfig(BaseConfig):
    """Testing configuration."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = SQLITE_TEST


class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    TOKEN_EXPIRE_MINUTES = 15
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", SQLITE_DEV)


class ProductionConfig(BaseConfig):
    """Production configuration."""

    TOKEN_EXPIRE_HOURS = 1
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", SQLITE_PROD)
    PRESERVE_CONTEXT_ON_EXCEPTION = True


ENV_CONFIG_DICT = dict(
    development=DevelopmentConfig, testing=TestingConfig, production=ProductionConfig
)


def get_config(config_name):
    """Retrieve environment configuration settings."""
    return ENV_CONFIG_DICT.get(config_name, ProductionConfig)
