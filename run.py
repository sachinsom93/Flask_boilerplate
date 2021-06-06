"""Flask CLI/Application entry point."""
import os

from app import create_app, db

app = create_app(os.getenv("FLASK_ENV", "development"))


@app.shell_context_processor
def shell():
    return {"db": db}
