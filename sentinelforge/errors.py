"""Centralized error handling for SentinelForge REST API."""
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException


def register_error_handlers(app: Flask) -> None:
    """Register JSON-only error handlers for all standard HTTP errors and exceptions."""

    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        """Return JSON format for standard HTTP exceptions."""
        response = {
            "status": "error",
            "error": {
                "code": e.code,
                "name": e.name,
                "message": e.description,
            },
            "path": request.path,
        }
        return jsonify(response), e.code or 500

    @app.errorhandler(Exception)
    def handle_generic_exception(e: Exception):
        """Catch-all error handler that prevents stack trace leakage."""
        app.logger.exception(f"Unhandled exception processing request {request.path}: {str(e)}")
        response = {
            "status": "error",
            "error": {
                "code": 500,
                "name": "Internal Server Error",
                "message": "An unexpected internal server error occurred.",
            },
            "path": request.path,
        }
        return jsonify(response), 500
