from flask import Flask, json
from werkzeug.exceptions import HTTPException

from ssh_manager_backend.db.database import db_session

app = Flask(__name__)


@app.teardown_appcontext
def shutdown_session() -> None:
    """
    Shuts down database session on application close
    :return: None
    """

    db_session.remove()


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps(
        {
            "code": e.code,
            "name": e.name,
            "description": e.description,
        }
    )
    response.content_type = "application/json"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
