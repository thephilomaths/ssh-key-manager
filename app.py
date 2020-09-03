from flask import Flask

from ssh_manager_backend.db.database import db_session

app = Flask(__name__)


@app.teardown_appcontext
def shutdown_session() -> None:
    """
    Shuts down database session on application close
    :return: None
    """

    db_session.remove()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
