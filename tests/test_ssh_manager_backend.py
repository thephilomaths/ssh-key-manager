from ssh_manager_backend import __version__
from ssh_manager_backend.db.database import db_session
from ssh_manager_backend.db.schema import AccessControl, Key, KeyMapping, User


def test_version():
    assert __version__ == "0.1.0"


def test_delete():
    session = db_session()
    session.query(User).delete()
    session.query(Key).delete()
    session.query(KeyMapping).delete()
    session.query(AccessControl).delete()
    session.commit()
    db_session.remove()
