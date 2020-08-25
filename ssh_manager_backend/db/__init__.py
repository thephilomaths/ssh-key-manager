import sys

from ssh_manager_backend.db.database import init_db
from ssh_manager_backend.db.schema import AccessControl, Key, KeyMapping, User

sys.path.append("../../")


init_db()
