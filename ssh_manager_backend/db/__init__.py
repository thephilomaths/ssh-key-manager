import sys

from ssh_manager_backend.db.database import init_db
from ssh_manager_backend.db.schema import (
    AccessControl,
    Key,
    KeyMapping,
    User,
    UserSession,
)

sys.path.append("../../")


init_db()
