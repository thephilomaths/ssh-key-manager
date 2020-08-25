from flask import Flask

from ssh_manager_backend.app.models.user import UserModel
from ssh_manager_backend.db.database import db_session

# app = Flask(__name__)
#
#
# @app.teardown_appcontext
# def shutdown_session() -> None:
# 	"""
# 	Shuts down database session on application close
# 	:return: None
# 	"""
#
# 	db_session.remove()
#

a = UserModel()
# print(a.create('abcd', 'abcd', 'abcd', True, b'123d', b'123d', b'123d', b'123d', b'123d', b'123d'))
print(a.get_user("abc"))
