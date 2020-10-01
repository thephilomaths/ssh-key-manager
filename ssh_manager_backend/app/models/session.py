from typing import Union

from sqlalchemy.exc import SQLAlchemyError

from ssh_manager_backend.db import User, UserSession
from ssh_manager_backend.db.database import db_session


class SessionModel:
    def __init__(self):
        self.session = db_session()

    def exists(self, username: str) -> bool:
        """
        Checks whether a session exists.

        :params username: The username of the user.
        :return:
        """

        return (
            self.session.query(UserSession)
            .join(User)
            .filter(User.username == username)
            .first()
            is not None
        )

    def create(self, username: str, access_token: str) -> bool:
        """
        Creates a user session and returns access token upon success.
        :param username: The username of the user,
        :return:
        """

        try:
            user_session: UserSession = UserSession(
                access_token=access_token, username=username, active=True
            )
            self.session.add(user_session)
            self.session.commit()
        except SQLAlchemyError:
            self.session.rollback()
            return False
        except AttributeError:
            return False

        return True

    def activate_session(self, username: str) -> bool:
        """
        Activates a user session.
        :param username: The username of the user,
        :return:
        """

        try:
            self.session.query(UserSession).filter(
                UserSession.username == username
            ).update({"active": True})
            self.session.commit()

            return True
        except AttributeError:
            return False

    def deactivate_session(self, username: str) -> bool:
        """
        Activates a user session.
        :param username: The username of the user,
        :return:
        """

        try:
            self.session.query(UserSession).filter(
                UserSession.username == username
            ).update({"active": False})
            self.session.commit()
            return True
        except AttributeError:
            return False

    def access_token(self, username: str) -> Union[bool, str]:
        """
        Returns access token of user.
        :param username: The usernameof the user,
        :return: access token
        """

        try:
            access_token: str = (
                self.session.query(UserSession)
                .filter(UserSession.username == username)
                .first()
                .access_token
            )
            return access_token
        except AttributeError:
            return False
