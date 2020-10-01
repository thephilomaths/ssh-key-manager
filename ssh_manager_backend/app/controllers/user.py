import uuid
from typing import Tuple, Union

from src.modules.utils import hash_data

from ssh_manager_backend.app.controllers.secrets import Secrets
from ssh_manager_backend.app.models import SessionModel, UserModel


class User:
    def __init__(self):
        self.secrets: Secrets = Secrets()
        self.username: str = ""
        self.__access_token: str = ""
        self.__password: str = ""
        self.email: str = ""
        self.name: str = ""
        self.admin: str = ""
        self.user: UserModel = UserModel()

    def set_attributes(
        self, username: str, password: str, email: str, name: str, access_token: str
    ):
        """
        Sets the class attribute based on the function arguments.

        :param username: The username of the user
        :param password: The password of the user
        :param email: The email of the user
        :param name: The name of the user
        :param access_token: The access token of the user
        :return:
        """

        self.username = username
        self.__password = password
        self.email = email
        self.name = name
        self.__access_token = access_token

    def register(self, username: str, password: str, email: str, name: str) -> bool:
        """
        Generates the secrets of the user based on the password. Hashes the password using SAH256 and stores the
        generated information in DynamoDB.

        :param username:
        :param password:
        :param email:
        :param name:
        :param table_name:
        :return: True/False for success/failure
        """

        self.set_attributes(
            username=username,
            password=password,
            email=email,
            name=name,
            access_token=uuid.uuid4().hex,
        )

        self.secrets.generate_secrets(password=self.__password)
        self.__password = hash_data(self.__password, self.salt_for_password)
        user_is_admin = True

        if self.user.admin_exists():
            user_is_admin = False

        return self.user.create(
            name=name,
            username=self.username,
            password=self.__password,
            admin=user_is_admin,
            encrypted_dek=self.secrets.encrypted_dek,
            iv_for_dek=self.secrets.iv_for_dek,
            salt_for_dek=self.secrets.salt_for_dek,
            iv_for_kek=self.secrets.iv_for_kek,
            salt_for_kek=self.secrets.salt_for_kek,
            salt_for_password=self.secrets.salt_for_password,
        )

    def login(self, username: str, password: str) -> Tuple[Union[bool, str]]:
        """
        Handles user login.

        :param username: The username of the user
        :param password: The password of the user
        :param table_name: The table in which the data is to be inserted
        :return: access token upon successful login
        """

        if self.user.exists(username):
            if self.user.password_match(
                username=username, password=hash_data(password)
            ):
                access_token: str = uuid.uuid4()
                session: SessionModel = SessionModel()
                if not session.exists(username=username):
                    session.create(usernmae=username, access_token=access_token)
                else:
                    session.activate_session(username=username)

                return (True, access_token)
            else:
                return (False, "Password does not match")

        return (False, "User does not exists")

    def is_admin(self) -> bool:
        return self.user.get_user(username=self.username).admin

    @property
    def password(self) -> str:
        """
        Returns the password of the user
        """

        return self.__password

    @property
    def access_token(self) -> str:
        """
        Returns the access token of the user
        """

        return self.__access_token
