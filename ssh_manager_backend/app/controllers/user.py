import uuid
from typing import Dict, Tuple

from flask import Response

from ssh_manager_backend.app.controllers import api
from ssh_manager_backend.app.controllers.secrets import Secrets
from ssh_manager_backend.app.models import SessionModel, UserModel
from ssh_manager_backend.app.services import utils


class User:
    def __init__(self):
        self.secrets = Secrets()
        self.username: str = ""
        self.__password: str = ""
        self.name: str = ""
        self.admin: str = ""
        self.user: UserModel = UserModel()

    def set_attributes(self, username: str, password: str, name: str):
        """
        Sets the class attribute based on the function arguments.

        :param username: The username of the user
        :param password: The password of the user
        :param name: The name of the user
        :return:
        """

        self.username = username
        self.__password = password
        self.name = name

    def register(self, body: Dict[str, any]) -> Response:
        """
        Generates the secrets of the user based on the password. Hashes the password using SAH256 and stores the
        generated information in DynamoDB.

        :param body:
        :return: True/False for success/failure
        """

        data, key, iv = api.decrypt_request_data(body=body)
        self.set_attributes(
            username=data["username"], password=data["password"], name=data["name"]
        )

        if self.user.exists(username=self.username):
            data = {"success": False}
            return api.response_data(
                data=data, message="Username is taken", status_code=409, key=key, iv=iv
            )

        self.secrets.generate_secrets(password=str(self.__password))
        self.__password = utils.hash_data(
            self.__password, self.secrets.salt_for_password
        )
        user_is_admin = True

        if self.user.admin_exists():
            user_is_admin = False

        user_created = self.user.create(
            name=self.name,
            username=self.username,
            password=self.__password,
            admin=user_is_admin,
            encrypted_dek=self.secrets.dek,
            iv_for_dek=self.secrets.iv_for_dek,
            salt_for_dek=self.secrets.salt_for_dek,
            iv_for_kek=self.secrets.iv_for_kek,
            salt_for_kek=self.secrets.salt_for_kek,
            salt_for_password=self.secrets.salt_for_password,
        )

        data = {"success": user_created}
        return api.response_data(
            data=data, message="User created", status_code=200, key=key, iv=iv
        )

    def login(self, body: Dict[str, any]) -> Response:
        """
        Handles user login.

        :param body:
        :return: access token upon successful login
        """

        data, key, iv = api.decrypt_request_data(body=body)
        self.set_attributes(
            username=data["username"], password=data["password"], name=""
        )

        if self.user.exists(self.username):
            user_data = self.user.get_user(username=self.username)
            self.set_attributes(
                username=self.username, password=self.__password, name=user_data.name
            )
            secrets = {
                "encryptedDek": user_data.encrypted_dek,
                "ivForDek": user_data.iv_for_dek,
                "saltForDek": user_data.salt_for_dek,
                "ivForKek": user_data.iv_for_kek,
                "saltForKek": user_data.salt_for_kek,
                "saltForPassword": user_data.salt_for_password,
            }
            self.secrets.set_secrets(secrets=secrets)
            if self.user.password_match(
                username=self.username,
                password=utils.hash_data(
                    self.__password, self.secrets.salt_for_password
                ),
            ):
                access_token: str = uuid.uuid4().hex
                session: SessionModel = SessionModel()
                if not session.exists(username=self.username):
                    session.create(username=self.username, access_token=access_token)
                else:
                    session.activate_session(username=self.username)

                data = {"success": True, "access_token": access_token}
                return api.response_data(
                    data=data,
                    message="Login successful",
                    status_code=200,
                    key=key,
                    iv=iv,
                )
            else:
                data = {
                    "success": False,
                }
                return api.response_data(
                    data=data,
                    message="Password does not match",
                    status_code=401,
                    key=key,
                    iv=iv,
                )

        data = {"success": False}
        return api.response_data(
            data=data, message="User does not exists", status_code=401, key=key, iv=iv
        )

    def is_admin(self, body: Dict[str, any]) -> Response:
        """
        Checks whether user is admin or not.

        Args:
            body:

        Returns:

        """
        data, key, iv = api.decrypt_request_data(body=body)
        self.set_attributes(username=data["username"], password="", name="")

        user = self.user.get_user(username=self.username)

        data = {"success": True, "is_admin": user is not None and user.admin}
        return api.response_data(data=data, message="", status_code=200, key=key, iv=iv)
