from typing import Dict, Tuple, Union

from flask import Response

from ssh_manager_backend.app.controllers import api
from ssh_manager_backend.app.models import KeyModel, UserModel
from ssh_manager_backend.app.services import AES, utils


"""
This module manages the SSH key of the user.
"""


class Key:
    def __init__(self, username: str, password: Union[str, bytes], secrets: dict):
        self.username = username
        self.key = KeyModel()

        if secrets is not None and password is not None:
            self.iv_for_kek = secrets["ivForKek"]
            self.salt_for_kek = secrets["saltForKek"]
            self.encrypted_dek = secrets["encryptedDek"]
            self.iv_for_dek = secrets["ivForDek"]
            self.salt_for_dek = secrets["saltForDek"]

            self.dek = self.decrypt_dek(
                password=password,
            )

        self.ssh_encrypted_key = None
        self.ssh_key = None

    def decrypt_dek(self, password: str) -> object:
        """
        Decrypts the dek(See secrets module) using AES and the password of the user.

        :param password: The password of the user
        :return: decrypted decryption key
        """

        kek = utils.pbkdf(data=password, salt=self.salt_for_kek)
        aes = AES(key=kek, iv=self.iv_for_kek)
        dek = aes.decrypt(self.encrypted_dek)
        return dek

    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        """
        Encrypts the SSH key with the "dek" and salt for "dek".

        :param plaintext: The text to be encrypted
        :return: ciphertext
        """

        kek = utils.pbkdf(data=self.dek, salt=self.salt_for_dek)
        aes = AES(key=kek, iv=self.iv_for_dek)
        ciphertext = aes.encrypt(plaintext=plaintext)

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypts the SSH key using "dek" and salt for "dek" and AES algorithm.

        :param ciphertext: The text which is to be decrypted
        :return:
        """

        kek = utils.pbkdf(data=self.dek, salt=self.salt_for_dek)
        aes = AES(key=kek, iv=self.iv_for_dek)
        plaintext = aes.decrypt(ciphertext=ciphertext)

        return plaintext

    def put_key(self, body: Dict[str, any]) -> Response:
        """
        Puts key in db.

        :param body:
        :return: Either a string error message or a boolean value stating success
        """

        request_data, key, iv = api.decrypt_request_data(body=body)

        self.ssh_encrypted_key = self.encrypt(request_data["key"])
        key_hash = utils.hash_data(data=request_data["key"], salt=b"")

        if self.key.exists(key_name=request_data["key_name"]):
            data = {
                "success": False,
            }
            return api.response_data(
                data=data,
                message="Key with the same name already exists",
                status_code=409,
                key=key,
                iv=iv,
            )

        user = UserModel()
        if not user.exists(username=self.username):
            data = {
                "success": False,
            }
            return api.response_data(
                data=data, message="Unauthorized", status_code=401, key=key, iv=iv
            )

        user = user.get_user(username=self.username)

        data = {"success": True}
        self.key.create(
            name=request_data["key_name"],
            encrypted_key=self.ssh_encrypted_key,
            key_hash=key_hash.decode(),
            user_id=user.id,
        )

        return api.response_data(
            data=data,
            message="Successfully stored the key",
            status_code=200,
            key=key,
            iv=iv,
        )

    def get_key(self, body: Dict[str, any]) -> Response:
        """
        Gets the encrypted SSH key and decrypts it.

        :param body:
        :return:
        """

        request_data, key, iv = api.decrypt_request_data(body=body)

        if not self.key.exists(key_name=request_data["key_name"]):
            data = {"success": False}

            return api.response_data(
                data=data, message="Key does not exist", status_code=404, key=key, iv=iv
            )

        self.ssh_encrypted_key = self.key.get_key(
            key_name=request_data["key_name"]
        ).encrypted_key
        self.ssh_key = self.decrypt(ciphertext=self.ssh_encrypted_key)

        data = {"success": False, "key": self.ssh_key}

        return api.response_data(data=data, message="", status_code=200, key=key, iv=iv)
