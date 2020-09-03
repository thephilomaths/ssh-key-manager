from typing import Union

from sqlalchemy.exc import SQLAlchemyError

from ssh_manager_backend.db import Key, User
from ssh_manager_backend.db.database import db_session


class KeyModel:
    def __init__(self):
        self.session = db_session()

    def exists(self, key_name: str) -> bool:
        """
        Checks whether key with the given name exists.

        :param key_name:
        :return: boolean value indicating the presence of key.
        """

        return self.session.query(Key).filter(Key.name == key_name).first() is not None

    def create(
        self, name: str, encrypted_key: bytes, key_hash: str, user_id: int
    ) -> bool:
        """
        Creates a key in database.

        :param name:
        :param encrypted_key:
        :param key_hash:
        :param user_id:
        :return: Boolean value indicating success/failure.
        """

        try:
            key: Key = Key(
                name=name,
                encrypted_key=encrypted_key,
                key_hash=key_hash,
                user_id=user_id,
            )

            self.session.add(key)
            self.session.commit()
        except SQLAlchemyError:
            self.session.rollback()
            return False

        return True

    def get_key(self, key_name: str) -> Union[None, Key]:
        """
        Gets the key object from teh database.

        :param key_name:
        :return: Key object
        """

        return self.session.query(Key).filter(Key.name == key_name).first()
