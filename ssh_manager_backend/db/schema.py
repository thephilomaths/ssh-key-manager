from sqlalchemy import ARRAY, Boolean, Column, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import relationship

from ssh_manager_backend.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    username = Column(String, unique=True)
    password = Column(String)
    admin = Column(Boolean)
    encrypted_dek = Column(LargeBinary, unique=True)
    iv_for_dek = Column(LargeBinary, unique=True)
    salt_for_dek = Column(LargeBinary, unique=True)
    iv_for_kek = Column(LargeBinary, unique=True)
    salt_for_kek = Column(LargeBinary, unique=True)
    salt_for_password = Column(LargeBinary, unique=True)
    keys = relationship("Key", backref="users")
    access_control = relationship("AccessControl", backref="users")

    def __repr__(self) -> str:
        """
        :return: user id
        """

        return f"User {self.id}"


class Key(Base):
    __tablename__ = "keys"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    encrypted_key = Column(LargeBinary, unique=True)
    key_hash = Column(String, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User")
    key_mapping = relationship("KeyMapping", backref="keys")

    def __repr__(self) -> str:
        """
        :return: key id
        """

        return f"Key {self.id}"


class KeyMapping(Base):
    __tablename__ = "key_mapping"

    id = Column(Integer, primary_key=True)
    key_name = Column(String, ForeignKey("keys.name"))
    ip_address = Column(String, unique=True)
    key = relationship("Key")

    def __repr__(self) -> str:
        """
        :return: key_mapping id
        """

        return f"Key Mapping {self.id}"


class AccessControl(Base):
    __tablename__ = "access_control"

    id = Column(Integer, primary_key=True)
    username = Column(String, ForeignKey("users.username"))
    ip_addresses = Column(ARRAY(String))
    user = relationship("User")

    def __repr__(self) -> str:
        """
        :return: access_control id
        """

        return f"Access control {self.id}"
