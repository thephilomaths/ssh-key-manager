import json

from config import logger
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Response
from src.modules.request_decryption import request_decryption


"""
This is sa utility file which contains functions which are called frequently in various fieles.
"""


def hash_data(data: str or bytes, salt: bytes) -> bytes:
    """
    Hashes the given data using the salt and returns the hashed bytes. If the provided data is not an instance of bytes, then an explicit conversion is done.

    Parameters
    ----------
    data: str, bytes
        The data to be hashed
    salt: bytes
        The salt used for hashing
    ----------
    """

    logger.info("Hashing data using SHA256")
    if not isinstance(data, bytes):
        data = bytes(data, encoding="utf-8") + salt

    digest = hashes.Hash(algorithm=hashes.SHA256(), backend=default_backend())

    digest.update(data)
    return digest.finalize()


def pbkdf(data: str or bytes, salt: bytes) -> bytes:
    """
    Generates a key from the data and salt using the PBKDF2(Password based key derivation function) algorithm and returns the generated key(in bytes)

    Parameters
    ----------
    data: str, bytes
        The password in the PBKDF
    salt: bytes
        The salt used for PBKDF
    ----------
    """

    if not isinstance(data, bytes):
        data = bytes(data, encoding="utf-8")

    logger.info("Calculating PBKDF of data")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )

    return kdf.derive(data)


def success_response(data: dict, status_code: int, key: bytes, iv: bytes) -> Response:
    """
    A function for generating a success response.
    Returns a flask Response object

    :param data: The response data
    :param status_code: The status code of the response
    :param key: The key for encrypting the response
    :param iv: The iv for encrypting the response
    :return: Response
    """

    response_body = {"data": data}

    response_body = request_decryption.encrypt(body=response_body, key=key, iv=iv)

    return Response(
        response=json.dumps(response_body),
        status=status_code,
        mimetype="application/json",
    )


def error_response(
    error_message: str, status_code: int, key: bytes, iv: bytes
) -> Response:
    """
    A function for generating error response.
    Returns a flask Response object.

    :param error_message: The error message to be returned
    :param status_code: The status code of the response
    :param key: The key for encrypting the response
    :param iv: The iv for encrypting the response
    :return: Response
    """

    response_body = {"data": {"error": error_message}}

    response_body = request_decryption.encrypt(body=response_body, key=key, iv=iv)

    return Response(
        response=json.dumps(response_body),
        status=status_code,
        mimetype="application/json",
    )
