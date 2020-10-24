from typing import Dict

from flask import Response

from ssh_manager_backend.app.controllers import api
from ssh_manager_backend.app.models import AccessControlModel


def grant_access(body: Dict[str, any]) -> Response:
    """
    Grants access of the list of IP addresses to the specifies username,

    :param: body:
    :return:
    """

    data, key, iv = api.decrypt_request_data(body=body)
    username = data["username"]
    ip_addresses = data["ip_addresses"]
    acl = AccessControlModel()
    access_required = False

    for ip in ip_addresses:
        access_required = acl.has_access(username=username, ip_address=ip)
        if access_required:
            break

    if not acl.grant_access(
        username=data["username"], ip_addresses=data["ip_addresses"]
    ):
        data = {"success": False}
        return api.response_data(
            data=data,
            message="Username does not exist",
            status_code=404,
            key=key,
            iv=iv,
        )

    data = {"success": True}
    return api.response_data(
        data=data, message="Access granted", status_code=200, key=key, iv=iv
    )


def revoke_access(body: Dict[str, any]) -> Response:
    """
    Revokes access to the list of IP addresses to the specifies username,

    :param: username:
    :param: ip_addresses:
    :return:
    """
    data, key, iv = api.decrypt_request_data(body=body)

    acl = AccessControlModel()
    if not acl.revoke_access(
        username=data["username"], ip_addresses=data["ip_addresses"]
    ):
        data = {"success": False}
        return api.response_data(
            data=data,
            message="Username does not exist",
            status_code=404,
            key=key,
            iv=iv,
        )

    data = {"success": True}
    return api.response_data(
        data=data, message="Access revoked", status_code=200, key=key, iv=iv
    )


def revoke_all(body: Dict[str, any]) -> Response:
    """
    Revokes all access of the specified user.

    :param body:
    :return:
    """

    data, key, iv = api.decrypt_request_data(body=body)

    if not AccessControlModel().revoke_access(
        username=data["username"], ip_addresses=[], revoke_all=True
    ):
        data = {"success": False}
        return api.response_data(
            data=data,
            message="Username does not exist",
            status_code=404,
            key=key,
            iv=iv,
        )

    data = {"success": True}
    return api.response_data(
        data=data, message="Access revoked", status_code=200, key=key, iv=iv
    )


def has_access(body: Dict[str, any]):
    """
    Checks whether user has access to the specified ip address.

    :param body:
    :return:
    """

    data, key, iv = api.decrypt_request_data(body=body)

    if (
        AccessControlModel().has_access(
            username=data["username"], ip_address=data["ip_address"]
        )
        is None
    ):
        data = {"success": False}
        return api.response_data(
            data=data,
            message="Username does not exist",
            status_code=404,
            key=key,
            iv=iv,
        )

    data = {"success": True, "has_access": True}
    return api.response_data(
        data=data, message="Access details", status_code=200, key=key, iv=iv
    )
