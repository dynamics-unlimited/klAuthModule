"""
Kairnial auth services
"""
import json
import logging

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.utils.translation import gettext as _

from . import JSON_CONTENT_TYPE
from .serializers import AuthServiceErrorSerializer

PASSWORD_LOGIN_PATH = '/api/oauth2/login'
API_AUTHENT_PATH = '/api/oauth2/client_credentials/{clientID}'
MESSAGE_INVALID_RESPONSE = "Invalid response from server"

class KairnialAuthServiceError(Exception):
    _message = _("Error fetching data from Kairnial WebServices")
    _status = 0

    def __init__(self, message, status):
        self._status = status
        self._message = message

    @property
    def error(self):
        return AuthServiceErrorSerializer({
            'service_status': self._status,
            'service_message': self._message
        }).data

    @property
    def status(self):
        return self._status


class KairnialAuthentication:
    """
    Kairnial aauthentication class
    """
    token_type = None
    token = None
    user = None
    client_id = None

    def __init__(self, client_id: str):
        self.client_id = client_id

    def password_authentication(self, username: str, password: str) -> dict:
        """
        Get atuh token from auth server
        :param username: User unique identifier
        :param password: User password
        :return:
        """
        payload = {
            'client_id': self.client_id,
            'scope': " ".join(settings.KAIRNIAL_AUTHENTICATION_SCOPES),
            'grant_type': 'password',
            'password': password,
            'username': username,
        }
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        response = requests.post(
            settings.KAIRNIAL_AUTH_SERVER + PASSWORD_LOGIN_PATH,
            headers=headers,
            data=payload
        )
        if response.status_code != 200:
            raise KairnialAuthServiceError(
                message=_(f"Authentication failed with code {response.status_code}: {response.content}"),
                status=response.status_code
            )

        try:
            resp = response.json()
            self._extract_token(resp)
            self._extract_token_type(resp)
            self._extract_user(resp)
            return resp
        except json.JSONDecodeError:
            raise KairnialAuthServiceError(
                message=MESSAGE_INVALID_RESPONSE,
                status=400
            )

    def secrets_authentication(self, api_key: str, api_secret: str) -> dict:
        """
        Get auth token from auth server
        :param api_key: User API Key
        :param api_secret: User API Secret
        :return:
        """
        logger = logging.getLogger('services')
        payload = {
            'grant_type': 'api_key',
            'scope': " ".join(settings.KAIRNIAL_AUTHENTICATION_SCOPES),
            'client_id': self.client_id,
            'api_key': api_key,
            'api_secret': api_secret

        }
        logger.debug(settings.KAIRNIAL_AUTH_SERVER + PASSWORD_LOGIN_PATH)
        logger.debug(payload)
        headers = {
            'Content-Type': JSON_CONTENT_TYPE,
        }
        logger.debug(headers)
        response = requests.post(
            settings.KAIRNIAL_AUTH_SERVER + PASSWORD_LOGIN_PATH,
            headers=headers,
            data=json.dumps(payload)
        )
        logger.debug(response.status_code)
        logger.debug(response.content)
        if response.status_code != 200:
            raise KairnialAuthServiceError(
                message=_(f"Authentication failed with code {response.status_code}: {response.content}"),
                status=response.status_code
            )

        try:
            resp = response.json()
            logger.debug(resp)
            self._extract_token(resp)
            self._extract_token_type(resp)
            self._extract_user(resp)
            return resp
        except json.JSONDecodeError:
            raise KairnialAuthServiceError(
                message=MESSAGE_INVALID_RESPONSE,
                status=400
            )

    def refresh_authentication(self, refresh_token: str, provider_uuid: str) -> dict:
        """
        Get auth token from auth server
        :param refresh_token: Refresh token
        :param provider_uuid: Authentication provider identifier
        :return:
        """
        logger = logging.getLogger('services')
        payload = {
            'grant_type': 'refresh_token',
            'scope': " ".join(settings.KAIRNIAL_AUTHENTICATION_SCOPES),
            'client_id': self.client_id,
            'provider_uuid': provider_uuid,
            'refresh_token': refresh_token
        }
        logger.debug(settings.KAIRNIAL_AUTH_SERVER + PASSWORD_LOGIN_PATH)
        logger.debug(payload)
        headers = {
            'Content-Type': JSON_CONTENT_TYPE,
        }
        logger.debug(headers)
        response = requests.post(
            settings.KAIRNIAL_AUTH_SERVER + PASSWORD_LOGIN_PATH,
            headers=headers,
            data=json.dumps(payload)
        )
        logger.debug(response.status_code)
        logger.debug(response.content)
        if response.status_code != 200:
            raise KairnialAuthServiceError(
                message=_(f"Authentication failed with code {response.status_code}: {response.content}"),
                status=response.status_code
            )

        try:
            resp = response.json()
            logger.debug(resp)
            self._extract_token(resp)
            self._extract_token_type(resp)
            self._extract_user(resp)
            return resp
        except json.JSONDecodeError:
            raise KairnialAuthServiceError(
                message=MESSAGE_INVALID_RESPONSE,
                status=400
            )

    def _extract_token_type(self, response: dict):
        """
        extract token from authentication response
        :param response:
        :return:
        """
        self.token_type = response.get('token_type')
        return self.token_type

    def _extract_token(self, response: dict):
        """
        extract token from authentication response
        :param response:
        :return:
        """
        self.token = response.get('access_token')
        return self.token

    def _extract_user(self, response: dict):
        """
        Extract User object from
        :param response:
        :return:
        """
        resp_user = response.get('user', {})
        user = User()
        user.first_name = resp_user.get('first_name')
        user.last_name = resp_user.get('last_name')
        user.email = resp_user.get('email')
        user.uuid = resp_user.get('uuid')
        self.user = user
        return self.user
