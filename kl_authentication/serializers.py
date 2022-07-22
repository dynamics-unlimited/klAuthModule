"""
Authentication serializers
"""
import os

from django.utils.translation import gettext as _
from rest_framework import serializers


class AuthServiceErrorSerializer(serializers.Serializer):
    """
    Serialize error from failing Kairnial WS
    """
    service_status = serializers.IntegerField(
        label=_('Service response status'),
    )
    service_message = serializers.CharField(
        label=_('Service response message'),
    )


class AuthUserSerializer(serializers.Serializer):
    uuid = serializers.UUIDField(label=_("User Unique ID"))
    first_name = serializers.CharField(label=_("User first name"))
    last_name = serializers.CharField(label=_("User last name"))
    full_name = serializers.CharField(label=_("User full name"))
    email = serializers.CharField(label=_("User email"))


class ClientlessPasswordAuthenticationSerializer(serializers.Serializer):
    """
    Password authentication class
    """
    email = serializers.CharField(label=_("User unique identifier"),
                                  help_text=_('Type your email here'),
                                  default=_('Type your email here'))
    password = serializers.CharField(label=_("Password"), help_text=_('Type your password here'),
                                     default=_('Type your password here'))


class ClientlessAPIKeyAuthenticationSerializer(serializers.Serializer):
    """
    API Key / Secret authentication class
    """
    api_key = serializers.CharField(
        label=_("User API key"),
        help_text=_("User API Key obtained from Kairnial support"),
        default=os.environ.get('DEFAULT_KAIRNIAL_API_KEY', ''))
    api_secret = serializers.CharField(
        label=_("User API secret"),
        help_text=_("User API secret obtained from Kairnial support"),
        default=os.environ.get('DEFAULT_KAIRNIAL_API_SECRET', ''))


class ClientlessRefreshTokenAuthenticationSerializer(serializers.Serializer):
    """
    Refresh token authentication class
    """
    refresh_token = serializers.CharField(
        label=_("Refresh token"),
        help_text=_("A refresh token obtained from a previous authentication"),
        default=os.environ.get('DEFAULT_KAIRNIAL_REFRESH_TOKEN', ''))


class AuthResponseSerializer(serializers.Serializer):
    """
    Serialize authentication response
    """
    user = AuthUserSerializer()
    token_type = serializers.CharField(
        label=_("Type of token"),
        help_text=_("Type of token to pass to the Authorization header")
    )
    access_token = serializers.CharField(
        label=_("Access token"),
        help_text=_("Access token to use in Authorization header, typically "
                    "'Authorization: <token_type> <access_token>. Access tokens for APIs last for 24 hours")
    )
    refresh_token = serializers.CharField(
        label=_("Refresh token"),
        help_text=_("Refresh token to prolonged acces_token"),
        required=False
    )
    expires_in = serializers.IntegerField(label=_("Number of seconds before token exipiration"))
    scope = serializers.CharField(label=_("Functions accessible using this token"))
