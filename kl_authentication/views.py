"""
Authentication views
"""
import os

from django.utils.translation import gettext as _
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiParameter, OpenApiExample
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import JSON_CONTENT_TYPE
from .decorators import handle_auth_ws_error
from .serializers import AuthServiceErrorSerializer
from .serializers import ClientlessPasswordAuthenticationSerializer, \
    AuthResponseSerializer, ClientlessAPIKeyAuthenticationSerializer, \
    ClientlessRefreshTokenAuthenticationSerializer
from .services import KairnialAuthentication

default_client_example = OpenApiExample(
    name='Default clientID',
    value=os.environ.get('DEFAULT_KAIRNIAL_CLIENT_ID', '')
)

default_app_user_id_example = OpenApiExample(
    name='Default AppUserId',
    value=os.environ.get('DEFAULT_KAIRNIAL_USER_ID', '')
)

client_parameters = [
    OpenApiParameter("client_id", OpenApiTypes.STR, OpenApiParameter.PATH,
                     exclude=True,
                     description=_("Client ID obtain from Kairnial support"),
                     examples=[default_client_example]),
    OpenApiParameter('X-App-User-Id', OpenApiTypes.STR, OpenApiParameter.HEADER,
                     description=_("A user identifier to be paired with the M2M token"),
                     required=False, examples=[default_app_user_id_example])
]


class ClientlessPasswordAuthenticationView(APIView):
    """
    Create an authentication token from user/password
    """
    permission_classes = []

    @extend_schema(
        summary=_("Get a token from user / password"),
        description=_("Create token from username / password authentication"),
        parameters=client_parameters,
        request=ClientlessPasswordAuthenticationSerializer,
        responses={200: AuthResponseSerializer, 400: OpenApiTypes.OBJECT, 503: AuthServiceErrorSerializer},
        methods=["POST"]
    )
    @handle_auth_ws_error
    def post(self, request, client_id):
        serializer = ClientlessPasswordAuthenticationSerializer(data=request.data)
        if serializer.is_valid():
            ka = KairnialAuthentication(client_id=client_id)
            auth_response = ka.password_authentication(
                username=serializer.validated_data.get('email'),
                password=serializer.validated_data.get('password'))
            resp_serializer = AuthResponseSerializer(auth_response)
            return Response(resp_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, content_type=JSON_CONTENT_TYPE,
                            status=status.HTTP_400_BAD_REQUEST)


class ClientlessAPIKeyAuthenticationView(APIView):
    """
    Create an authentication token from user/password
    """
    permission_classes = []

    @extend_schema(
        summary=_("Get a token from API key"),
        description=_("Create token from API key / secret authentication"),
        parameters=client_parameters,
        responses={200: AuthResponseSerializer, 400: OpenApiTypes.OBJECT, 503: AuthServiceErrorSerializer},
        request=ClientlessAPIKeyAuthenticationSerializer,
        methods=["POST"]
    )
    @handle_auth_ws_error
    def post(self, request, client_id):
        serializer = ClientlessAPIKeyAuthenticationSerializer(data=request.data)
        if serializer.is_valid():
            ka = KairnialAuthentication(client_id=client_id)
            auth_response = ka.secrets_authentication(
                api_key=serializer.validated_data.get('api_key'),
                api_secret=serializer.validated_data.get('api_secret')
            )
            resp_serializer = AuthResponseSerializer(auth_response)
            return Response(resp_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, content_type=JSON_CONTENT_TYPE,
                            status=status.HTTP_400_BAD_REQUEST)


class ClientlessRefreshTokenAuthenticationView(APIView):
    """
    Obtain a bearer token using a refresh token
    """
    permission_classes = []

    @extend_schema(
        summary=_("Obtain a token using a refresh token"),
        description=_("Obtain a bearer token using a refresh token"),
        parameters=client_parameters,
        responses={200: AuthResponseSerializer, 400: OpenApiTypes.OBJECT, 503: AuthServiceErrorSerializer},
        request=ClientlessRefreshTokenAuthenticationSerializer,
        methods=["POST"]
    )
    @handle_auth_ws_error
    def post(self, request, client_id):
        serializer = ClientlessRefreshTokenAuthenticationSerializer(data=request.data)
        if serializer.is_valid():
            ka = KairnialAuthentication(client_id=client_id)
            auth_response = ka.refresh_authentication(
                refresh_token=serializer.validated_data.get('refresh_token'),
                provider_uuid=serializer.validated_data.get('provider_uuid'),
            )
            resp_serializer = AuthResponseSerializer(auth_response)
            return Response(resp_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, content_type=JSON_CONTENT_TYPE,
                            status=status.HTTP_400_BAD_REQUEST)
