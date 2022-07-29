"""
OpenAPI extensions
"""
from django.conf import settings
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object


class TokenScheme(OpenApiAuthenticationExtension):
    target_class = 'kl_authentication.authentication.KairnialTokenAuthentication'
    name = 'API Token authentication'
    match_subclasses = True
    priority = -1

    def get_security_definition(self, auto_schema):
        return build_bearer_security_scheme_object(
            header_name='Authorization',
            token_prefix='Bearer'
        )


def preprocess_exclude_clientless_routes(endpoints, **kwargs):
    """
        preprocessing hook that filters out {format} suffixed paths, in case
        format_suffix_patterns is used and {format} path params are unwanted.
    """
    client_id_path = f'{{{settings.CLIENT_ID_VARIABLE}}}'
    return [
        (path, path_regex, method, callback)
        for path, path_regex, method, callback in endpoints
        if client_id_path in path
    ]
