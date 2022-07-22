from django.urls import path

from .views import ClientlessPasswordAuthenticationView, \
    ClientlessAPIKeyAuthenticationView, \
    ClientlessRefreshTokenAuthenticationView

# The API URLs are now determined automatically by the router.
urlpatterns = [
    path('password', ClientlessPasswordAuthenticationView.as_view()),
    path('key', ClientlessAPIKeyAuthenticationView.as_view()),
    path('renew', ClientlessRefreshTokenAuthenticationView.as_view()),
]
