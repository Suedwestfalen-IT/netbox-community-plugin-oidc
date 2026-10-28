from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .pipeline import REQUEST_TOKENS_ATTR


@receiver(user_logged_in, dispatch_uid='netbox_keycloak_oidc_store_tokens')
def store_tokens(sender, request, user, **kwargs):
    """
    Persist the tokens of a Keycloak login in the (freshly cycled) session.
    """
    tokens = getattr(request, REQUEST_TOKENS_ATTR, None) if request is not None else None
    if tokens:
        request.session.update(tokens)
