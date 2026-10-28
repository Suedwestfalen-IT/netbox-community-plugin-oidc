from django.core.management.base import BaseCommand, CommandError

from netbox_keycloak_oidc.diagnostics import FAILED, OK, run_diagnostics


class Command(BaseCommand):
    help = 'Check the connection and client configuration of the Keycloak OIDC login'

    def handle(self, *args, **options):
        results = run_diagnostics()
        for result in results:
            style = {OK: self.style.SUCCESS, FAILED: self.style.ERROR}.get(result.status, self.style.WARNING)
            self.stdout.write(f'{style(f"[{result.status.upper():7}]")} {result.name}: {result.detail}')
        if any(result.status == FAILED for result in results):
            raise CommandError('Keycloak OIDC check failed')
