import logging

from django.core.management.base import BaseCommand

from netbox_keycloak_oidc.scim import sync_users


class Command(BaseCommand):
    help = 'Provision NetBox users from Keycloak via SCIM'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Show the changes without saving them')

    def handle(self, *args, dry_run=False, **options):
        log = logging.getLogger('netbox_keycloak_oidc.scim.command')
        log.setLevel(logging.INFO)
        handler = logging.StreamHandler(self.stdout)
        handler.setFormatter(logging.Formatter('%(levelname)-7s %(message)s'))
        log.addHandler(handler)
        log.propagate = False
        sync_users(dry_run=dry_run, log=log)
