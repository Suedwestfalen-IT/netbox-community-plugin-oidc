from netbox.jobs import JobRunner, system_job

from .jobs_meta import SCIM_JOB_NAME
from .scim import sync_users
from .utils import get_setting


@system_job(interval=int(get_setting('scim_sync_interval')))
class KeycloakScimSyncJob(JobRunner):
    """
    Periodically provisions NetBox users from Keycloak's SCIM API.
    """

    class Meta:
        name = SCIM_JOB_NAME

    def run(self, *args, **kwargs):
        sync_users(log=self.logger)
