from datetime import UTC, datetime

from core.models import Job
from django.contrib.auth.mixins import UserPassesTestMixin
from django.shortcuts import render
from django.views.generic import View

from .diagnostics import FAILED, run_diagnostics
from .jobs_meta import SCIM_JOB_NAME
from .utils import SESSION_LAST_CHECK, SESSION_REFRESH_TOKEN, get_setting


class StatusView(UserPassesTestMixin, View):
    """
    Runs the Keycloak diagnostics and shows the effective plugin configuration (superusers only).
    """
    template_name = 'netbox_keycloak_oidc/status.html'

    def test_func(self):
        return self.request.user.is_superuser

    def get(self, request):
        results = run_diagnostics(request)
        last_check = request.session.get(SESSION_LAST_CHECK)
        settings = {
            name: get_setting(name) for name in (
                'role_sources', 'required_roles', 'superuser_roles', 'group_mapping', 'auto_create_groups',
                'remove_unmapped_groups', 'session_check_interval', 'session_check_fail_closed',
                'logout_from_keycloak', 'link_existing_users', 'sync_groups', 'sync_groups_prefix',
                'sync_groups_exclude', 'scim_enabled', 'scim_endpoint', 'scim_client_id', 'scim_sync_interval',
                'scim_groups', 'scim_deactivate_missing',
            )
        }
        scim_jobs = Job.objects.filter(name=SCIM_JOB_NAME).order_by('-created')[:5] if settings['scim_enabled'] else []
        return render(request, self.template_name, {
            'results': results,
            'healthy': not any(r.status == FAILED for r in results),
            'settings': settings,
            'keycloak_session': SESSION_REFRESH_TOKEN in request.session,
            'scim_jobs': scim_jobs,
            'last_check': datetime.fromtimestamp(last_check, tz=UTC) if last_check else None,
        })
