from netbox.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_keycloak_oidc:status',
        link_text='Keycloak OIDC Status',
        staff_only=True,
    ),
)
