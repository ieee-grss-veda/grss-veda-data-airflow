#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Default configuration for the Airflow webserver."""
from __future__ import annotations


from flask_appbuilder.security.manager import AUTH_OAUTH

from airflow.auth.managers.fab.security_manager.override import (
    FabAirflowSecurityManagerOverride,
)
import logging
from typing import Any, Union
import os

basedir = os.path.abspath(os.path.dirname(__file__))

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None

# ----------------------------------------------------
# AUTHENTICATION CONFIG
# ----------------------------------------------------
# For details on how to set up each of the following authentication, see
# http://flask-appbuilder.readthedocs.io/en/latest/security.html# authentication-methods
# for details.

# The authentication type
# AUTH_OID : Is for OpenID
# AUTH_DB : Is for database
# AUTH_LDAP : Is for LDAP
# AUTH_REMOTE_USER : Is for using REMOTE_USER from web server
# AUTH_OAUTH : Is for OAuth
AUTH_TYPE = AUTH_OAUTH

# Uncomment to setup Full admin role name
# AUTH_ROLE_ADMIN = 'Admin'

# Uncomment and set to desired role to enable access without authentication
# AUTH_ROLE_PUBLIC = 'Viewer'

# Will allow user self registration
# AUTH_USER_REGISTRATION = True

# The recaptcha it's automatically enabled for user self registration is active and the keys are necessary
# RECAPTCHA_PRIVATE_KEY = PRIVATE_KEY
# RECAPTCHA_PUBLIC_KEY = PUBLIC_KEY

# Config for Flask-Mail necessary for user self registration
# MAIL_SERVER = 'smtp.gmail.com'
# MAIL_USE_TLS = True
# MAIL_USERNAME = 'yourappemail@gmail.com'
# MAIL_PASSWORD = 'passwordformail'
# MAIL_DEFAULT_SENDER = 'sender@gmail.com'

AUTH_ROLES_SYNC_AT_LOGIN = True  # Checks roles on every login
AUTH_USER_REGISTRATION = (
    True  # allow users who are not already in the FAB DB to register
)
# Make sure to replace this with the path to your security manager class
AUTH_ROLES_MAPPING = {
    "Viewer": ["Viewer"],
    "Admin": ["Admin"],
    "Dag_Launcher": ["DAG Launcher"],
}
# If you wish, you can add multiple OAuth providers.
OAUTH_PROVIDERS = [
    {
        "name": "keycloak",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": os.getenv("KEYCLOAK_CLIENT_ID"),
            "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET"),
            "api_base_url": f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/protocol/openid-connect",
            "client_kwargs": {"scope": "openid email profile"},
            "access_token_url": f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/protocol/openid-connect/token",
            "authorize_url": f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/protocol/openid-connect/auth",
            "server_metadata_url": f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/.well-known/openid-configuration",
            "request_token_url": None,
        },
    },
]


log = logging.getLogger(__name__)
log.setLevel(os.getenv("AIRFLOW__LOGGING__FAB_LOGGING_LEVEL", "INFO"))

FAB_ADMIN_ROLE = "Admin"
FAB_VIEWER_ROLE = "Viewer"
FAB_DAG_LAUNCHER_ROLE = "Dag_Launcher"
FAB_PUBLIC_ROLE = "Public"  # The "Public" role is given no permissions
KEYCLOAK_ADMIN_ROLE = os.getenv("KEYCLOAK_ADMIN_ROLE", "grss-veda-airflow-admin")
KEYCLOAK_VIEWER_ROLE = os.getenv("KEYCLOAK_VIEWER_ROLE", "grss-veda-airflow-viewer")
KEYCLOAK_DAG_LAUNCHER_ROLE = os.getenv("KEYCLOAK_DAG_LAUNCHER_ROLE", "GRSS-VEDA-dag-launcher")


def parse_keycloak_roles(roles_payload: list[str]) -> list[str]:
    # Parse the roles from Keycloak JWT token or userinfo endpoint.
    # Returns a list of role names.
    return roles_payload if roles_payload else []


def map_keycloak_roles_to_airflow(keycloak_roles: list[str]) -> list[str]:
    # Map Keycloak roles to Airflow FAB roles.
    # The expected output is a list of roles that FAB will use to Authorize the user.

    role_map = {
        KEYCLOAK_ADMIN_ROLE: FAB_ADMIN_ROLE,
        KEYCLOAK_VIEWER_ROLE: FAB_VIEWER_ROLE,
        KEYCLOAK_DAG_LAUNCHER_ROLE: FAB_DAG_LAUNCHER_ROLE,
    }

    mapped_roles = []
    for kc_role in keycloak_roles:
        if kc_role in role_map:
            mapped_roles.append(role_map[kc_role])

    # If no roles match, return Public role
    return mapped_roles if mapped_roles else [FAB_PUBLIC_ROLE]


class KeycloakAuthorizer(FabAirflowSecurityManagerOverride):
    # Custom security manager for Keycloak OAuth integration.
    # Extracts user info and roles from Keycloak and maps them to Airflow roles.

    def get_oauth_user_info(
        self, provider: str, resp: Any
    ) -> dict[str, Union[str, list[str]]]:
        # Creates the user info payload from Keycloak.
        # The user previously allowed your app to act on their behalf,
        # so now we can query the userinfo endpoint for their data.
        # Username and roles are extracted and returned to FAB.

        if provider != "keycloak":
            log.warning(f"Unexpected OAuth provider: {provider}")
            return {"username": "unknown", "role_keys": [FAB_PUBLIC_ROLE]}

        remote_app = self.appbuilder.sm.oauth_remotes[provider]

        # Get user info from Keycloak's userinfo endpoint
        userinfo_response = remote_app.get("userinfo")
        userinfo = userinfo_response.json()

        # Extract username (prefer 'preferred_username', fall back to 'email' or 'sub')
        username = userinfo.get("preferred_username") or userinfo.get("email") or userinfo.get("sub")

        # Extract roles from the token
        # Keycloak can provide roles in different places depending on configuration:
        # - In the access token's 'realm_access.roles'
        # - In the access token's 'resource_access.{client_id}.roles'
        # - In custom claims

        # First, try to get roles from the userinfo response
        keycloak_roles = []

        # Check for realm roles
        if "realm_access" in userinfo and "roles" in userinfo["realm_access"]:
            keycloak_roles.extend(userinfo["realm_access"]["roles"])

        # Check for client-specific roles
        client_id = os.getenv("KEYCLOAK_CLIENT_ID")
        if "resource_access" in userinfo and client_id in userinfo["resource_access"]:
            client_roles = userinfo["resource_access"][client_id].get("roles", [])
            keycloak_roles.extend(client_roles)

        # Check for roles in a custom 'roles' claim (some Keycloak configurations)
        if "roles" in userinfo:
            if isinstance(userinfo["roles"], list):
                keycloak_roles.extend(userinfo["roles"])

        # Parse and map roles
        parsed_roles = parse_keycloak_roles(keycloak_roles)
        airflow_roles = map_keycloak_roles_to_airflow(parsed_roles)

        log.info(f"User info from Keycloak: username={username}, keycloak_roles={parsed_roles}, airflow_roles={airflow_roles}")

        return {
            "username": f"keycloak_{username}",
            "email": userinfo.get("email"),
            "first_name": userinfo.get("given_name", ""),
            "last_name": userinfo.get("family_name", ""),
            "role_keys": airflow_roles
        }


SECURITY_MANAGER_CLASS = KeycloakAuthorizer
# The default user self registration role
# AUTH_USER_REGISTRATION_ROLE = "Public"

# When using OAuth Auth, uncomment to setup provider(s) info
# Google OAuth example:
# OAUTH_PROVIDERS = [{
#   'name':'google',
#     'token_key':'access_token',
#     'icon':'fa-google',
#         'remote_app': {
#             'api_base_url':'https://www.googleapis.com/oauth2/v2/',
#             'client_kwargs':{
#                 'scope': 'email profile'
#             },
#             'access_token_url':'https://accounts.google.com/o/oauth2/token',
#             'authorize_url':'https://accounts.google.com/o/oauth2/auth',
#             'request_token_url': None,
#             'client_id': GOOGLE_KEY,
#             'client_secret': GOOGLE_SECRET_KEY,
#         }
# }]

# When using LDAP Auth, setup the ldap server
# AUTH_LDAP_SERVER = "ldap://ldapserver.new"

# When using OpenID Auth, uncomment to setup OpenID providers.
# example for OpenID authentication
# OPENID_PROVIDERS = [
#    { 'name': 'Yahoo', 'url': 'https://me.yahoo.com' },
#    { 'name': 'AOL', 'url': 'http://openid.aol.com/<username>' },
#    { 'name': 'Flickr', 'url': 'http://www.flickr.com/<username>' },
#    { 'name': 'MyOpenID', 'url': 'https://www.myopenid.com' }]

# ----------------------------------------------------
# Theme CONFIG
# ----------------------------------------------------
# Flask App Builder comes up with a number of predefined themes
# that you can use for Apache Airflow.
# http://flask-appbuilder.readthedocs.io/en/latest/customizing.html#changing-themes
# Please make sure to remove "navbar_color" configuration from airflow.cfg
# in order to fully utilize the theme. (or use that property in conjunction with theme)
# APP_THEME = "bootstrap-theme.css"  # default bootstrap
# APP_THEME = "amelia.css"
# APP_THEME = "cerulean.css"
# APP_THEME = "cosmo.css"
# APP_THEME = "cyborg.css"
# APP_THEME = "darkly.css"
# APP_THEME = "flatly.css"
# APP_THEME = "journal.css"
# APP_THEME = "lumen.css"
# APP_THEME = "paper.css"
# APP_THEME = "readable.css"
# APP_THEME = "sandstone.css"
# APP_THEME = "simplex.css"
# APP_THEME = "slate.css"
# APP_THEME = "solar.css"
# APP_THEME = "spacelab.css"
# APP_THEME = "superhero.css"
# APP_THEME = "united.css"
# APP_THEME = "yeti.css"
