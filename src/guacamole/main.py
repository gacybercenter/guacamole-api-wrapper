import socket
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
socket.setdefaulttimeout(0.5)


class session:
    """
    Guacamole Session Class. Used to interface with the Guacamole API.
    
    Example usage for getting the current Guacamole users:
    gconn = guacamole.session('https://guacamole.org',
                              'mysql',
                              guac_user,
                              guac_pass)
    users = gconn.list_users()
    """

    def __init__(self,
                 host: str,
                 data_source: str,
                 username: str,
                 password: str):
        self.host = host
        self.username = username
        self.password = password
        self.data_source = data_source
        self.api_url = f"{self.host}/api/session/data/{self.data_source}"
        self.token = self.generate_token()
        self.params = {"token": self.token}

    def generate_token(self) -> object:
        """Returns a token"""

        return requests.post(
            f"{self.host}/api/tokens",
            data={"username": self.username, "password": self.password},
            verify=False,
            timeout=20,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        ).json()['authToken']

    def delete_token(self) -> object:
        """Deletes a token"""

        return requests.delete(
            f"{self.host}/api/tokens/{self.token}",
            params=self.params,
            verify=False,
            timeout=20
        )

    def list_schema_users(self) -> object:
        """Returns schema for user attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/userAttributes",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_schema_groups(self) -> object:
        """Returns schema for group attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/userGroupAttributes",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_schema_connections(self) -> object:
        """Returns schema for connection attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/connectionAttributes",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_schema_sharing(self) -> object:
        """Returns schema for sharing attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/sharingProfileAttributes",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_schema_connection_group(self) -> object:
        """Returns schema for connection group attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/connectionGroupAttributes",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_schema_protocols(self) -> object:
        """Returns schema for protocols attributes"""

        return json.dumps(requests.get(
            f"{self.api_url}/schema/protocols",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_patches(self) -> object:
        """
        Returns patches
        TODO: NEED TO EXPLORE FURTHER API CAPABILITIES FROM THIS PATH
        """

        return json.dumps(requests.get(
            f"{self.host}/api/patches",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_languages(self) -> object:
        """Returns available locales"""

        return json.dumps(requests.get(
            f"{self.host}/api/languages",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_extensions(self) -> object:
        """
        Returns details for installed extensions
        TODO: VALIDATE FUNCTION OPERATES
        """

        return json.dumps(requests.get(
            f"{self.host}/api/session/ext/{self.data_source}",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_history_users(self) -> object:
        """Returns user history"""

        return json.dumps(requests.get(
            f"{self.api_url}/history/users",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_history_connections(self) -> object:
        """Returns user connections"""

        return json.dumps(requests.get(
            f"{self.api_url}/history/connections",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_users(self) -> object:
        """Returns users"""

        return json.dumps(requests.get(
            f"{self.api_url}/users",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_user(self,
                    username: str) -> object:
        """Returns users details"""

        return json.dumps(requests.get(
            f"{self.api_url}/users/{username}",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_user_permissions(self,
                                username: str) -> object:
        """Returns users permissions"""

        return json.dumps(requests.get(
            f"{self.api_url}/users/{username}/permissions",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_user_effective_permissions(self,
                                          username: str) -> object:
        """Returns users efffective permissions"""

        return json.dumps(requests.get(
            f"{self.api_url}/users/{username}/effectivePermissions",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_user_groups(self,
                           username: str) -> object:
        """Returns users groups"""

        return json.dumps(requests.get(
            f"{self.api_url}/users/{username}/userGroups",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_user_history(self,
                            username: str) -> object:
        """Returns users history"""

        return json.dumps(requests.get(
            f"{self.api_url}/users/{username}/history",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_self(self) -> object:
        """Returns current user details"""

        return json.dumps(requests.get(
            f"{self.api_url}/self",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def create_user(self,
                    username: str,
                    password: str,
                    attributes: dict = None) -> requests.Response:
        """Creates user"""

        return requests.post(
            f"{self.api_url}/users",
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=20,
            params=self.params,
            json={
                "username": username,
                "password": password,
                "attributes": {
                    "disabled": attributes.get("disabled", ""),
                    "expired": attributes.get("expired", ""),
                    "access-window-start": attributes.get("access-window-start", ""),
                    "access-window-end": attributes.get("access-window-end", ""),
                    "valid-from": attributes.get("valid-from", ""),
                    "valid-until": attributes.get("valid-until", ""),
                    "timezone": attributes.get("timezone", ""),
                    "guac-full-name": attributes.get("guac-full-name", ""),
                    "guac-organization": attributes.get("guac-organization", ""),
                    "guac-organizational-role": attributes.get("guac-organizational-role", "")
                }
            }
        )

    def update_user(self,
                    username: str,
                    attributes: dict = None) -> requests.Response:
        """Updates a user"""

        return requests.put(
            f"{self.api_url}/users/{username}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "username": username,
                "attributes": {
                    "guac-email-address": attributes.get("guac-email-address", None),
                    "guac-organizational-role": attributes.get("guac-organizational-role", None),
                    "guac-full-name": attributes.get("guac-full-name", None),
                    "expired": attributes.get("expired", ""),
                    "timezone": attributes.get("timezone", None),
                    "access-window-start": attributes.get("access-window-start", ""),
                    "guac-organization": attributes.get("guac-organization", None),
                    "access-window-end": attributes.get("access-window-end", ""),
                    "disabled": attributes.get("disabled", ""),
                    "valid-until": attributes.get("valid-until", ""),
                    "valid-from": attributes.get("valid-from", "")
                }
            },
            verify=False,
            timeout=20
        )

    def update_user_password(self,
                             username: str,
                             oldpassword: str,
                             newpassword: str) -> requests.Response:
        """Updates a user Password"""

        return requests.put(
            f"{self.api_url}/users/{username}/password",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "oldPassword": oldpassword,
                "newPassword": newpassword
            },
            verify=False,
            timeout=20
        )

    def update_user_group(self,
                          username: str,
                          groupname: str,
                          operation: str = "add") -> requests.Response | str:
        """Assign to or Remove user from group"""

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/users/{username}/userGroups",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": "/",
                        "value": groupname
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def update_user_connection(self,
                               username: str,
                               connectionid: str,
                               operation: str = "add",
                               conn_type: str = "connection") -> requests.Response | str:
        """
        Change a user Connections
        TODO: VALIDATE FUNCTION OPERATES
        """

        if conn_type == "connection":
            path = f"/connectionPermissions/{connectionid}"
        elif conn_type == "group":
            path = f"/connectionGroupPermissions/{connectionid}"
        elif conn_type == "sharing profile":
            path = f"/sharingProfilePermissions/{connectionid}"
        else:
            return "Invalid Connection Type, requires 'connection', 'group', or 'sharing profile'"

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/users/{username}/permissions",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": path,
                        "value": "READ"
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires 'add' or 'remove'"

    def update_user_permissions(self,
                                username: str,
                                operation: str = "add",
                                cuser: bool = False,
                                cusergroup: bool = False,
                                cconnect: bool = False,
                                cconnectgroup: bool = False,
                                cshare: bool = False,
                                admin: bool = False) -> requests.Response | str:
        """Change a user Connections"""

        path = f"/userPermissions/{username}"

        permissions = []

        permissions.append({
            "op": operation,
            "path": path,
            "value": "UPDATE"
        })

        if cuser:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                "value": "CREATE_USER"
            })

        if cusergroup:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_USER_GROUP"
            })

        if cconnect:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_CONNECTION"
            })

        if cconnectgroup:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_CONNECTION_GROUP"
            })

        if cshare:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_SHARING_PROFILE"
            })

        if admin:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "ADMINISTER"
            })

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/users/{username}/permissions",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=permissions,
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def delete_user(self,
                    username: str) -> requests.Response:
        """Deletes user"""

        return requests.delete(
            f"{self.api_url}/users/{username}",
            params=self.params,
            verify=False,
            timeout=20
        )

    def list_usergroups(self) -> object:
        """Returns user groups"""

        return json.dumps(requests.get(
            f"{self.api_url}/userGroups",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def detail_usergroup(self, groupname: str) -> object:
        """Returns user groups"""

        return json.dumps(requests.get(
            f"{self.api_url}/userGroups/{groupname}",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def update_usergroup_member(self,
                                username: str,
                                groupname: str,
                                operation: str = "add") -> requests.Response | str:
        """Assign to or Remove user from group"""

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/userGroups/{groupname}/memberUsers",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": "/",
                        "value": username
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def update_usergroup_membergroup(self,
                                     identifier: int,
                                     groupname: str,
                                     operation: str = "add") -> requests.Response | str:
        """Assign to or Remove group from group"""

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/userGroups/{groupname}/memberUserGroup",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": "/",
                        "value": str(identifier)
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def update_usergroup_parentgroup(self,
                                     identifier: int,
                                     groupname: str,
                                     operation: str = "add") -> requests.Response | str:
        """Assign to or Remove group from group"""

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/userGroups/{groupname}/userGroups",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": "/",
                        "value": str(identifier)
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def update_usergroup_permissions(self,
                                     groupname: str,
                                     operation: str = "add",
                                     cuser: bool = False,
                                     cusergroup: bool = False,
                                     cconnect: bool = False,
                                     cconnectgroup: bool = False,
                                     cshare: bool = False,
                                     admin: bool = False) -> requests.Response | str:
        """Update permissions of user group"""

        permissions = []

        permissions.append({
            "op": operation,
            "path": f"/connectionPermissions/{groupname}",
            "value": "READ"
        })

        if cuser:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                "value": "CREATE_USER"
            })

        if cusergroup:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_USER_GROUP"
            })

        if cconnect:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_CONNECTION"
            })

        if cconnectgroup:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_CONNECTION_GROUP"
            })

        if cshare:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "CREATE_SHARING_PROFILE"
            })

        if admin:
            permissions.append({
                "op": operation,
                "path": "/systemPermissions",
                        "value": "ADMINISTER"
            })

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/userGroups/{groupname}/permissions",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=permissions,
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def update_usergroup_connection(self,
                                    connection_id: int,
                                    groupname: str,
                                    operation: str = "add") -> requests.Response | str:
        """Assign to or Remove connection from group"""

        if operation in ["add", "remove"]:
            return requests.patch(
                f"{self.api_url}/userGroups/{groupname}/permissions",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json=[
                    {
                        "op": operation,
                        "path": f"/connectionPermissions/{str(connection_id)}",
                        "value": "READ"
                    }
                ],
                verify=False,
                timeout=20
            )
        return "Invalid Operation, requires (add or remove)"

    def create_usergroup(self,
                         groupname: str,
                         attributes: dict = None) -> requests.Response:
        """Creates a user group"""

        return requests.post(
            f"{self.api_url}/userGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "identifier": groupname,
                "attributes": {
                    "disabled": attributes.get("disabled", "")
                }
            },
            verify=False,
            timeout=20
        )

    def update_usergroup(self,
                         groupname: str,
                         attributes: dict = None) -> requests.Response:
        """Updates a user group"""

        return requests.put(
            f"{self.api_url}/userGroups/{groupname}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "identifier": groupname,
                "attributes": {
                    "disabled": attributes.get("disabled", "")
                }
            },
            verify=False,
            timeout=20
        )

    def delete_usergroup(self,
                         user_group: str) -> requests.Response:
        """Deletes a user group"""

        return requests.delete(
            f"{self.api_url}/userGroups/{user_group}",
            params=self.params,
            verify=False,
            timeout=20
        )

    def list_tunnels(self) -> object:
        """Returns tunnels"""

        return json.dumps(requests.get(
            f"{self.host}/api/session/tunnels",
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def detail_tunnels(self,
                       tunnel_id: int) -> object:
        """Returns tunnels"""

        return json.dumps(requests.get(
            f"{self.host}/api/session/tunnels/{str(tunnel_id)}/activeConnection/connection/sharingProfiles",
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def list_connections(self,
                         active: bool = False) -> object:
        """
        NOTE: Returns connections or active connections
        * @params active (boolean value) toggles viewing active connections
        """

        if active:
            host = f"{self.api_url}/activeConnections"
        else:
            host = f"{self.api_url}/connections"

        return json.dumps(requests.get(
            host,
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def detail_connection(self,
                          identifier: int,
                          option: str = None) -> object:
        """
        NOTE: Returns connection details and parameters
        * @params option (None, params, history, sharing)
        """

        if not option:
            host = f"{self.api_url}/connections/{str(identifier)}"
        elif option == "params":
            host = f"{self.api_url}/connections/{str(identifier)}/parameters"
        elif option == "history":
            host = f"{self.api_url}/connections/{str(identifier)}/history"
        elif option == "sharing":
            host = f"{self.api_url}/connections/{str(identifier)}/sharingProfiles"
        else:
            return "Invalid option, requires no entry or (params, history, or sharing)"

        return json.dumps(requests.get(
            host,
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def kill_active_connection(self,
                               connection_id: str) -> requests.Response:
        """Kill an active connection to a hosted system"""

        return requests.patch(
            f"{self.api_url}/activeConnections",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=[
                {
                    "op": "remove",
                    "path": f"/{connection_id}"
                }
            ],
            verify=False,
            timeout=20
        )

    def manage_connection(self,
                          request: str,
                          protocol: str,
                          name: str,
                          parent_identifier: int,
                          identifier: int = None,
                          parameters: dict = None,
                          attributes: dict = None) -> requests.Response | str:
        """
        NOTE Creates an SSH connection
        * @param request = post (create) or put (update)
        * @param protocol = ssh, rdp, vnc, telnet, kubernetes
        * @param parent_identifier is required if placing in a specific connection group
        * @param parameters = {"hostname": "", "port": "", "username": "", "password": ""}
        * @param attributes = {"max-connections": "", "max-connections-per-user": "" }
        """

        if protocol == "vnc":
            parameters = {
                "port": parameters.get("port", ""),
                "read-only": parameters.get("read-only", ""),
                "swap-red-blue": parameters.get("swap-red-blue", ""),
                "cursor": parameters.get("cursor", ""),
                "color-depth": parameters.get("color-depth", ""),
                "clipboard-encoding": parameters.get("clipboard-encoding", ""),
                "disable-copy": parameters.get("disable-copy", ""),
                "disable-paste": parameters.get("disable-paste", ""),
                "dest-port": parameters.get("dest-port", ""),
                "recording-exclude-output": parameters.get("recording-exclude-output", ""),
                "recording-exclude-mouse": parameters.get("recording-exclude-mouse", ""),
                "recording-include-keys": parameters.get("recording-include-keys", ""),
                "create-recording-path": parameters.get("create-recording-path", ""),
                "enable-sftp": parameters.get("enable-sftp", "true"),
                "sftp-port": parameters.get("sftp-port", ""),
                "sftp-server-alive-interval": parameters.get("sftp-server-alive-interval", ""),
                "enable-audio": parameters.get("enable-audio", ""),
                "audio-servername": parameters.get("audio-servername", ""),
                "sftp-directory": parameters.get("sftp-directory", ""),
                "sftp-root-directory": parameters.get("sftp-root-directory", ""),
                "sftp-passphrase": parameters.get("sftp-passphrase", ""),
                "sftp-private-key": parameters.get("sftp-private-key", ""),
                "sftp-username": parameters.get("sftp-username", ""),
                "sftp-password": parameters.get("sftp-password", ""),
                "sftp-host-key": parameters.get("sftp-host-key", ""),
                "sftp-hostname": parameters.get("sftp-hostname", ""),
                "recording-name": parameters.get("recording-name", ""),
                "recording-path": parameters.get("recording-path", ""),
                "dest-host": parameters.get("dest-host", ""),
                "password": parameters.get("password", ""),
                "username": parameters.get("username", ""),
                "hostname": parameters.get("hostname", ""),
            }

        if protocol == "ssh":
            parameters = {
                "port": parameters.get("port", ""),
                "read-only": parameters.get("read-only", ""),
                "swap-red-blue": parameters.get("swap-red-blue", ""),
                "cursor": parameters.get("cursor", ""),
                "color-depth": parameters.get("color-depth", ""),
                "clipboard-encoding": parameters.get("clipboard-encoding", ""),
                "disable-copy": parameters.get("disable-copy", ""),
                "disable-paste": parameters.get("disable-paste", ""),
                "dest-port": parameters.get("dest-port", ""),
                "recording-exclude-output": parameters.get("recording-exclude-output", ""),
                "recording-exclude-mouse": parameters.get("recording-exclude-mouse", ""),
                "recording-include-keys": parameters.get("recording-include-keys", ""),
                "create-recording-path": parameters.get("create-recording-path", ""),
                "enable-sftp": parameters.get("enable-sftp", ""),
                "sftp-port": parameters.get("sftp-port", ""),
                "sftp-server-alive-interval": parameters.get("sftp-server-alive-interval", ""),
                "enable-audio": parameters.get("enable-audio", ""),
                "color-scheme": parameters.get("color-scheme", ""),
                "font-size": parameters.get("font-size", ""),
                "scrollback": parameters.get("scrollback", ""),
                "timezone": parameters.get("timezone", None),
                "server-alive-interval": parameters.get("server-alive-interval", ""),
                "backspace": parameters.get("backspace", ""),
                "terminal-type": parameters.get("terminal-type", ""),
                "create-typescript-path": parameters.get("create-typescript-path", ""),
                "hostname": parameters.get("hostname", ""),
                "host-key": parameters.get("host-key", ""),
                "private-key": parameters.get("private-key", ""),
                "username": parameters.get("username", ""),
                "password": parameters.get("password", ""),
                "passphrase": parameters.get("passphrase", ""),
                "font-name": parameters.get("font-name", ""),
                "command": parameters.get("command", ""),
                "locale": parameters.get("locale", ""),
                "typescript-path": parameters.get("typescript-path", ""),
                "typescript-name": parameters.get("typescript-name", ""),
                "recording-path": parameters.get("recording-path", ""),
                "recording-name": parameters.get("recording-name", ""),
                "sftp-root-directory": parameters.get("sftp-root-directory", ""),
            }

        if protocol == "rdp":
            parameters = {
                "port": parameters.get("port", ""),
                "read-only": parameters.get("read-only", ""),
                "swap-red-blue": parameters.get("swap-red-blue", ""),
                "cursor": parameters.get("cursor", ""),
                "color-depth": parameters.get("color-depth", ""),
                "clipboard-encoding": parameters.get("clipboard-encoding", ""),
                "disable-copy": parameters.get("disable-copy", ""),
                "disable-paste": parameters.get("disabled-paste", ""),
                "dest-port": parameters.get("dest-port", ""),
                "recording-exclude-output": parameters.get("recording-exclude-output" ""),
                "recording-exclude-mouse": parameters.get("recording-exclude-mouse", ""),
                "recording-include-keys": parameters.get("recording-include-keys", ""),
                "create-recording-path": parameters.get("create-recording-path", ""),
                "enable-sftp": parameters.get("enable-sftp", ""),
                "sftp-port": parameters.get("sftp-port", ""),
                "sftp-server-alive-interval": parameters.get("sftp-server-alive-interval", ""),
                "enable-audio": parameters.get("enable-audio", ""),
                "security": parameters.get("security", ""),
                "disable-auth": parameters.get("disable-auth", ""),
                "ignore-cert": parameters.get("ignore-cert", ""),
                "gateway-port": parameters.get("gateway-port", ""),
                "gateway-hostname": parameters.get("gateway-hostname", ""),
                "gateway-username": parameters.get("gateway-username", ""),
                "gateway-password": parameters.get("gateway-password", ""),
                "gateway-domain": parameters.get("gateway-domain", ""),
                "server-layout": parameters.get("server-layout", ""),
                "timezone": parameters.get("timezone", ""),
                "console": parameters.get("console", ""),
                "width": parameters.get("width", ""),
                "height": parameters.get("height", ""),
                "dpi": parameters.get("dpi", ""),
                "resize-method": parameters.get("resize-method", ""),
                "console-audio": parameters.get("console-audio", ""),
                "disable-audio": parameters.get("disable-audio", ""),
                "enable-audio-input": parameters.get("enable-audio-input", ""),
                "enable-printing": parameters.get("enable-printing", ""),
                "enable-drive": parameters.get("enable-drive", ""),
                "create-drive-path": parameters.get("create-drive-path", ""),
                "enable-wallpaper": parameters.get("enable-wallpaper", ""),
                "enable-theming": parameters.get("enable-theming", ""),
                "enable-font-smoothing": parameters.get("enable-font-smoothing", ""),
                "enable-full-window-drag": parameters.get("enable-full-window-drag", ""),
                "enable-desktop-composition": parameters.get("enable-desktop-composition", ""),
                "enable-menu-animations": parameters.get("enable-menu-animations", ""),
                "disable-bitmap-caching": parameters.get("disable-bitmap-caching", ""),
                "disable-offscreen-caching": parameters.get("disable-offscreen-caching", ""),
                "disable-glyph-caching": parameters.get("disable-glyph-caching", ""),
                "preconnection-id": parameters.get("preconnection-id", ""),
                "hostname": parameters.get("hostname", ""),
                "username": parameters.get("username", ""),
                "password": parameters.get("password", ""),
                "domain": parameters.get("domain", ""),

                "initial-program": parameters.get("initial-program", ""),
                "client-name": parameters.get("client-name", ""),

                "printer-name": parameters.get("printer-name", ""),
                "drive-name": parameters.get("drive-name", ""),
                "drive-path": parameters.get("drive-path", ""),
                "static-channels": parameters.get("static-channels", ""),

                "remote-app": parameters.get("remote-app", ""),
                "remote-app-dir": parameters.get("remote-app-dir", ""),
                "remote-app-args": parameters.get("remote-app-args", ""),

                "preconnection-blob": parameters.get("preconnection-blob", ""),
                "load-balance-info": parameters.get("load-balance-info", ""),
                "recording-path": parameters.get("recording-path", ""),
                "recording-name": parameters.get("recording-name", ""),
                "sftp-hostname": parameters.get("sftp-hostname", ""),
                "sftp-host-key": parameters.get("sftp-host-key", ""),
                "sftp-username": parameters.get("sftp-username", ""),
                "sftp-password": parameters.get("sftp-password", ""),
                "sftp-private-key": parameters.get("sftp-private-key", ""),
                "sftp-passphrase": parameters.get("sftp-passphrase", ""),
                "sftp-root-directory": parameters.get("sftp-root-directory", ""),
                "sftp-directory": parameters.get("sftp-directory", ""),
            }

        if protocol == "telnet":
            parameters = {
                "port": parameters.get("port", ""),
                "read-only": parameters.get("read-only", ""),
                "swap-red-blue": parameters.get("swap-red-blue", ""),
                "cursor": parameters.get("cursor", ""),
                "color-depth": parameters.get("color-depth", ""),
                "clipboard-encoding": parameters.get("clipboard-encoding", ""),
                "disable-copy": parameters.get("disable-copy", ""),
                "disable-paste": parameters.get("disable-paste", ""),
                "dest-port": parameters.get("dest-port", ""),
                "recording-exclude-output": parameters.get("recording-exclude-output", ""),
                "recording-exclude-mouse": parameters.get("recording-exclude-mouse", ""),
                "recording-include-keys": parameters.get("recording-include-keys", ""),
                "create-recording-path": parameters.get("create-recording-path", ""),
                "enable-sftp": parameters.get("enable-sftp", ""),
                "sftp-port": parameters.get("sftp-port", ""),
                "sftp-server-alive-interval": parameters.get("sftp-server-alive-interval", ""),
                "enable-audio": parameters.get("enable-audio", ""),
                "color-scheme": parameters.get("color-scheme", ""),
                "font-size": parameters.get("font-size", ""),
                "scrollback": parameters.get("scrollback", ""),
                "backspace": parameters.get("backspace", ""),
                "terminal-type": parameters.get("terminal-type", ""),
                "create-typescript-path": parameters.get("create-typescript-path", ""),
                "hostname": parameters.get("hostname", ""),
                "username": parameters.get("username", ""),
                "password": parameters.get("password", ""),
                "username-regex": parameters.get("username-regex", ""),
                "password-regex": parameters.get("password-regex", ""),
                "login-success-regex": parameters.get("login-success-regex", ""),
                "login-failure-regex": parameters.get("login-failure-regex", ""),
                "font-name": parameters.get("font-name", ""),
                "typescript-path": parameters.get("typescript-path", ""),
                "typescript-name": parameters.get("typescript-name", ""),
                "recording-path": parameters.get("recording-path", ""),
                "recording-name": parameters.get("recording-name", ""),
            }

        if protocol == "kubernetes":
            parameters = {
                "port": parameters.get("port", ""),
                "read-only": parameters.get("read-only", ""),
                "swap-red-blue": parameters.get("swap-red-blue", ""),
                "cursor": parameters.get("cursor", ""),
                "color-depth": parameters.get("color-depth", ""),
                "clipboard-encoding": parameters.get("clipboard-encoding", ""),
                "disable-copy": parameters.get("disable-copy", ""),
                "disable-paste": parameters.get("disable-paste", ""),
                "dest-port": parameters.get("dest-port", ""),
                "recording-exclude-output": parameters.get("recording-exclude-output", ""),
                "recording-exclude-mouse": parameters.get("recording-exclude-mouse", ""),
                "recording-include-keys": parameters.get("recording-include-keys", ""),
                "create-recording-path": parameters.get("create-recording-path", ""),
                "enable-sftp": parameters.get("enable-sftp", ""),
                "sftp-port": parameters.get("sftp-port", ""),
                "sftp-server-alive-interval": parameters.get("sftp-server-alive-interval", ""),
                "enable-audio": parameters.get("enable-audio", ""),
                "use-ssl": parameters.get("use-ssl", ""),
                "ignore-cert": parameters.get("ignore-cert", ""),
                "color-scheme": parameters.get("color-scheme", ""),
                "font-size": parameters.get("font-size", ""),
                "scrollback": parameters.get("scrollback", ""),
                "backspace": parameters.get("backspace", ""),
                "create-typescript-path": parameters.get("create-typescript-path", ""),
                "hostname": parameters.get("hostname", ""),
                "ca-cert": parameters.get("ca-cert", ""),
                "namespace": parameters.get("namespace", ""),
                "pod": parameters.get("pod", ""),
                "container": parameters.get("container", ""),
                "client-cert": parameters.get("client-cert", ""),
                "client-key": parameters.get("client-key", ""),
                "font-name": parameters.get("font-name", ""),
                "typescript-path": parameters.get("typescript-path", ""),
                "typescript-name": parameters.get("typescript-name", ""),
                "recording-path": parameters.get("recording-path", ""),
                "recording-name": parameters.get("recording-name", ""),
            }

        attributes = {
            "max-connections": attributes.get("max-connections", ""),
            "max-connections-per-user": attributes.get("max-connections-per-user", ""),
            "weight": attributes.get("weight", ""),
            "failover-only": attributes.get("failover-only", ""),
            "guacd-port": attributes.get("guacd-port", ""),
            "guacd-encryption": attributes.get("guacd-encryption", ""),
            "guacd-hostname": attributes.get("guacd-hostname", ""),
        }

        if request == "post":
            return requests.post(
                f"{self.api_url}/connections",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json={
                    "parentIdentifier": str(parent_identifier),
                    "name": name,
                    "protocol": protocol,
                    "parameters": parameters,
                    "attributes": attributes,
                },
                verify=False,
                timeout=20
            )
        if request == "put":
            return requests.put(
                f"{self.api_url}/connections",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json={
                    "parentIdentifier": str(parent_identifier),
                    "name": name,
                    "identifier": str(identifier),
                    "activeConnections": 0,
                    "protocol": protocol,
                    "parameters": parameters,
                    "attributes": attributes,
                },
                verify=False,
                timeout=20
            )
        return "Invalid request option, requires (post or put)"

    def delete_connection(self,
                          identifier: int) -> requests.Response:
        """Deletes a connection"""

        return requests.delete(
            f"{self.api_url}/connections/{str(identifier)}",
            params=self.params,
            verify=False,
            timeout=20
        )

    def list_connection_groups(self) -> object:
        """Returns all connection groups"""

        return json.dumps(requests.get(
            f"{self.api_url}/connectionGroups",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def list_connection_group_connections(self) -> object:
        """Returns all connection groups connections"""

        return json.dumps(requests.get(
            f"{self.api_url}/connectionGroups/ROOT/tree",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def details_sharing_profile(self,
                                sharing_id: int,
                                option: str) -> object:
        """Returns sharing profiles"""

        if not option:
            host = f"{self.host}/api/session/data/{self.data_source}/sharingProfiles/{str(sharing_id)}"
        elif option == "params":
            host = f"{self.host}/api/session/data/{self.data_source}/sharingProfiles/{str(sharing_id)}/parameters"

        return json.dumps(requests.get(
            host,
            verify=False,
            params=self.params,
        ).json(), indent=2)

    def details_connection_group_connections(self,
                                             identifier: str) -> object:
        """Returns specific connection group connections"""

        return json.dumps(requests.get(
            f"{self.api_url}/connectionGroups/{identifier}/tree",
            params=self.params,
            verify=False,
            timeout=20
        ).json(), indent=2)

    def create_connection_group(self,
                                group_name: str,
                                group_type: str,
                                parent_identifier: int = None,
                                attributes: dict = None) -> requests.Response:
        """Creates a connection group"""

        return requests.post(
            f"{self.api_url}/connectionGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "parentIdentifier": str(parent_identifier),
                "name": group_name,
                "type": group_type,
                "attributes": {
                    "max-connections": attributes.get("max-connections", ""),
                    "max-connections-per-user": attributes.get("max-connections-per-user", ""),
                    "enable-session-affinity": attributes.get("enable-session-affinity", "")
                }
            },
            verify=False,
            timeout=20
        )

    def update_connection_group(self,
                                identifier: str,
                                group_name: str,
                                group_type: str,
                                parent_identifier: int = None,
                                attributes: dict = None) -> requests.Response:
        """
        Updates a connection group
        TODO: IF parent_identifier IS NOT ROOT THEN int IS REQUIRED
        """

        return requests.put(
            f"{self.api_url}/connectionGroups/{identifier}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "parentIdentifier": str(parent_identifier),
                "identifier": identifier,
                "name": group_name,
                "type": group_type,
                "attributes": {
                    "max-connections": attributes.get("max-connections", ""),
                    "max-connections-per-user": attributes.get("max-connections-per-user", ""),
                    "enable-session-affinity": attributes.get("enable-session-affinity", "")
                }
            },
            verify=False,
            timeout=20
        )

    def delete_connection_group(self,
                                connection_group: str) -> requests.Response:
        """Deletes a connection group"""

        return requests.delete(
            f"{self.api_url}/connectionGroups/{connection_group}",
            params=self.params,
            verify=False,
            timeout=20
        )

    def list_sharing_profile(self) -> object:
        """Returns sharing profiles"""

        return json.dumps(requests.get(
            f"{self.api_url}/sharingProfiles",
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def details_sharing_profile(self,
                                sharing_id: int) -> object:
        """Returns sharing profiles"""

        return json.dumps(requests.get(
            f"{self.api_url}/sharingProfiles/{str(sharing_id)}",
            verify=False,
            timeout=20,
            params=self.params
        ).json(), indent=2)

    def create_sharing_profile(self,
                               primaryConnectionIdentifier: str,
                               name: str,
                               parameters: dict = None) -> requests.Response:
        """Creates connection sharing profile"""

        return requests.post(
            f"{self.api_url}/sharingProfiles",
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=20,
            params=self.params,
            json={
                "primaryConnectionIdentifier": primaryConnectionIdentifier,
                "name": name,
                "parameters": {
                    "read-only": parameters.get("read-only", "")
                },
                "attributes": {}
            }
        )

    def update_sharing_profile(self,
                               primaryConnectionIdentifier: str,
                               name: str,
                               identifier: str,
                               parameters: dict = None) -> requests.Response:
        """Updates connection sharing profile"""

        return requests.post(
            f"{self.api_url}/sharingProfiles/{identifier}",
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=20,
            params=self.params,
            json={
                "primaryConnectionIdentifier": primaryConnectionIdentifier,
                "name": name,
                "parameters": {
                    "read-only": parameters.get("read-only", "")
                },
                "attributes": {}
            }
        )

    def delete_sharing_profile(self,
                               identifier: str) -> requests.Response:
        """Deletes connection sharing profile"""

        return requests.delete(
            f"{self.api_url}/sharingProfiles/{identifier}",
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=20,
            params=self.params
        )
