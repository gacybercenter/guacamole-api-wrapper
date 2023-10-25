"""
Guacamole API Wrapper
"""
from socket import setdefaulttimeout
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
setdefaulttimeout(0.5)


class session:
    """
    Guacamole Session Class. Used to interface with the Guacamole API.

    Args:
        host (str): The hostname of the Guacamole server.
        data_source (str): The name of the data source.
        username (str): The username of the Guacamole user.
        password (str): The password of the Guacamole user.

    Returns:
        str: The response from the API request.

    Example: 
        For getting the current Guacamole users:
    gconn = guacamole.session('https://my.guacamole.org',
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
        self.session_url = f"{self.host}/api/session/data/{self.data_source}"
        self.tunnels_url = f"{self.host}/api/session/tunnels"
        self.token = self.generate_token()
        self.params = {"token": self.token}

    def generate_token(self) -> str | object:
        """
        Generates a token by sending a POST request to the API endpoint
        '/api/tokens' with the provided username and password.

        Args:
            None

        Returns:
            str | object: The authentication token extracted from the JSON response.
        """

        response = requests.post(
            f"{self.host}/api/tokens",
            data={"username": self.username, "password": self.password},
            verify=False,
            timeout=12,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        ).text

        try:
            return json.loads(response)['authToken']
        except json.JSONDecodeError:
            return response

    def delete_token(self) -> str | object:
        """
        Deletes the token associated with the API instance.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.host}/api/tokens/{self.token}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_users(self) -> str | object:
        """
        Retrieves a list of schema users from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/userAttributes",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_groups(self) -> str | object:
        """
        Returns the schema groups for user group attributes.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/userGroupAttributes",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_connections(self) -> str | object:
        """
        Retrieves the schema connection attributes from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/connectionAttributes",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_sharing_profiles(self) -> str | object:
        """
        Retrieves the schema for sharing profile attributes from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/sharingProfileAttributes",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_connection_groups(self) -> str | object:
        """
        Retrieves a list of connection group attributes from the schema API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/connectionGroupAttributes",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_schema_protocols(self) -> str | object:
        """
        Retrieves a list of schema protocols from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/schema/protocols",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_patches(self) -> str | object:
        """
        Retrieves a list of patches from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.host}/api/patches",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_languages(self) -> str | object:
        """
        Returns a JSON object containing a list of languages supported by the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.host}/api/languages",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_extensions(self) -> str | object:
        """
        Retrieves the details of the extensions for the current session.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.host}/api/session/ext/{self.data_source}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_history_users(self) -> str | object:
        """
        Generates a list of history users.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/history/users",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_history_connections(self) -> str | object:
        """
        Return a JSON string representation of the history connections.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/history/connections",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_users(self) -> str | object:
        """
        Generates a JSON formatted string containing a list of users.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_user(self,
                    username: str) -> str | object:
        """
        Detail a user by their username.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users/{username}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_user_permissions(self,
                                username: str) -> str | object:
        """
        Retrieves the detailed permissions of a user.

        Args:
            username (str): The username of the user for which to retrieve permissions.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users/{username}/permissions",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_user_effective_permissions(self,
                                          username: str) -> str | object:
        """
        Retrieves the effective permissions of a specific user.

        Args:
            username (str): The username of the user to retrieve permissions for.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users/{username}/effectivePermissions",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_user_groups(self,
                           username: str) -> str | object:
        """
        Retrieve the detailed information about the user groups for a given username.

        Args:
            username (str): The username for which to retrieve the user groups.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users/{username}/userGroups",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_user_history(self,
                            username: str) -> str | object:
        """
        Retrieves the detailed history of a user.

        Args:
            username (str): The username of the user whose history is to be retrieved.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/users/{username}/history",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_self(self) -> str | object:
        """
        Retrieves detailed information about the current session.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/self",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def create_user(self,
                    username: str,
                    password: str,
                    attributes: dict | None = None) -> str | object:
        """
        Create a new user.

        Args:
            username (str): The username of the user to create.
            password (str): The password of the user to create.
            attributes (dict, optional): A dictionary of attributes to create.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.post(
            f"{self.session_url}/users",
            headers={"Content-Type": "application/json"},
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
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_user(self,
                    username: str,
                    attributes: dict | None = None) -> str | object:
        """
        Updates a user's attributes in the database.

        Args:
            username (str): The username of the user to update.
            attributes (dict, optional): A dictionary of attributes to update.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.put(
            f"{self.session_url}/users/{username}",
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
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_user_password(self,
                             username: str,
                             oldpassword: str,
                             newpassword: str) -> str | object:
        """
        Update the password for a user.

        Args:
            username (str): The username of the user.
            oldpassword (str): The old password of the user.
            newpassword (str): The new password of the user.

        Returns:
           str | object: The request response JSON string or object        """

        response = requests.put(
            f"{self.session_url}/users/{username}/password",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "oldPassword": oldpassword,
                "newPassword": newpassword
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_user_group(self,
                          username: str,
                          groupnames: str | list,
                          operation: str = "add") -> str | object:
        """
        Update the user group for a specified username.

        Args:
            username (str): The username of the user.
            groupname (str | list): The group or groups to update.
            operation (str, optional): The operation to perform. Defaults to "add".
                                        Must be either "add" or "remove".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If the operation is not valid.
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(groupnames, str):
            groupnames = [groupnames]

        groups = [
            {
                "op": operation,
                "path": "/",
                "value": group
            } for group in groupnames
        ]

        response = requests.patch(
            f"{self.session_url}/users/{username}/userGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=groups,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_connection_permissions(self,
                                      username: str,
                                      identifiers: str | list,
                                      operation: str = "add",
                                      permission: str = "connection") -> str | object:
        """
        Update the permissions for a given user's connection(s) in the API.

        Args:
            username: The username of the user.
            identifiers: The ID(s) of the connection(s) to update permissions for.
                Can be a string or a list of strings.
            operation: The operation to perform on the permissions.
                Defaults to "add". Must be either "add" or "remove".
            permission: The type of permission to update.
                Must be one of "connection", "group", "sharing profile", or "active connection".
                Defaults to "connection".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If an argument is not valid.
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if permission == "connection":
            path = "/connectionPermissions/"
        elif permission == "group":
            path = "/connectionGroupPermissions/"
        elif permission == "sharing profile":
            path = "/sharingProfilePermissions/"
        elif permission == "active connection":
            path = "/activeConnectionPermissions/"
        else:
            raise ValueError(f"Invalid permission type '{permission}'")

        if isinstance(identifiers, str):
            identifiers = [identifiers]

        permissions = [
            {
                "op": operation,
                "path": path + identifier,
                "value": "READ"
            } for identifier in identifiers
        ]

        response = requests.patch(
            f"{self.session_url}/users/{username}/permissions",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=permissions,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_user_permissions(self,
                                username: str,
                                permissions: list | str,
                                operation: str = "add") -> str | object:
        """
        Update a user's permissions

        Args:
            username: The username of the user.
            permissions: The permissions to update.
                Can be a string or a list of strings. Valid values are:
                - "ADMINISTER"
                - "CREATE_USER"
                - "CREATE_USER_GROUP"
                - "CREATE_CONNECTION",
                - "CREATE_CONNECTION_GROUP"
                - "CREATE_SHARING_PROFILE"
                - "UPDATE"
            operation: The operation to perform on the permissions.
                Defaults to "add". Must be either "add" or "remove".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If an argument is not valid.
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(permissions, str):
            permissions = [permissions]

        if "UPDATE" in permissions:
            perms = [
                {
                    "op": operation,
                    "path": f"/userPermissions/{username}",
                    "value": "UPDATE"
                }
            ]
            permissions.remove("UPDATE")
        else:
            perms = []

        valid_perms = [
            "ADMINISTER",
            "CREATE_USER",
            "CREATE_USER_GROUP",
            "CREATE_CONNECTION",
            "CREATE_CONNECTION_GROUP",
            "CREATE_SHARING_PROFILE",
        ]

        for perm in permissions:
            if perm not in valid_perms:
                raise ValueError(
                    f"Invalid permission '{perm}'. Use {valid_perms}")

            perms.append({
                "op": operation,
                "path": "/systemPermissions",
                "value": perm
            })

        response = requests.patch(
            f"{self.session_url}/users/{username}/permissions",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=perms,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def delete_user(self,
                    username: str) -> str | object:
        """
        Deletes a user with the specified username.

        Args:
            username (str): The username of the user to be deleted.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.session_url}/users/{username}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_usergroups(self) -> str | object:
        """
        Returns a JSON string containing the user groups.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/userGroups",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_usergroup(self,
                         groupname: str) -> str | object:
        """
        Retrieves the details of a user group from the API.

        Args:
            groupname (str): The name of the user group to retrieve.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/userGroups/{groupname}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_usergroup_permissions(self,
                                     groupname: str) -> str | object:
        """
        Retrieves the permissions of a user group from the API.

        Args:
            groupname (str): The name of the user group to retrieve.
            permission (str, optional): The type of permission to retrieve.
                Defaults to "connection".

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/userGroups/{groupname}/permissions",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup_member(self,
                                usernames: str,
                                groupname: str,
                                operation: str = "add") -> str | object:
        """
        Update the membership of a user in a user group.

        Args:
            usernames (str): The username of the user.
            groupname (str): The name of the user group.
            operation (str, optional): The operation to perform. Defaults to "add".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If the operation is not valid.
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(usernames, str):
            usernames = [usernames]

        users = [
            {
                "op": operation,
                "path": "/",
                "value": user
            } for user in usernames
        ]

        response = requests.patch(
            f"{self.session_url}/userGroups/{groupname}/memberUsers",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=users,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup_membergroup(self,
                                     identifiers: str,
                                     groupname: str,
                                     operation: str = "add") -> str | object:
        """
        Updates the member group of a user group.

        Args:
            identifier (str): The identifier of the user.
            groupname (str): The name of the user group.
            operation (str, optional): The operation to perform. Defaults to "add".
                Possible values are "add" and "remove".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If the operation is not "add" or "remove".
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(identifiers, str):
            identifiers = [identifiers]

        member_groups = [
            {
                "op": operation,
                "path": "/",
                "value": identifier
            } for identifier in identifiers
        ]

        response = requests.patch(
            f"{self.session_url}/userGroups/{groupname}/memberUserGroup",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=member_groups,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup_parentgroup(self,
                                     identifiers: str,
                                     groupname: str,
                                     operation: str = "add") -> str | object:
        """
        Update the parent group of a user group.

        Args:
            identifier (str): The identifier of the user group.
            groupname (str): The name of the user group.
            operation (str, optional): The operation to perform. Defaults to "add".
                Possible values are "add" and "remove".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If the operation is not "add" or "remove".
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(identifiers, str):
            identifiers = [identifiers]

        parent_groups = [
            {
                "op": operation,
                "path": "/",
                "value": identifier
            } for identifier in identifiers
        ]

        response = requests.patch(
            f"{self.session_url}/userGroups/{groupname}/userGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=parent_groups,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup_permissions(self,
                                     groupname: str,
                                     permissions: str | list,
                                     operation: str = "add") -> str | object:
        """
        Updates the permissions of a user group.

        Args:
            groupname (str): The name of the user group.
            permissions (str | list): The permissions to update.
            Can be a string or a list of strings.
            operation (str, optional): The operation to perform.
            Defaults to "add".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If an invalid operation or permission is provided.
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if isinstance(permissions, str):
            permissions = [permissions]

        valid_perms = [
            "ADMINISTER",
            "CREATE_USER",
            "CREATE_USER_GROUP",
            "CREATE_CONNECTION",
            "CREATE_CONNECTION_GROUP",
            "CREATE_SHARING_PROFILE"
        ]

        perms = []
        for perm in permissions:
            if perm not in valid_perms:
                raise ValueError(
                    f"Invalid permission '{perm}'. Use {valid_perms}"
                )

            perms.append({
                "op": operation,
                "path": "/systemPermissions",
                "value": perm
            })

        response = requests.patch(
            f"{self.session_url}/userGroups/{groupname}/permissions",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=perms,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup_connections(self,
                                     groupname: str,
                                     identifiers: str | list,
                                     operation: str = "add",
                                     permision: str = "connection") -> str | object:
        """
        Add to or remove connection(s) from a group

        Args:
            groupname: The name of the user group.
            identifiers: The ID(s) of the connection(s) to update permissions for.
                Can be a string or a list of strings.
            connection_type: The type of connection(s) to update permissions for.
                Defaults to "connection".
            operation: The operation to perform on the permissions.
                Defaults to "add". Must be either "add" or "remove".

        Returns:
           str | object: The request response JSON string or object
        """

        if operation not in ["add", "remove"]:
            raise ValueError(
                f"Invalid operation '{operation}'. Use 'add' or 'remove'")

        if permision == "connection":
            path = "/connectionPermissions"
        elif permision == "group":
            path = "/connectionGroupPermissions"
        elif permision == "sharing profile":
            path = "/sharingProfilePermissions"
        elif permision == "active connection":
            path = "/activeConnectionPermissions"
        else:
            raise ValueError(f"Invalid connection type '{permision}'")

        if isinstance(identifiers, str):
            identifiers = [identifiers]

        conns = [
            {
                "op": operation,
                "path": f"{path}/{identifier}",
                "value": "READ"
            } for identifier in identifiers
        ]

        response = requests.patch(
            f"{self.session_url}/userGroups/{groupname}/permissions",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=conns,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def create_usergroup(self,
                         groupname: str,
                         attributes: dict | None = None) -> str | object:
        """
        Create a user group with the given group name and attributes.

        Args:
            groupname: The name of the user group to create.
            attributes: The attributes of the user group.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.post(
            f"{self.session_url}/userGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "identifier": groupname,
                "attributes": {
                    "disabled": attributes.get("disabled", "")
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_usergroup(self,
                         groupname: str,
                         attributes: dict | None = None) -> str | object:
        """
        Update a user group.

        Args:
            groupname: The name of the user group to be updated.
            attributes: The attributes to be updated for the user group.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.put(
            f"{self.session_url}/userGroups/{groupname}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "identifier": groupname,
                "attributes": {
                    "disabled": attributes.get("disabled", "")
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def delete_usergroup(self,
                         user_group: str) -> str | object:
        """
        Deletes a user group.

        Args:
            user_group (str): The name of the user group to be deleted.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.session_url}/userGroups/{user_group}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_tunnels(self) -> str | object:
        """
        Return a JSON string representation of the Guacamole tunnels.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            self.tunnels_url,
            params=self.params,
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_tunnel(self,
                      identifier: str) -> str | object:
        """
        Retrieves the details of a specific tunnel.

        Args:
            identifier (str): The identifier of the tunnel.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.tunnels_url}/{identifier}/activeConnection/connection/sharingProfiles",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_connections(self) -> str | object:
        """
        Lists the connections.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/connections",
            params=self.params,
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_active_connections(self) -> str | object:
        """
        Lists the active connections with their uuids.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/activeConnections",
            params=self.params,
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_connection(self,
                          identifier: str,
                          option: str = None) -> str | object:
        """
        Detail a connection based on the given identifier and option.

        Args:
            identifier (str): The identifier of the connection.
            option (str, optional): The option to detail the connection.
            Defaults to None. Options are: "parameters", "history", and "sharing profiles".

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If an invalid option is provided.
        """

        if not option:
            host = f"{self.session_url}/connections/{identifier}"
        elif option == "parameters":
            host = f"{self.session_url}/connections/{identifier}/parameters"
        elif option == "history":
            host = f"{self.session_url}/connections/{identifier}/history"
        elif option == "sharing profiles":
            host = f"{self.session_url}/connections/{identifier}/sharingProfiles"
        else:
            raise ValueError(f"Invalid option '{option}'")

        response = requests.get(
            host,
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def kill_active_connections(self,
                                uuids: str | list) -> str | object:
        """
        Kills the active connection(s) specified by connection uuid(s).

        Args:
            uuids: The uuids(s) of the connection(s) to kill.
                Can be a string or a list of strings.

        Returns:
           str | object: The request response JSON string or object
        """

        if isinstance(uuids, str):
            uuids = [uuids]

        kill_uuids = [
            {
                "op": "remove",
                "path": f"/{uuid}"
            } for uuid in uuids
        ]

        response = requests.patch(
            f"{self.session_url}/activeConnections",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json=kill_uuids,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def manage_connection(self,
                          protocol: str,
                          name: str,
                          parent_identifier: str = 'ROOT',
                          identifier: str | None = None,
                          parameters: dict | None = None,
                          attributes: dict | None = None) -> str | object:
        """
        Creates or updates a connection. Setting the identifier creates a new connection.

        Args: 
            protocol (str): "vnc", "ssh", "rdp", "sftp", "telnet", "kubernetes"
            name (str): name of connection
            parent_identifier (str): identifier of parent connection
                Defaults to 'ROOT'
            identifier (str | optional): identifier of connection.
                Defaults to None. If None it creates a new connection
            parameters (dict | optional): dictionary of parameters.
                Defaults to None
            attributes (dict | optional): dictionary of attributes.
                Defaults to None

        Returns:
           str | object: The request response JSON string or object
        """

        if protocol not in ["vnc", "ssh", "rdp", "sftp", "telnet", "kubernetes"]:
            raise ValueError(
                f"Invalid protocol '{protocol}'. Use 'vnc', 'ssh', 'rdp', 'telnet', or 'kubernetes'"
            )

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
            } if parameters else {}

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
            } if parameters else {}

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
            } if parameters else {}

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
            } if parameters else {}

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
            } if parameters else {}

        attributes = {
            "max-connections": attributes.get("max-connections", ""),
            "max-connections-per-user": attributes.get("max-connections-per-user", ""),
            "weight": attributes.get("weight", ""),
            "failover-only": attributes.get("failover-only", ""),
            "guacd-port": attributes.get("guacd-port", ""),
            "guacd-encryption": attributes.get("guacd-encryption", ""),
            "guacd-hostname": attributes.get("guacd-hostname", ""),
        } if attributes else {}

        if identifier:
            response = requests.put(
                f"{self.session_url}/connections/{identifier}",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json={
                    "parentIdentifier": parent_identifier,
                    "name": name,
                    "identifier": identifier,
                    "activeConnections": 0,
                    "protocol": protocol,
                    "parameters": parameters,
                    "attributes": attributes,
                },
                verify=False,
                timeout=12
            ).text
        else:
            response = requests.post(
                f"{self.session_url}/connections",
                headers={"Content-Type": "application/json"},
                params=self.params,
                json={
                    "parentIdentifier": parent_identifier,
                    "name": name,
                    "protocol": protocol,
                    "parameters": parameters,
                    "attributes": attributes,
                },
                verify=False,
                timeout=12
            ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def delete_connection(self,
                          identifier: str) -> str | object:
        """
        Delete a connection identified by the given identifier.

        Args:
            identifier (str): The identifier of the connection to delete.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.session_url}/connections/{identifier}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_connection_groups(self) -> str | object:
        """
        Returns a JSON string containing the connection groups.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/connectionGroups",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_connection_group_connections(self) -> str | object:
        """
        Retrieves the connections in the connection group with the specified ID.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/connectionGroups/ROOT/tree",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_sharing_profile(self,
                               sharing_id: str,
                               option: str = '') -> str | object:
        """
        Retrieves the details of a sharing profile.

        Args:
            sharing_id (str): The identifier of the sharing profile.
            option (str | optional): An additional option for the request.
                Defaults to ''. Can be 'parameters'

        Returns:
           str | object: The request response JSON string or object

        Raises:
            ValueError: If an invalid option is provided.
        """

        if option not in ['', 'parameters']:
            raise ValueError(
                f"Invalid option '{option}'. Use '' or 'parameters'.")

        host = f"{self.session_url}/sharingProfiles/{sharing_id}"

        if option == 'parameters':
            host = host + "/parameters"

        response = requests.get(
            host,
            verify=False,
            params=self.params,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def detail_connection_group_connections(self,
                                            identifier: str) -> str | object:
        """
        Retrieve the details of a connection group's connections.

        Args:
            identifier (str): The identifier of the connection group.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/connectionGroups/{identifier}/tree",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def create_connection_group(self,
                                group_name: str,
                                group_type: str = 'ORGANIZATIONAL',
                                parent_identifier: str = 'ROOT',
                                attributes: dict | None = None) -> str | object:
        """
        Creates a connection group with the given parameters.

        Args:
            group_name (str): The name of the connection group.
            group_type (str): The type of the connection group.
            Defaults to 'ORGANIZATIONAL'. Can be 'ORGANIZATIONAL' or 'BALANCING'
            parent_identifier (str, optional): The parent connection group identifier.
            Defaults to 'ROOT'.
            attributes (dict, optional): Additional attributes for the connection group.
            Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        if group_type not in ['ORGANIZATIONAL', 'BALANCING']:
            raise ValueError(
                f"Invalid option '{group_type}'. Use 'ORGANIZATIONAL' or 'BALANCING'.")

        response = requests.post(
            f"{self.session_url}/connectionGroups",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "parentIdentifier": parent_identifier,
                "name": group_name,
                "type": group_type,
                "attributes": {
                    "max-connections": attributes.get("max-connections", ""),
                    "max-connections-per-user": attributes.get("max-connections-per-user", ""),
                    "enable-session-affinity": attributes.get("enable-session-affinity", "")
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_connection_group(self,
                                identifier: str,
                                group_name: str,
                                group_type: str = 'ORGANIZATIONAL',
                                parent_identifier: str = 'ROOT',
                                attributes: dict | None = None) -> str | object:
        """
        Update a connection group.

        Args:
            identifier (str): The identifier of the connection group.
            group_name (str): The name of the connection group.
            group_type (str): The type of the connection group.
            Defaults to 'ORGANIZATIONAL'. Can be 'ORGANIZATIONAL' or 'BALANCING'
            parent_identifier (str, optional): The parent connection group identifier.
            Defaults to 'ROOT'.
            attributes (dict, optional): Additional attributes for the connection group.
            Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.put(
            f"{self.session_url}/connectionGroups/{identifier}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "parentIdentifier": parent_identifier,
                "identifier": identifier,
                "name": group_name,
                "type": group_type,
                "attributes": {
                    "max-connections": attributes.get("max-connections", ""),
                    "max-connections-per-user": attributes.get("max-connections-per-user", ""),
                    "enable-session-affinity": attributes.get("enable-session-affinity", "")
                } if attributes else {}
            },
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def delete_connection_group(self,
                                identifier: str) -> str | object:
        """
        Deletes a connection group from the server.

        Args:
            identifier (str): The connection group identifier to delete.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.session_url}/connectionGroups/{identifier}",
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def list_sharing_profiles(self) -> str | object:
        """
        Retrieves the sharing profile list from the API.

        Args:
            None

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.get(
            f"{self.session_url}/sharingProfiles",
            params=self.params,
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def create_sharing_profile(self,
                               primary_identifier: str,
                               name: str,
                               parameters: dict | None = None) -> str | object:
        """
        Creates a sharing profile with the specified primary identifier, name, and parameters.

        Args:
            primary_identifier (str): The identifier of the connection above the sharing profile.
            name (str): The name of the sharing profile.
            parameters (dict, optional): Additional parameters for the sharing profile.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.post(
            f"{self.session_url}/sharingProfiles",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "primaryConnectionIdentifier": primary_identifier,
                "name": name,
                "parameters": {
                    "read-only": parameters.get("read-only", "")
                } if parameters else {},
                "attributes": {}
            },
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def update_sharing_profile(self,
                               primary_identifier: str,
                               name: str,
                               identifier: str,
                               parameters: dict | None = None) -> str | object:
        """
        Updates the sharing profile with the specified primary identifier,
            name, identifier, and parameters.

        Args:
            primary_identifier (str): The primary identifier of the sharing profile.
            name (str): The name of the sharing profile.
            identifier (str): The identifier of the sharing profile.
            parameters (dict, optional): The parameters of the sharing profile.
                Defaults to None.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.post(
            f"{self.session_url}/sharingProfiles/{identifier}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            json={
                "primaryConnectionIdentifier": primary_identifier,
                "name": name,
                "parameters": {
                    "read-only": parameters.get("read-only", "")
                } if parameters else {},
                "attributes": {}
            },
            verify=False,
            timeout=12,
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response

    def delete_sharing_profile(self,
                               identifier: str) -> str | object:
        """
        Deletes a sharing profile with the specified identifier.

        Args:
            identifier (str): The identifier of the sharing profile.

        Returns:
           str | object: The request response JSON string or object
        """

        response = requests.delete(
            f"{self.session_url}/sharingProfiles/{identifier}",
            headers={"Content-Type": "application/json"},
            params=self.params,
            verify=False,
            timeout=12
        ).text

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return response
