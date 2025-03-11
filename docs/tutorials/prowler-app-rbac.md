# Managing Users and Roles

The **Prowler App** supports multiple users within a single tenant, enabling seamless collaboration by allowing team members to easily share insights and manage security findings.

[Roles](#roles) help you control user permissions, determining what actions each user can perform and the data they can access within Prowler. By default, each account includes an immutable **admin** role, ensuring that your account always retains administrative access.

## Membership

To get to User-Invitation Management we will focus on the Membership section.

???+ note
    **Only users that have the _Invite and Manage Users_ or _admin_ permission can access this section.**

<img src="../img/rbac/membership.png" alt="Membership tab" width="700"/>

### Users

#### Editing a User

Follow these steps to edit a user of your account:

1. Navigate to **Users** from the side menu.
2. Click on the edit button of the user you want to modify.

    <img src="../img/rbac/user_edit.png" alt="Edit User" width="700"/>

3. Edit the user fields you need and save your changes.

    <img src="../img/rbac/user_edit_details.png" alt="Edit User Details" width="700"/>

#### Removing a User

Follow these steps to remove a user of your account:

1. Navigate to **Users** from the side menu.
2. Click on the delete button of your current user.
> **Note: Each user will be able to delete himself and not others, regardless of his permissions.**

    <img src="../img/rbac/user_remove.png" alt="Remove User" width="700"/>

### Invitations

#### Inviting Users

???+note
    _Please be aware that at this time, an email address can only be associated with a single Prowler account._

Follow these steps to invite a user to your account:

1. Navigate to **Users** from the side menu.
2. Click on the **Invite User** button on the top right-hand corner of the screen.

    <img src="../img/rbac/invite.png" alt="Invite User" width="700"/>

3. In the Invite User screen, enter the email address of the user you want to invite.
4. Pick a Role for the user. You can also change the roles for users and pending invites later. To learn more about the roles and what they can do, see [Roles](#roles).

    <img src="../img/rbac/invitation_info.png" alt="Invitation info" width="700"/>

5. Click on the **Send Invitation** button to send the invitation to the user.
6. After clicking you will see a summary of the status of the invitation. You could access this view again from the invitation menu.

    <img src="../img/rbac/invitation_details.png" alt="Invitation details" width="700"/>
    <img src="../img/rbac/invitation_details_1.png" alt="Invitation button" width="700"/>

7. To allow the user to join your Prowler account you will need to share the link with the user. They will only need to access this URL and follow the steps to create a user and complete their registration. **Note: Invitations will expire after 7 days.**

    <img src="../img/rbac/invitation_sign-up.png" alt="Invitation sign-up" width="700"/>

???+note
    If you are a [Prowler Cloud](https://cloud.prowler.com/sign-in) user, the invited user will receive an email with the link to accept the invitation.

#### Editing Invitation

Follow these steps to edit an invitation:

1. Navigate to **Invitations** from the side menu.
2. Click on the edit button of the invitation and modify the email, the role or both. **Note: Editing an invitation will not reset its expiration time.**

    <img src="../img/rbac/invitation_edit.png" alt="Invitation edit" width="700"/>
    <img src="../img/rbac/invitation_edit_1.png" alt="Invitation edit details" width="700"/>

#### Cancelling Invitation

Follow these steps to cancel an invitation:

1. Navigate to **Invitations** from the side menu.
2. Click on the revoke button of the invitation.

    <img src="../img/rbac/invitation_revoke.png" alt="Invitation revoke" width="700"/>

#### Sending Invitation Again

To resend the invitation to the user it is necessary to explicitly **delete the previous invitation and create a new invitation**.

## Managing Groups and Roles

The Roles section in Prowler is designed to facilitate the assignment of custom user privileges. This section allows administrators to define roles with specific permissions for Prowler administrative tasks and Account visibility.

???+ note
    **Only users that have the _Manage Account_ or _admin_ permission can access this section.**

### Provider Groups

Provider Groups control visibility across specific providers. When creating a new role, you can assign specific groups to define their Cloud Provider visibility. This ensures that users with that role have access only to the Cloud Providers that are required.

By default, a new user role does not have visibility into any group.

Alternatively, to grant the role unlimited visibility across all providers, check the Grant Unlimited Visibility checkbox.

#### Creating a Provider Group

Follow these steps to create a provider group in your account:

1. 1. Navigate to **Provider Groups** from the side menu..
2. In this view you can select the provider groups you want to assign to one or more roles.
3. Click on the **Create Group** button on the center of the screen.

    <img src="../img/rbac/provider_group.png" alt="Create Provider Group" width="700"/>

#### Editing a Provider Group

Follow these steps to edit a provider group on your account:

1. 1. Navigate to **Provider Groups** from the side menu..
2. Click on the edit button of the provider group you want to modify.

    <img src="../img/rbac/provider_group_edit.png" alt="Edit Provider Group" width="700"/>

3. Change the provider group parameters you need and save the changes.

    <img src="../img/rbac/provider_group_edit_1.png" alt="Edit Provider Group Details" width="700"/>

#### Removing a Provider Group

Follow these steps to remove a provider group of your account:

1. 1. Navigate to **Provider Groups** from the side menu..
2. Click on the delete button of the provider group you want to remove.

    <img src="../img/rbac/provider_group_remove.png" alt="Remove Provider Group" width="700"/>

### Roles

#### Creating a Role

Follow these steps to create a role for your account:

1. Navigate to **Roles** from the side menu.
2. Click on the **Add Role** button on the top right-hand corner of the screen.

    <img src="../img/rbac/role_create.png" alt="Create Role" width="700"/>

3. In the Add Role screen, enter the role name, the administration permissions and the groups of providers to which the Role will have access to.
4. In the Groups and Account Visibility section, you will see a list of available groups with checkboxes next to them. To assign a group to the user role, simply click the checkbox next to the group name. If you need to assign multiple groups, repeat the process for each group you wish to add.

    <img src="../img/rbac/role_create_1.png" alt="Role parameters" width="700"/>

#### Editing a Role

Follow these steps to edit a role on your account:

1. Navigate to **Roles** from the side menu.
2. Click on the edit button of the role you want to modify.

    <img src="../img/rbac/role_edit.png" alt="Edit Role" width="700"/>

3. Adjust the settings as needed and save the changes.

    <img src="../img/rbac/role_edit_details.png" alt="Edit Role Details" width="700"/>

#### Removing a Role

Follow these steps to remove a role of your account:

1. Navigate to **Roles** from the side menu.
2. Click on the delete button of the role you want to remove.

    <img src="../img/rbac/role_remove.png" alt="Remove Role" width="700"/>

## RBAC Administrative Permissions

Assign administrative permissions by selecting from the following options:

**Invite and Manage Users:** Invite new users and manage existing ones.<br>
**Manage Account:** Adjust account settings and delete users.<br>
**Manage Scans:** Run and review scans.<br>
**Manage Cloud Providers:** Add or modify connected cloud providers.<br>
**Manage Integrations:** Add or modify the Prowler Integrations.

To grant all administrative permissions, select the **Grant all admin permissions** option.
