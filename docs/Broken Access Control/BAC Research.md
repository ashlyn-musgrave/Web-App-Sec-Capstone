# Web Application Security Research
# Broken Access Control  

### What is Broken Access Control (BAC)?

Broken Access Control (BAC) is a web application security vulnerability that occurs when an application fails to properly enforce restrictions on what authenticated or unauthenticated users are allowed to access or modify.

In a properly secured web application, users are assigned permissions that determine which resources and functions they can access. Broken Access Control occurs when those restrictions can be bypassed, potentially allowing attackers to view sensitive information, modify another user's data, or perform administrative actions without authorization.

Broken Access Control is especially dangerous because a user can be successfully authenticated but still gain access to resources they should not be authorized to use.

### Types of BAC: 

1) Insecure Direct Object Reference (IDOR)

Occurs when an application allows users to access resources belonging to other users by manipulating identifiers, such as account IDs or transaction IDs.

VulnBank example: A customer changes /account/1001 to /account/1002 and successfully views another customer's banking information.

Primary weakness => Missing object-level authorization 

2) Vertical Privilege Escalation

Occurs when a lower-privileged user gains access to functionality reserved for higher-privileged users, such as administrators.

VulnBank example: A regular customer accesses /admin/users and gains the ability to modify or delete customer accounts.

Primary weakness => Access to higher-privileged functionality

3) Horizontal Privilege Escalation

Occurs when a user accesses another user's resources or performs actions on their behalf, even though both users have the same permission level.

VulnBank example: Customer A modifies Customer B's contact information without permission.

Primary weakness => Access to another user's resources

4) Missing Function-Level Access Control

Occurs when an application fails to verify whether a user has permission to execute a particular function or API operation.

VulnBank example: A customer sends a request to POST /admin/create-user and successfully creates an administrative account because the backend doesn't enforce role restrictions.

Primary weakness => Missing permission checks on operations

5) Forced Browsing/URL Manipulation

Occurs when users directly navigate to restricted pages or resources that aren't properly protected by server-side authorization checks.

VulnBank example: A customer manually enters /admin/dashboard into the browser and accesses the administrative dashboard, even though the application doesn't display an admin navigation link.

Primary weakness => Restricted URLs aren't properly protected 

6) Authoization Bypass Through Parameter Tampering

Occurs when an application trusts user-controlled values, such as role parameters or account ownership identifiers, instead of independently validating permissions.

VulnBank example: A customer changes a request parameter from role=user to role=admin, and the application grants administrative privileges without verifying the user's actual role.

Primary weakness => Server trusts user-controlled authorization data 
