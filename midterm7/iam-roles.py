"""
Audit the IAM roles in this AWS account.

Lists every role created in the last 90 days with the date it was created,
followed by the managed and inline policies attached to it. Roles whose
policies we are not allowed to read are still printed, with a message
explaining why their policies are missing.

Usage:
    python iam-roles.py
"""

import datetime

import boto3
# pytz provides the UTC timezone used to build a cutoff date that can be
# compared against the timezone-aware dates AWS returns.
import pytz
# ClientError is the exception boto3 raises whenever AWS rejects a request,
# such as when our credentials are not allowed to make a call.
from botocore.exceptions import ClientError

# Only roles created within this many days are reported.
DAYS_BACK = 90

def print_error(e, action):
    """Print a friendly message for an AWS error instead of a traceback."""
    # The AWS error code (for example 'AccessDenied') is stored in the
    # exception's response dictionary.
    error_code = e.response['Error']['Code']
    # AccessDenied means the lab account's permissions don't allow this call.
    # The messages are indented to line up with the policy lines under each role.
    if error_code == 'AccessDenied':
        print(f"    You are not authorized to {action}.")
    else:
        # Other errors (such as ExpiredToken when the lab session runs out) print
        # their code so the cause can still be identified.
        print(f"    Error trying to {action}: {error_code}")

def get_recent_roles(client):
    """Return every role in the account that was created in the last DAYS_BACK days."""
    # The cutoff is the moment exactly DAYS_BACK days ago; any role created after
    # it is recent. CreateDate comes back from AWS in UTC, so the cutoff must also
    # be a UTC-aware datetime, or Python refuses to compare them.
    # datetime.now(pytz.utc) gives the same value as
    # pytz.utc.localize(datetime.utcnow()) without the deprecated utcnow().
    cutoff = datetime.datetime.now(pytz.utc) - datetime.timedelta(days=DAYS_BACK)
    # Roles that pass the date check are collected here.
    recent_roles = []
    # list_roles returns at most 100 roles per call, so the paginator keeps
    # requesting pages until every role has been read.
    paginator = client.get_paginator('list_roles')
    for page in paginator.paginate():
        # Each role is a dictionary with keys such as 'RoleName', 'Arn' and 'CreateDate'.
        for role in page['Roles']:
            # A creation date after the cutoff means the role was created
            # within the last DAYS_BACK days.
            if role['CreateDate'] > cutoff:
                recent_roles.append(role)
    return recent_roles

def print_managed_policies(client, role_name):
    """Print the managed policies attached to the role.

    Returns how many policies were printed, or None if the request failed.
    """
    try:
        # list_attached_role_policies returns managed policies (AWS or customer managed),
        # which exist on their own and are attached to the role. One call returns up
        # to 100 policies, more than AWS allows on a single role, so no paginator is needed.
        response = client.list_attached_role_policies(RoleName=role_name)
    except ClientError as e:
        # Print a friendly message instead of stopping, so the rest of the report still prints.
        print_error(e, f"list the managed policies for '{role_name}'")
        # None, rather than 0, tells main() the lookup failed, so it won't
        # wrongly report that the role has no policies.
        return None
    # 'AttachedPolicies' is a list of dictionaries holding each policy's name and ARN.
    for policy in response['AttachedPolicies']:
        print(f"    Managed policy: {policy['PolicyName']}")
    # The count lets main() tell whether the role had any managed policies.
    return len(response['AttachedPolicies'])

def print_inline_policies(client, role_name):
    """Print the inline (unmanaged) policies embedded in the role.

    Returns how many policies were printed, or None if the request failed.
    """
    try:
        # list_role_policies returns only the names of inline policies, which live
        # inside the role and are deleted along with it.
        response = client.list_role_policies(RoleName=role_name)
    except ClientError as e:
        # Print a friendly message instead of stopping, so the rest of the report still prints.
        print_error(e, f"list the inline policies for '{role_name}'")
        # As with managed policies, None marks a failed lookup rather than an empty one.
        return None
    # Unlike the managed policy response, 'PolicyNames' is a plain list of strings.
    for policy_name in response['PolicyNames']:
        print(f"    Inline policy: {policy_name}")
    # The count lets main() tell whether the role had any inline policies.
    return len(response['PolicyNames'])

def main():
    """Find the recent roles and list the policies for each one."""
    # IAM is a global service, so this client sees every role in the account no
    # matter which region the AWS configuration uses.
    client = boto3.client("iam")

    # Get the roles created in the last DAYS_BACK days; every other step works from this list.
    try:
        roles = get_recent_roles(client)
    except ClientError as e:
        # Without the role list there is nothing else to report.
        print_error(e, "list the IAM roles in this account")
        return

    # An empty list means no role in the account is newer than the cutoff.
    if not roles:
        print(f"No roles were created in the last {DAYS_BACK} days.")
        return

    # Print a heading, then loop through the roles, printing each one with its policies.
    print(f"Roles created in the last {DAYS_BACK} days:\n")
    for role in roles:
        # CreateDate is a datetime object; strftime turns it into readable text
        # such as '2026-09-08 20:33:00 UTC'.
        created = role['CreateDate'].strftime('%Y-%m-%d %H:%M:%S %Z')
        # The role name and creation date share one line, with its policies
        # indented underneath.
        print(f"Role: {role['RoleName']}    Created: {created}")
        # The two policy lookups are separate, so a denied call on one still lets
        # the other print, and the role itself is always printed above.
        managed_count = print_managed_policies(client, role['RoleName'])
        inline_count = print_inline_policies(client, role['RoleName'])
        # Only say the role has no policies when both lookups actually succeeded.
        if managed_count == 0 and inline_count == 0:
            print("    No policies found.")
        # A blank line separates one role's output from the next.
        print()

# Run main() only when the script is executed directly, not when it is imported.
if __name__ == "__main__":
    main()
