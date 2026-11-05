"""
Audit recent security-related changes in this AWS account using CloudTrail.

CloudTrail keeps a 90-day event history of the API calls made in every AWS
account, even when no trail has been set up. This script uses the CloudTrail
lookup_events function to find calls that change who can get into the account
or its resources: new IAM users, roles, policies and access keys, new security
group rules, S3 bucket policy and public access changes, and attempts to turn
CloudTrail off. For each one it prints when the change happened, which event
it was, who made it, and which resources it touched, followed by a count of
changes per user. The full report, including the caller's IP address, can
also be saved to a CSV file.

IAM is a global service whose events are recorded in us-east-1, so IAM changes
only appear when the script runs with that region configured.

Usage:
    python student-choice.py                     # changes from the last 7 days
    python student-choice.py --days 30           # changes from the last 30 days
    python student-choice.py --csv changes.csv   # also save the report to a CSV file
"""

import argparse
import csv
import datetime
import json
from collections import Counter

import boto3
from botocore.config import Config
# ClientError is raised when AWS rejects a request. NoCredentialsError is raised
# before any request is sent, when boto3 can't find AWS credentials at all.
from botocore.exceptions import ClientError, NoCredentialsError

# CloudTrail only keeps event history for the last 90 days.
MAX_DAYS = 90

# API calls that change access to the account or its resources, grouped by service.
# These are the names CloudTrail records, which don't always match the boto3 function
# names (delete_public_access_block is recorded as DeleteBucketPublicAccessBlock).
EVENT_NAMES = [
    # IAM: new identities, new credentials, and new or changed permissions.
    'CreateUser', 'CreateAccessKey', 'CreateRole', 'CreatePolicy',
    'AttachRolePolicy', 'PutRolePolicy', 'AttachUserPolicy', 'PutUserPolicy',
    # EC2: new security groups and inbound rules that open network access.
    'CreateSecurityGroup', 'AuthorizeSecurityGroupIngress',
    # S3: changes that can make a bucket public.
    'PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPublicAccessBlock',
    # CloudTrail: stopping or deleting a trail hides any activity that follows.
    'StopLogging', 'DeleteTrail',
]

# Columns saved to the CSV file, in order.
CSV_COLUMNS = ['Time', 'Event', 'User', 'Source IP', 'Result', 'Resources']

def parse_args():
    """Read the --days and --csv options from the command line."""
    # The description is shown when the script is run with -h or --help.
    parser = argparse.ArgumentParser(
        description="Report security-related changes recorded in the CloudTrail event history."
    )
    # --days sets how far back to search. type=int makes argparse reject anything
    # that isn't a whole number.
    parser.add_argument(
        "-d", "--days", type=int, default=7,
        help=f"How many days back to search, from 1 to {MAX_DAYS} (default: 7).",
    )
    # --csv is optional; without it the report is only printed to the screen.
    parser.add_argument(
        "--csv", metavar="FILE",
        help="Also save the full report, including source IP addresses, to this CSV file.",
    )
    # Read the command line; argparse stops with a usage message if an option is invalid.
    args = parser.parse_args()
    # CloudTrail has nothing older than 90 days to search, and a zero or negative
    # number makes no sense, so stop with a clear message instead.
    if not 1 <= args.days <= MAX_DAYS:
        parser.error(f"--days must be between 1 and {MAX_DAYS}.")
    return args

def find_events(client, start_time):
    """Return every event in EVENT_NAMES recorded since start_time, newest first."""
    # Matching events for every event name are collected in this one list.
    events = []
    # get_paginator returns a helper that calls lookup_events repeatedly, passing
    # along the NextToken from each response to get the next page of results.
    paginator = client.get_paginator('lookup_events')
    # lookup_events can only filter on one event name per request, so search
    # for each security-related event name in turn.
    for event_name in EVENT_NAMES:
        # The filter matches only events with exactly this name.
        lookup = [{'AttributeKey': 'EventName', 'AttributeValue': event_name}]
        # Each page holds up to 50 events; the paginator keeps requesting pages
        # until every matching event has been read.
        for page in paginator.paginate(LookupAttributes=lookup, StartTime=start_time):
            events.extend(page['Events'])
    # The results arrive grouped by event name, so sort them into one timeline.
    return sorted(events, key=lambda event: event['EventTime'], reverse=True)

def get_resource_names(event):
    """Return the names of the resources an event touched, without duplicates."""
    names = []
    # Resources lists each resource the call affected, such as a role, a policy,
    # a security group, or a bucket.
    for resource in event.get('Resources', []):
        name = resource.get('ResourceName', '')
        # ARNs are long, so keep only the part after the last ':' or '/', which is
        # the resource's own name (the role, policy, or bucket name).
        if name.startswith('arn:'):
            name = name.replace(':', '/').rsplit('/', 1)[-1]
        # The same resource is often listed twice, once by name and once by ARN.
        if name and name not in names:
            names.append(name)
    return ', '.join(names)

def build_row(event):
    """Turn one CloudTrail event into a dictionary of report columns."""
    # CloudTrailEvent is the full event record as a JSON string. It holds details
    # that lookup_events doesn't return as separate fields, such as the caller's IP address.
    details = json.loads(event['CloudTrailEvent'])
    return {
        # EventTime is converted to this computer's time zone so it matches the local clock.
        'Time': event['EventTime'].astimezone().strftime('%Y-%m-%d %H:%M:%S'),
        'Event': event['EventName'],
        # Username can be missing, for example when an AWS service made the call itself.
        'User': event.get('Username', 'unknown'),
        'Source IP': details.get('sourceIPAddress', ''),
        # errorCode is only present when the call failed, such as an AccessDenied attempt.
        'Result': details.get('errorCode', 'Success'),
        'Resources': get_resource_names(event),
    }

def print_table(headers, rows):
    """Print rows as a table, with each column as wide as its longest value."""
    # zip(headers, *rows) groups the values by column, so each column's width
    # can be measured, including its header.
    widths = [max(len(value) for value in column) for column in zip(headers, *rows)]
    # Print the header, a dashed separator line, and then every row, padding each
    # value to its column's width so the columns line up.
    for line in [headers, ['-' * width for width in widths]] + rows:
        print("  ".join(value.ljust(width) for value, width in zip(line, widths)).rstrip())

def print_report(rows, region, days):
    """Print the events as a table, followed by a summary of who made the changes."""
    # The heading shows which region and time window the report covers.
    print(f"Security-related changes in {region} over the last {days} days (local time)\n")
    # With nothing to show, print a message instead of an empty table.
    if not rows:
        print("No security-related changes were found.")
        return

    # The console table leaves out the source IP to stay readable; the CSV file
    # has every column. Failed calls are rare but important, so they are marked
    # next to the event name.
    table = []
    for row in rows:
        event = row['Event']
        if row['Result'] != 'Success':
            event += f" (FAILED: {row['Result']})"
        table.append([row['Time'], event, row['User'], row['Resources']])
    # Print the rows under their column headings.
    print_table(['Time', 'Event', 'User', 'Resources'], table)

    # Count the changes made by each user, most active first, so unexpected
    # users or unusual amounts of activity stand out.
    print(f"\nTotal: {len(rows)} security-related changes")
    for user, count in Counter(row['User'] for row in rows).most_common():
        print(f"    {count:>4}  {user}")

    # A failed call can mean someone tried to make a change they aren't allowed to.
    failed = sum(1 for row in rows if row['Result'] != 'Success')
    if failed:
        print(f"\nWARNING: {failed} of these calls failed. Check who made them and why.")

def write_csv(rows, file_name):
    """Save every column of the report to a CSV file."""
    try:
        # newline='' stops Python from adding a blank line between rows on Windows.
        with open(file_name, 'w', newline='') as csv_file:
            # DictWriter writes each row dictionary as one line, with the values in
            # CSV_COLUMNS order.
            writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
            # The first line of the file holds the column names.
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nFull report saved to {file_name}")
    except OSError as e:
        # The most common cause is a PermissionError because the file is open in Excel.
        print(f"\nCould not save the report to {file_name}: {e.strerror}")

def main():
    """Look up the security-related events and report them."""
    # Read --days and --csv from the command line.
    args = parse_args()
    # lookup_events only allows 2 requests per second, and this script sends at
    # least one request per event name, so boto3 is told to retry throttled
    # requests (waiting a little longer each time) instead of failing.
    client = boto3.client("cloudtrail", config=Config(retries={'max_attempts': 10, 'mode': 'standard'}))
    # Search back from the current time; CloudTrail expects the start time in UTC.
    start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=args.days)

    # Every AWS request happens inside find_events, so any error it hits is caught here.
    try:
        events = find_events(client, start_time)
    except NoCredentialsError:
        # boto3 found no credentials, so no request ever reached AWS.
        print("No AWS credentials were found. Start the lab and copy its credentials "
              "into ~/.aws/credentials, then try again.")
        return
    except ClientError as e:
        # The AWS error code is stored in the exception's response dictionary.
        # Services spell some codes differently, so both spellings are checked.
        error_code = e.response['Error']['Code']
        if error_code in ('AccessDenied', 'AccessDeniedException'):
            print("You are not authorized to read the CloudTrail event history.")
        elif error_code in ('ExpiredToken', 'ExpiredTokenException'):
            print("Your AWS session has expired. Restart the lab, update "
                  "~/.aws/credentials, and try again.")
        else:
            print(f"Error reading the CloudTrail event history: {error_code}")
        return

    # Turn each raw CloudTrail event into a row of readable report columns.
    rows = [build_row(event) for event in events]
    # The region comes from the AWS configuration instead of being hard-coded.
    print_report(rows, client.meta.region_name, args.days)
    # The CSV file is only written when --csv was given.
    if args.csv:
        write_csv(rows, args.csv)

# Run main() only when the script is executed directly, not when it is imported.
if __name__ == "__main__":
    main()
