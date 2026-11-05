"""
Report the inbound rules of the security groups in this AWS account and warn
about any rule that is open to the public internet.

For each security group, prints the port(s) every inbound rule allows and the
IP range(s) allowed to use them. Rules that allow every IP address
(0.0.0.0/0, or ::/0 for IPv6) are flagged with a warning.

Usage:
    python ec2-sg.py                        # check every security group
    python ec2-sg.py -s Jeffrey-HTTP-SG     # check one security group by name
"""

import argparse

import boto3
# ClientError is the exception boto3 raises whenever AWS rejects a request,
# such as when our credentials are not allowed to make a call.
from botocore.exceptions import ClientError

# These CIDR ranges match every IPv4 and every IPv6 address, so a rule that
# allows either one lets anyone on the internet connect.
OPEN_RANGES = ('0.0.0.0/0', '::/0')

# Common services, shown next to their port number to make the report easier to read.
PORT_NAMES = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP'}

WARNING = "WARNING: Open to the public internet!"

def parse_args():
    """Read the optional -s/--security-group argument from the command line."""
    # The description is shown when the script is run with -h or --help.
    parser = argparse.ArgumentParser(
        description="List the inbound rules of security groups and warn about "
                    "any that are open to the public internet."
    )
    # argparse stores this flag as args.security_group (dashes become underscores).
    parser.add_argument(
        "-s", "--security-group",
        help="Name of the security group to check. If omitted, every "
             "security group is checked.",
    )
    # parse_args reads the command line and stops with a usage message if a flag
    # is used incorrectly, such as -s with no name after it.
    return parser.parse_args()

def get_security_groups(client, group_name):
    """Return the security group with the given name, or every group if no name is given."""
    # Filtering on group-name, rather than using the GroupNames parameter, works for
    # groups in any VPC, and a name that doesn't exist returns an empty list instead
    # of raising an error. No filter at all returns every security group.
    filters = [{'Name': 'group-name', 'Values': [group_name]}] if group_name else []
    # Security groups from every page are collected here.
    groups = []
    # describe_security_groups returns results a page at a time, so the paginator
    # keeps requesting pages until every group has been read.
    paginator = client.get_paginator('describe_security_groups')
    for page in paginator.paginate(Filters=filters):
        groups.extend(page['SecurityGroups'])
    # AWS returns the groups in no particular order; sorting by name makes the report easier to scan.
    return sorted(groups, key=lambda group: group['GroupName'].lower())

def format_ports(rule):
    """Describe the protocol and port(s) a rule allows, such as 'TCP 22 (SSH)'."""
    # IpProtocol is '-1' when the rule allows every protocol on every port.
    if rule['IpProtocol'] == '-1':
        return "All traffic"
    protocol = rule['IpProtocol'].upper()
    # AWS leaves FromPort and ToPort out of rules for protocols that don't use ports,
    # so .get() is used to return None instead of raising a KeyError.
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    # For ICMP, FromPort holds the ICMP message type instead of a port; -1 means every type.
    if protocol in ('ICMP', 'ICMPV6'):
        return f"{protocol} (all types)" if from_port == -1 else f"{protocol} type {from_port}"
    # A rule covers the range FromPort-ToPort; when they match, it is a single port.
    if from_port == to_port:
        name = PORT_NAMES.get(from_port)
        return f"{protocol} {from_port} ({name})" if name else f"{protocol} {from_port}"
    # Otherwise the rule covers a range of ports, such as 'TCP 1024-65535'.
    return f"{protocol} {from_port}-{to_port}"

def get_sources(rule):
    """Return (label, value) pairs for everything the rule allows traffic from."""
    # IPv4 and IPv6 ranges are stored in separate lists, each entry holding one CIDR range.
    sources = [('Range', ip_range['CidrIp']) for ip_range in rule.get('IpRanges', [])]
    sources += [('Range', ip_range['CidrIpv6']) for ip_range in rule.get('Ipv6Ranges', [])]
    # Instead of an IP range, a rule can allow traffic from resources in another
    # security group (the default group allows traffic from itself) or a prefix list.
    sources += [('Source', f"security group {pair['GroupId']}")
                for pair in rule.get('UserIdGroupPairs', [])]
    sources += [('Source', f"prefix list {prefix['PrefixListId']}")
                for prefix in rule.get('PrefixListIds', [])]
    return sources

def print_security_group(group):
    """Print one security group's inbound rules, warning about any open to the public."""
    # The group's name and ID go on one line, with its rules indented underneath.
    print(f"Security group: {group['GroupName']} ({group['GroupId']})")
    # IpPermissions holds the inbound rules; outbound rules are in IpPermissionsEgress.
    rules = group['IpPermissions']
    # A group with no inbound rules blocks all incoming traffic.
    if not rules:
        print("    No inbound rules.")
    # Loop through the inbound rules, turning each one's protocol and ports into readable text.
    for rule in rules:
        ports = format_ports(rule)
        # One rule can list several sources, so each one gets its own line with the
        # rule's ports, which makes it clear exactly which range is open on which port.
        for label, source in get_sources(rule):
            print(f"    Port(s): {ports:<20} {label}: {source}")
            # A range that matches every IP address gets the warning on the line below it.
            if source in OPEN_RANGES:
                print(f"        {WARNING}")
    # A blank line separates one security group from the next.
    print()

def main():
    """Look up the requested security group(s) and print each one's inbound rules."""
    # args.security_group holds the name given with -s, or None if the flag wasn't used.
    args = parse_args()
    # Security groups belong to a region, so the client checks the region set in
    # the AWS configuration.
    client = boto3.client("ec2")

    # Look up the security group(s); if AWS rejects the request, print a friendly
    # message instead of a traceback.
    try:
        groups = get_security_groups(client, args.security_group)
    except ClientError as e:
        # The AWS error code (for example 'UnauthorizedOperation') is stored in the
        # exception's response dictionary.
        error_code = e.response['Error']['Code']
        # UnauthorizedOperation is the code EC2 uses when our permissions don't allow the call.
        if error_code == 'UnauthorizedOperation':
            print("You are not authorized to view the security groups in this account.")
        else:
            print(f"Error reading the security groups: {error_code}")
        return

    # An empty list means the name given with -s doesn't match any security group.
    if not groups:
        if args.security_group:
            print(f"No security group named '{args.security_group}' was found.")
        else:
            print("No security groups were found.")
        return

    # Loop through the security groups and print each one's inbound rules.
    for group in groups:
        print_security_group(group)

# Run main() only when the script is executed directly, not when it is imported.
if __name__ == "__main__":
    main()
