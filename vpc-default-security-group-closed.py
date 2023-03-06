#!/usr/bin/env python

"""
./vpc-default-security-group-closed.py \
    --accounts {[aws-accounts]} \
    --profile profile-name \
    --region {us-east-1} \
    --remediate \
    --output output-dir
"""

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from csv import DictWriter
from datetime import date
from itertools import count
from json import dump, load, loads
from operator import itemgetter
from os import path
from pathlib import Path

import boto3
import botocore
from tqdm import tqdm
from xlsxwriter.workbook import Workbook

ACCOUNT_NAME_DICT = {"012345678901": "account-name"}

TODAY = date.today().strftime("%Y%m%d")
NOW = date.today().strftime("%Y%m%d-%H%M%S")

parser = ArgumentParser(
    description="Query and optionally fix non-empty default security groups",
    formatter_class=ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "--accounts",
    "-a",
    default=list(ACCOUNT_NAME_DICT) + list(ACCOUNT_NAME_DICT.values()),
    nargs="+",
    help="List of space-separated 12-digit account ID(s) or name(s) to be remediated. Defaults to all accounts.",
)
parser.add_argument(
    "--profile",
    "-p",
    required=True,
    help="AWS profile name. "
    "Parsed from ~/.aws/config (SSO) or credentials (API key). "
    "Corresponds to the account where Config is deployed.",
)
parser.add_argument(
    "--region", "-r", default="us-east-1", help="AWS region where Config is deployed."
)
parser.add_argument(
    "--aggregator",
    "-a",
    default="OrganizationConfigAggregator",
    help="Value of ConfigurationAggregatorName.",
)
parser.add_argument(
    "--remediate",
    "-e",
    help="Remediate non-compliant default security groups to custom groups. "
    "By default, this'll remove rules for un-attached security groups. "
    'Specify this option twice ("-ee") to *also* migrate attached security groups.',
    action="count",
    default=0,
)
parser.add_argument("--verbose", "-v", action="store_true")
parser.add_argument("--output", "-o", default="", help="Output directory of CSV/XLSX.")
args = parser.parse_args()
arg_accounts = args.accounts
profile = args.profile
region = args.region
aggregator_name = args.aggregator
remediate_level = args.remediate
dir_path = args.output
Path(dir_path).mkdir(parents=True, exist_ok=True)
is_verbose = args.verbose


def verbose_print(text):
    """Print current operation when enabled"""
    if is_verbose is True:
        print(text)


def select_aggregate_resource_config(expression):
    """Run Config (SQL) query specified by "expression" argument"""
    results = []
    config_response = {}
    for i in count():
        params = {
            "Expression": expression,
            "ConfigurationAggregatorName": aggregator_name,
        }
        if i == 0 or "NextToken" in config_response:
            if "NextToken" in config_response:
                params["NextToken"] = config_response["NextToken"]
            config_response = client.select_aggregate_resource_config(**params)
            results.extend(config_response["Results"])
        else:
            break

    return results


# Cache ResourceCompliance output
RULE_CACHE = f"/tmp/rule_list-cache-{TODAY}.txt"
rule_list = []

if path.exists(RULE_CACHE):
    verbose_print(f"Loading ResourceCompliance from {RULE_CACHE}")

    with open(RULE_CACHE) as f:
        rule_list = load(f)
else:
    verbose_print("Loading ResourceCompliance from API")

    rule_list = select_aggregate_resource_config(
        "SELECT accountId, "
        "awsRegion, "
        "configuration.targetResourceId, "
        "configuration.configRuleList.configRuleName, "
        "configuration.configRuleList.complianceType "
        "WHERE resourceType = 'AWS::Config::ResourceCompliance'"
    )

    with open(RULE_CACHE, "w") as f:
        dump(rule_list, f)

compliance_list = []

# Query compliance status of vpc-default-security-group-closed using Config
for result in rule_list:
    resource = loads(result)
    configuration = resource["configuration"]
    sg_id = configuration["targetResourceId"]
    account_name = ACCOUNT_NAME_DICT.get(resource["accountId"], "")
    aws_region = resource["awsRegion"]

    for c_rule in configuration["configRuleList"]:
        if "vpc-default-security-group-closed" in c_rule["configRuleName"]:
            compliance_list.append(
                {
                    "ACCOUNT_ID": resource["accountId"],
                    "ACCOUNT": account_name,
                    "REGION": aws_region,
                    "SG_ID": sg_id,
                    "COMPLIANCE": c_rule["complianceType"],
                }
            )


def paginator(name, value, operation_name, profile_name, region_name):
    """return: compiled pages of response"""
    ec_session = boto3.session.Session(
        profile_name=profile_name, region_name=region_name
    )
    ec_client = ec_session.client("ec2")
    ec2_response = (
        ec_client.get_paginator(operation_name)
        .paginate(Filters=[{"Name": name, "Values": [value]}])
        .build_full_result()
    )

    return ec2_response


# Parse non-compliant security groups
non_compliant_sg = []
for compliance_dict in compliance_list:
    account_id = compliance_dict["ACCOUNT_ID"]
    profile = compliance_dict["ACCOUNT"]
    region = compliance_dict["REGION"]
    sg_id = compliance_dict["SG_ID"]
    compliance = compliance_dict["COMPLIANCE"]

    # Query all ENI IDs attached to the security group
    if compliance == "NON_COMPLIANT" and (
        account_id in arg_accounts or profile in arg_accounts
    ):
        verbose_print(f"Querying ENIs attached to {sg_id}")

        session = boto3.session.Session(profile_name=profile, region_name=region)
        client = session.client("ec2")
        response = (
            client.get_paginator("describe_network_interfaces")
            .paginate(Filters=[{"Name": "group-id", "Values": [sg_id]}])
            .build_full_result()
        )

        # dedup
        network_interfaces = set()
        for network_interface in response["NetworkInterfaces"]:
            network_interfaces.add(network_interface["NetworkInterfaceId"])

        # set -> list
        network_interfaces_list = list(network_interfaces)

        non_compliant_sg.append(
            {
                "ACCOUNT_ID": account_id,
                "ACCOUNT": profile,
                "REGION": region,
                "SG_ID": sg_id,
                "ENI_IDs": "\n".join(network_interfaces_list),
            }
        )

if len(non_compliant_sg) >= 1:
    for sg in tqdm(non_compliant_sg):
        account_id = sg["ACCOUNT_ID"]
        profile = sg["ACCOUNT"]
        region = sg["REGION"]
        sg_id = sg["SG_ID"]
        network_interfaces = sg["ENI_IDs"].splitlines()

        if remediate_level >= 1 and (
            account_id in arg_accounts or profile in arg_accounts
        ):
            verbose_print(f"Fixing {sg_id}...")

            sg["FIXED"] = False
            # Query description of the security group
            default_sg = paginator(
                "group-id", sg_id, "describe_security_groups", profile, region
            )[0]["SecurityGroups"][0]

            # Query inbound/outbound rules of the security group
            describe_security_group_rules = paginator(
                "group-id", sg_id, "describe_security_group_rules", profile, region
            )
            sg_rules = list(describe_security_group_rules["SecurityGroupRules"])

            out_json = path.join(dir_path, f"{sg_id}-{NOW}.json")
            with open(out_json, "a") as f:
                dump(sg_rules, f, indent=2, default=str)
                verbose_print(f"Completed backup {sg_id} rules to {out_json}.")

            # Remove rules for un-attached security groups
            if len(network_interfaces) == 0:
                session = boto3.session.Session(
                    profile_name=profile, region_name=region
                )
                client = session.client("ec2")

                # Remove all rules from default security group
                ingress_rule_ids = []
                egress_rule_ids = []
                for rule in sg_rules:
                    if rule["IsEgress"] is False:
                        ingress_rule_ids.append(rule["SecurityGroupRuleId"])
                    else:
                        egress_rule_ids.append(rule["SecurityGroupRuleId"])

                if len(ingress_rule_ids) >= 1:
                    client.revoke_security_group_ingress(
                        GroupId=sg_id, SecurityGroupRuleIds=ingress_rule_ids
                    )

                    verbose_print(f"Revoked ingress rule from {sg_id}")

                if len(egress_rule_ids) >= 1:
                    client.revoke_security_group_egress(
                        GroupId=sg_id, SecurityGroupRuleIds=egress_rule_ids
                    )

                    verbose_print(f"Revoked egress rule from {sg_id}")

                sg["FIXED"] = True

                verbose_print(f"Fixed {sg_id}")

            # Migrate rules for attached security groups
            # DO NOT USE, it is better to fix it on the CloudFormation template
            if len(network_interfaces) >= 1 and remediate_level >= 2:
                groupName = f"Migrated from {sg_id}"
                for tag in default_sg["Tags"]:
                    if tag["Key"] == "Name":
                        groupName = tag["Value"]

                # Create a new security group
                session = boto3.session.Session(
                    profile_name=profile, region_name=region
                )
                client = session.client("ec2")

                new_sg = client.create_security_group(
                    Description=f"Migrated from {sg_id}",
                    GroupName=groupName,
                    VpcId=default_sg["VpcId"],
                    TagSpecifications=[
                        {"ResourceType": "security-group", "Tags": default_sg["Tags"]}
                    ],
                )

                # Copy and assign rules to the new security group
                ingress_ip_permissions = []
                for permission in default_sg.get("IpPermissions", []):
                    for group_pair in permission.get("UserIdGroupPairs", []):
                        if group_pair["GroupId"] == sg_id:
                            # Replace default group <-> group allow rule
                            group_pair["GroupId"] = new_sg["GroupId"]

                    ingress_ip_permissions.append(permission)

                if len(ingress_ip_permissions) >= 1:
                    client.authorize_security_group_ingress(
                        GroupId=new_sg["GroupId"], IpPermissions=ingress_ip_permissions
                    )

                egress_ip_permissions = []
                for permission in default_sg.get("IpPermissionsEgress", []):
                    for group_pair in permission.get("UserIdGroupPairs", []):
                        if group_pair["GroupId"] == sg_id:
                            group_pair["GroupId"] = new_sg["GroupId"]

                    # By default, security groups allow all outbound traffic.
                    if not (
                        permission["IpProtocol"] == "-1"
                        and len(permission["IpRanges"]) >= 1
                        and permission["IpRanges"][0].get("CidrIp", "") == "0.0.0.0/0"
                    ):
                        egress_ip_permissions.append(permission)

                if len(egress_ip_permissions) >= 1:
                    client.authorize_security_group_egress(
                        GroupId=new_sg["GroupId"], IpPermissions=egress_ip_permissions
                    )

                for eni in network_interfaces:
                    # Query current attachments
                    eni_group_set = client.describe_network_interface_attribute(
                        Attribute="groupSet",
                        NetworkInterfaceId=eni["NetworkInterfaceId"],
                    )

                    new_groups = [new_sg["GroupId"]]
                    for group in eni_group_set.get("Groups", []):
                        if group["GroupId"] != sg_id:
                            new_groups.append(eni_group_set["GroupId"])

                    # Detach default security group and attach newly created one to the ENI
                    requester_id = eni.get("RequesterId", "")
                    if requester_id == "amazon-elb":
                        session = boto3.session.Session(
                            profile_name=profile, region_name=region
                        )
                        client = session.client("elbv2")
                        client.set_security_groups(
                            LoadBalancerArn=(
                                f"arn:aws:elasticloadbalancing:{region}:"
                                f'{eni["OwnerId"]}:'
                                f'loadbalancer/{eni["Description"].split(" ")[1]}'
                            ),
                            SecurityGroups=new_groups,
                        )
                    elif requester_id == "amazon-rds":
                        session = boto3.session.Session(
                            profile_name=profile, region_name=region
                        )
                        client = session.client("rds")
                        response_iterator = client.get_paginator(
                            "describe_db_instances"
                        ).paginate()
                        for page in response_iterator:
                            for rds in page["DBInstances"]:
                                for vpc_sg in rds["VpcSecurityGroups"]:
                                    if vpc_sg["VpcSecurityGroupId"] == sg_id:
                                        client.modify_db_instance(
                                            DBInstanceIdentifier=rds[
                                                "DBInstanceIdentifier"
                                            ],
                                            VpcSecurityGroupIds=new_groups,
                                        )
                    elif requester_id == "amazon-redshift":
                        response_iterator = client.get_paginator(
                            "describe_clusters"
                        ).paginate()
                        for page in response_iterator:
                            for cluster in page["Clusters"]:
                                for vpc_sg in cluster["VpcSecurityGroups"]:
                                    if vpc_sg["VpcSecurityGroupId"] == sg_id:
                                        client.modify_cluster(
                                            ClusterIdentifier=cluster[
                                                "ClusterIdentifier"
                                            ],
                                            VpcSecurityGroupIds=new_groups,
                                        )
                    else:
                        session = boto3.session.Session(
                            profile_name=profile, region_name=region
                        )
                        client = session.client("ec2")
                        try:
                            client.modify_network_interface_attribute(
                                Groups=new_groups,
                                NetworkInterfaceId=eni["NetworkInterfaceId"],
                            )
                        except botocore.exceptions.ClientError:
                            print(
                                f'Error: cannot modify ENI ID "{eni["NetworkInterfaceId"]}", '
                                f'Description "{eni["Description"]}"'
                            )

                client = session.client("ec2")

                # Remove all rules from default security group
                ingress_rule_ids = []
                egress_rule_ids = []
                for rule in sg_rules:
                    if rule["IsEgress"] is False:
                        ingress_rule_ids.append(rule["SecurityGroupRuleId"])
                    else:
                        egress_rule_ids.append(rule["SecurityGroupRuleId"])

                if len(ingress_rule_ids) >= 1:
                    client.revoke_security_group_ingress(
                        GroupId=sg_id, SecurityGroupRuleIds=ingress_rule_ids
                    )

                if len(egress_rule_ids) >= 1:
                    client.revoke_security_group_egress(
                        GroupId=sg_id, SecurityGroupRuleIds=egress_rule_ids
                    )

                sg["FIXED"] = True

    sorted_list = sorted(non_compliant_sg, key=itemgetter("ACCOUNT"))

    out_csv = path.join(
        dir_path,
        f"non-compliant-vpc-default-security-group-closed-eni-attachments-{TODAY}.csv",
    )
    out_xlsx = path.join(
        dir_path,
        f"non-compliant-vpc-default-security-group-closed-eni-attachments-{TODAY}.xlsx",
    )

    # prevent overwriting previous report
    if len(arg_accounts) < len(list(ACCOUNT_NAME_DICT)):
        out_csv = path.join(
            dir_path,
            f"non-compliant-vpc-default-security-group-closed-eni-attachments-{NOW}.csv",
        )
        out_xlsx = path.join(
            dir_path,
            f"non-compliant-vpc-default-security-group-closed-eni-attachments-{NOW}.xlsx",
        )

    with open(out_csv, "w") as f:
        w = DictWriter(f, fieldnames=list(sorted_list[0]), dialect="unix")
        w.writeheader()
        w.writerows(sorted_list)

        verbose_print(f"Saved report to {out_csv}.")

    workbook = Workbook(out_xlsx)
    worksheet = workbook.add_worksheet()

    # Make the columns wider
    worksheet.set_column(0, 1, 14)
    worksheet.set_column(2, 3, 20)

    # Bold header row
    worksheet.set_row(0, None, workbook.add_format({"bold": 1}))

    n_row = 0
    n_col = 0

    for r, row in enumerate(sorted_list):
        for c, col in enumerate(row):
            if r == 0:
                # header row
                worksheet.write(0, c, col)
                n_col += 1
            worksheet.write(r + 1, c, row[col])
        n_row += 1

    worksheet.autofilter(0, 0, n_row - 1, n_col - 1)

    workbook.close()

    verbose_print(f"Saved report to {out_xlsx}.")
else:
    print(
        "All default security groups are compliant to 'vpc-default-security-group-closed'"
    )
