#!/usr/bin/env python

# Checks that the default security group of any VPC does not allow inbound or outbound traffic.
# Usage: ./vpc-default-security-group-closed.py --profile profile-name --region region-name --migrate --eni-attachment
# Refer to README.md for more details

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter

TODAY = date.today().strftime('%Y%m%d')

parser = ArgumentParser(description = 'AWS Resource Compliance')
parser.add_argument('--profile', '-p',
  required = True,
  help = 'AWS profile name. Parsed from ~/.aws/config (SSO) or credentials (API key).')
parser.add_argument('--region', '-r',
  required = True,
  help = 'AWS region.')
parser.add_argument('--migrate', '-m',
  help = 'Migrate attached non-compliant default security groups to custom security groups.',
  action = 'store_true')
parser.add_argument('--eni-attachment', '-e',
  help = 'Export a list of non-compliant default security groups to a CSV.',
  action = 'store_true')
args = parser.parse_args()
profile = args.profile
region = args.region
is_migrate = args.migrate
is_export_eni_report = args.eni_attachment

session = boto3.session.Session(profile_name = profile)
client = session.client('ec2', config = my_Config(region_name = region)config)

def paginator(name, value, operation_name):
  response = []
  client = session.client('ec2', config = my_Config(region_name = region)config)
  response_iterator = client.get_paginator(operation_name).paginate(
    Filters = [
      {
        'Name': name,
        'Values': [
          value
        ]
      }
    ]
  )

  for page in response_iterator:
    response.append(page)

  return response

# Query all default security groups with non-empty rules
sg_list = []
for page in paginator('group-name', 'default', 'describe_security_groups'):
  for sg in page['SecurityGroups']:
    if len(sg.get('IpPermissions', [])) >= 1 or len(sg.get('IpPermissionsEgress', [])) >= 1:
      sg_list.append(sg['GroupId'])

fixed_sg = []

for sg_id in sg_list:
  # Query all ENI IDs attached to the security group
  network_interfaces = []

  for page in paginator('group-id', sg_id, 'describe_network_interfaces'):
    for network_interface in page['NetworkInterfaces']:
      network_interfaces.append(network_interface)

  if is_export_eni_report == True:
    with open(f'default-sg-attachment-{TODAY}.csv', 'a') as c:
      attached = 'Y' if len(network_interfaces) >= 1 else 'N'
      c.write(f'{profile},{region},{sg_id},{attached}\n')
    continue

  # Query description of the security group
  default_sg = paginator('group-id', sg_id, 'describe_security_groups')[0]['SecurityGroups'][0]

  # Query inbound/outbound rules of the security group
  sg_rules = []

  for page in paginator('group-id', sg_id, 'describe_security_group_rules'):
    for sg in page['SecurityGroupRules']:
      sg_rules.append(sg)

  # Migrate rules for attached security groups
  if len(network_interfaces) >= 1 and is_migrate == True:
    groupName = f'Migrated from {sg_id}'
    for tag in default_sg['Tags']:
      if tag['Key'] == 'Name':
        groupName = tag['Value']

    # Create a new security group
    new_sg = client.create_security_group(
      Description = f'Migrated from {sg_id}',
      GroupName = groupName,
      VpcId = default_sg['VpcId'],
      TagSpecifications = [
        {
          'ResourceType': 'security-group',
          'Tags': default_sg['Tags']
        }
      ]
    )

    # Copy and assign rules to the new security group
    ingress_ip_permissions = []
    for permission in default_sg.get('IpPermissions', []):
      for group_pair in permission.get('UserIdGroupPairs', []):
        if group_pair['GroupId'] == sg_id:
          # Replace default group <-> group allow rule
          group_pair['GroupId'] = new_sg['GroupId']

      ingress_ip_permissions.append(permission)

    if len(ingress_ip_permissions) >= 1:
      client.authorize_security_group_ingress(
        GroupId = new_sg['GroupId'],
        IpPermissions = ingress_ip_permissions
      )

    egress_ip_permissions = []
    for permission in default_sg.get('IpPermissionsEgress', []):
      for group_pair in permission.get('UserIdGroupPairs', []):
        if group_pair['GroupId'] == sg_id:
          group_pair['GroupId'] = new_sg['GroupId']

      # By default, security groups allow all outbound traffic.
      if not (permission['IpProtocol'] == '-1' and len(permission['IpRanges']) >= 1 and permission['IpRanges'][0].get('CidrIp', '') == '0.0.0.0/0'):
        egress_ip_permissions.append(permission)

    if len(egress_ip_permissions) >= 1:
      client.authorize_security_group_egress(
        GroupId = new_sg['GroupId'],
        IpPermissions = egress_ip_permissions
      )

    for eni in network_interfaces:
      # Query current attachments
      eni_group_set = client.describe_network_interface_attribute(
        Attribute = 'groupSet',
        NetworkInterfaceId = eni['NetworkInterfaceId']
      )

      new_groups = [new_sg['GroupId']]
      for group in eni_group_set.get('Groups', []):
        if group['GroupId'] != sg_id:
          new_groups.append(eni_group_set['GroupId'])

      # Detach default security group and attach newly created one to the ENI
      requester_id = eni.get('RequesterId', '')
      if requester_id == 'amazon-elb':
        client = session.client('elbv2', config = my_config)
        client.set_security_groups(
          LoadBalancerArn = f'arn:aws:elasticloadbalancing:{region}:{eni["OwnerId"]}:loadbalancer/{eni["Description"].split(" ")[1]}',
          SecurityGroups = new_groups
        )
      elif requester_id == 'amazon-rds':
        client = session.client('rds', config = my_config)
        response_iterator = client.get_paginator('describe_db_instances').paginate()
        for page in response_iterator:
          for rds in page['DBInstances']:
            for vpc_sg in rds['VpcSecurityGroups']:
              if vpc_sg['VpcSecurityGroupId'] == sg_id:
                client.modify_db_instance(
                  DBInstanceIdentifier = rds['DBInstanceIdentifier'],
                  VpcSecurityGroupIds = new_groups
                )
      elif requester_id == 'amazon-redshift':
        response_iterator = client.get_paginator('describe_clusters').paginate()
        for page in response_iterator:
          for cluster in page['Clusters']:
            for vpc_sg in cluster['VpcSecurityGroups']:
              if vpc_sg['VpcSecurityGroupId'] == sg_id:
                client.modify_cluster(
                  ClusterIdentifier = cluster['ClusterIdentifier'],
                  VpcSecurityGroupIds = new_groups
                )
      else:
        client = session.client('ec2', config = my_config)
        try:
          client.modify_network_interface_attribute(
            Groups = new_groups,
            NetworkInterfaceId = eni['NetworkInterfaceId']
          )
        except:
          print(f'Error: cannot modify ENI ID "{eni["NetworkInterfaceId"]}", Description "{eni["Description"]}"')

    client = session.client('ec2', config = my_config)

    # Remove all rules from default security group
    ingress_rule_ids = []
    egress_rule_ids = []
    for rule in sg_rules:
      if rule['IsEgress'] == False:
        ingress_rule_ids.append(rule['SecurityGroupRuleId'])
      else:
        egress_rule_ids.append(rule['SecurityGroupRuleId'])

    if len(ingress_rule_ids) >= 1:
      client.revoke_security_group_ingress(
        GroupId = sg_id,
        SecurityGroupRuleIds = ingress_rule_ids
      )

    if len(egress_rule_ids) >= 1:
      client.revoke_security_group_egress(
        GroupId = sg_id,
        SecurityGroupRuleIds = egress_rule_ids
      )

    fixed_sg.append(sg_id)
  elif len(network_interfaces) == 0: # Remove rules for un-attached security groups
    client = session.client('ec2', config = my_config)

    # Remove all rules from default security group
    ingress_rule_ids = []
    egress_rule_ids = []
    for rule in sg_rules:
      if rule['IsEgress'] == False:
        ingress_rule_ids.append(rule['SecurityGroupRuleId'])
      else:
        egress_rule_ids.append(rule['SecurityGroupRuleId'])

    if len(ingress_rule_ids) >= 1:
      client.revoke_security_group_ingress(
        GroupId = sg_id,
        SecurityGroupRuleIds = ingress_rule_ids
      )

    if len(egress_rule_ids) >= 1:
      client.revoke_security_group_egress(
        GroupId = sg_id,
        SecurityGroupRuleIds = egress_rule_ids
      )

    fixed_sg.append(sg_id)

if len(sg_list) >= 1 and is_export_eni_report == False:
  with open(f'migrated-sg-{profile}-{region}-{TODAY}.csv', 'w') as c:
    fieldnames = ['SECURITY GROUP', 'FIXED']
    w = DictWriter(c, fieldnames = fieldnames, dialect = 'unix')
    w.writerheader()

    for sg_id in sg_list:
      fixed = 'Y' if sg_id in fixed_sg else 'N'
      w.writerow({
        'SECURITY GROUP': sg_id,
        'FIXED': fixed
      })
