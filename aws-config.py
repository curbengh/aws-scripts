#!/usr/bin/env python3

# Usage: ./aws-config.py --profile profile-name --rule rule-name --output output-dir
# Requirements: pip3 -q install boto3
# Refer to README.md for more details

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter
from datetime import date
from json import loads
from os import path
from pathlib import Path

RULES = [
  'alb-http-drop-invalid-header-enabled',
  'alb-http-to-https-redirection-check',
  'ebs-snapshot-public-restorable-check',
  'ec2-instance-managed-by-ssm',
  'ec2-instance-no-public-ip',
  'iam-policy-no-statements-with-admin-access',
  'iam-policy-no-statements-with-full-access',
  'iam-root-access-key-check',
  'iam-user-mfa-enabled',
  'iam-user-unused-credentials-check',
  'lambda-function-public-access-prohibited',
  'rds-instance-public-access-check',
  'rds-snapshots-public-prohibited',
  'restricted-ssh',
  's3-bucket-blacklisted-actions-prohibited',
  's3-bucket-level-public-access-prohibited',
  's3-bucket-public-read-prohibited',
  's3-bucket-public-write-prohibited',
  'subnet-auto-assign-public-ip-disabled',
  'vpc-default-security-group-closed',
  'vpc-network-acl-unused-check'
]

parser = ArgumentParser(description = 'AWS Resource Compliance')
parser.add_argument('--profile', '-p',
  help = 'AWS profile name. Parsed from ~/.aws/credentials.')
parser.add_argument('--rule', '-r',
  choices = RULES,
  help = 'AWS profile name. Parsed from ~/.aws/credentials.',
  required = True)
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
rule = args.rule
dirPath = args.output
Path(dirPath).mkdir(parents = True, exist_ok = True)

session = boto3.session.Session(profile_name = profile)
# use 'us-east-1' to query across multiple accounts and regions
my_config = Config(region_name = 'us-east-1')
client = session.client('config', config = my_config)

def select_aggregate_resource_config(Expression):
  response = client.select_aggregate_resource_config(
    Expression = Expression,
    ConfigurationAggregatorName = 'OrganizationConfigAggregator',
  )
  results = response['Results']

  while True:
    if 'NextToken' in response:
      response = client.select_aggregate_resource_config(
        Expression = Expression,
        ConfigurationAggregatorName = 'OrganizationConfigAggregator',
        NextToken = response['NextToken']
      )
      results.extend(response['Results'])
    else:
      break

  return results

resourceType = ''
resourceName = 'resourceName'

if rule.startswith('alb'):
  resourceType = 'AWS::ElasticLoadBalancingV2::LoadBalancer'
elif rule.startswith('ec2'):
  resourceType = "AWS::EC2::Instance' AND configuration.state.name = 'running"
elif rule.startswith('iam-policy'):
  resourceType = 'AWS::IAM::Policy'
elif rule.startswith('iam-user'):
  resourceType = 'AWS::IAM::User'
elif rule.startswith('lambda'):
  resourceType = "AWS::Lambda::Function' AND configuration.state.value = 'Active"
elif rule.startswith('rds-instance'):
  resourceType = "AWS::RDS::DBInstance' AND configuration.dBInstanceStatus = 'available"
elif rule.startswith('rds-snapshots'):
  resourceType = "AWS::RDS::DBSnapshot' AND configuration.dBInstanceStatus = 'available"
elif rule == 'restricted-ssh' or 'security-group' in rule:
  resourceType = 'AWS::EC2::SecurityGroup'
  resourceName = 'configuration.vpcId'
elif rule.startswith('subnet'):
  resourceType = 'AWS::EC2::Subnet'
  resourceName = 'configuration.vpcId'
elif rule.startswith('vpc'):
  resourceType = 'AWS::EC2::NetworkAcl'
  resourceName = 'configuration.vpcId'
elif rule.startswith('s3'):
  resourceType = 'AWS::S3::Bucket'

# List all ALBs
id_name_dict = {
  # 'resourceId': 'resourceName'
}
VPC_RESOURCES = [
  'restricted-ssh',
  'subnet-auto-assign-public-ip-disabled',
  'vpc-default-security-group-closed',
  'vpc-network-acl-unused-check'
]
resourceList = select_aggregate_resource_config(f"SELECT resourceId, {resourceName} WHERE resourceType = '{resourceType}'")
for ele in resourceList:
  resource = loads(ele)
  if rule in VPC_RESOURCES:
    id_name_dict[resource['resourceId']] = resource['configuration']['vpcId']
  else:
    id_name_dict[resource['resourceId']] = resource['resourceName']

ruleList = select_aggregate_resource_config("SELECT accountId, awsRegion, configuration.targetResourceId, configuration.configRuleList.configRuleName, configuration.configRuleList.complianceType WHERE resourceType = 'AWS::Config::ResourceCompliance'")
compliance_list = []
account_name_dict = {
  '012345678901': 'account-name',
}

# Some rules are under AWS::::Account resource
AWS_ACC_RULES = [
  'ebs-snapshot-public-restorable-check',
  'iam-root-access-key-check'
]
if rule in AWS_ACC_RULES:
  id_name_dict = account_name_dict

for result in ruleList:
  resource = loads(result)
  id_no = resource['configuration']['targetResourceId']
  for c_rule in resource['configuration']['configRuleList']:
    if rule in c_rule['configRuleName'] and id_no in id_name_dict:
      compliance_list.append({
        'accountId': resource['accountId'],
        'accountName': account_name_dict[resource['accountId']],
        'awsRegion': resource['awsRegion'],
        resourceType: id_no,
        resourceName: id_name_dict[id_no],
        'compliance': c_rule['complianceType']
      })

today = date.today().strftime('%Y%m%d')

if len(compliance_list) >= 1:
  with open(path.join(dirPath, f'{rule}-{today}.csv'), 'w') as csv:
    # unix dialect = double quote + '\n' line ending
    w = DictWriter(csv, fieldnames = list(compliance_list[0].keys()), dialect = 'unix')
    w.writeheader()
    w.writerows(compliance_list)
