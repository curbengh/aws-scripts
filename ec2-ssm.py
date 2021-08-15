#!/usr/bin/env python3

# Download a list of EC2 instances in all accounts with/out SSM
# https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-managed-by-systems-manager.html
# May take up to 3 mins to finish
# Usage: ./ec2-ssm.py --profile {audit} --output output-dir
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

parser = ArgumentParser(description = 'Download a list of EC2 instances in all accounts with/out SSM.')
parser.add_argument('--profile', '-p',
  # default = 'audit',
  help = 'AWS profile name. Parsed from ~/.aws/credentials.')
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
dirPath = args.output
Path(dirPath).mkdir(parents = True, exist_ok = True)

session = boto3.session.Session(profile_name = profile)
# use 'us-east-1' to query across multiple accounts and regions
my_config = Config(region_name = 'us-east-1')
client = session.client('config', config = my_config)

def select_aggregate_resource_config(Expression):
  response = client.select_aggregate_resource_config(
    Expression = Expression,
    ConfigurationAggregatorName = 'AggregatorName',
  )
  results = response['Results']

  while True:
    if 'NextToken' in response:
      response = client.select_aggregate_resource_config(
        Expression = Expression,
        ConfigurationAggregatorName = 'AggregatorName',
        NextToken = response['NextToken']
      )
      results.extend(response['Results'])
    else:
      break

  return results

# List all running instances
runningInstances = set()
listRunningInstances = select_aggregate_resource_config("SELECT resourceId WHERE resourceType = 'AWS::EC2::Instance' AND configuration.state.name = 'running'")
for ele in listRunningInstances:
  runningInstances.add(loads(ele)['resourceId'])

# List all rules
rulesList = select_aggregate_resource_config(f"SELECT accountId, awsRegion, configuration.targetResourceId, configuration.configRuleList.configRuleName, configuration.configRuleList.complianceType WHERE resourceType = 'AWS::Config::ResourceCompliance'")
ssmCompliance = []
account_name_dict = {
  '123456789012': 'account-name'
}

for result in rulesList:
  instance = loads(result)
  for rule in instance['configuration']['configRuleList']:
    # Query all running instances of 'securityhub-ec2-instance-managed-by-ssm' rules
    if 'securityhub-ec2-instance-managed-by-ssm-' in rule['configRuleName'] and instance['configuration']['targetResourceId'] in runningInstances:
      ssmCompliance.append({
        'accountId': instance['accountId'],
        # Convert account ID to name
        'accountName': account_name_dict[instance['accountId']],
        'awsRegion': instance['awsRegion'],
        'instanceId': instance['configuration']['targetResourceId'],
        'compliance': rule['complianceType']
      })

today = date.today().strftime('%Y%m%d')

if len(ssmCompliance) >= 1:
  with open(path.join(dirPath, f'running-ec2-ssm-compliance-{today}.csv'), 'w') as csv:
    # unix dialect = double quote + '\n' line ending
    w = DictWriter(csv, fieldnames = list(ssmCompliance[0].keys()), dialect = 'unix')
    w.writeheader()
    w.writerows(ssmCompliance)
