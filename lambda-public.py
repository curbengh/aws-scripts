#!/usr/bin/env python3

# Download a list of Lambda resources with/out public access
# https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-public-access-prohibited.html
# May take up to 3 mins to finish
# Usage: ./lambda-public.py --profile {audit} --output output-dir
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

parser = ArgumentParser(description = 'Download a list of Lambda resources with/out public access.')
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

# List all active lambdas
activeLambdas = set()
listActiveLambdas = select_aggregate_resource_config("SELECT resourceId WHERE resourceType = 'AWS::Lambda::Function' AND configuration.state.value = 'Active'")
for ele in listActiveLambdas:
  activeLambdas.add(loads(ele)['resourceId'])

rulesList = select_aggregate_resource_config("SELECT accountId, awsRegion, configuration.targetResourceId, configuration.configRuleList.configRuleName, configuration.configRuleList.complianceType WHERE resourceType = 'AWS::Config::ResourceCompliance'")
lambdaCompliance = []
account_name_dict = {
  '123456789012': 'account-name'
}

for result in rulesList:
  instance = loads(result)
  for rule in instance['configuration']['configRuleList']:
    # Query all running lambdas of 'securityhub-lambda-function-public-access-prohibited' rules
    if 'securityhub-lambda-function-public-access-prohibited-' in rule['configRuleName'] and instance['configuration']['targetResourceId'] in activeLambdas:
      lambdaCompliance.append({
        'accountId': instance['accountId'],
        # Convert account ID to name
        'accountName': account_name_dict[instance['accountId']],
        'awsRegion': instance['awsRegion'],
        'lambdaId': instance['configuration']['targetResourceId'],
        'compliance': rule['complianceType']
      })

today = date.today().strftime('%Y%m%d')

if len(lambdaCompliance) >= 1:
  with open(path.join(dirPath, f'active-lambda-public-access-compliance-{today}.csv'), 'w') as csv:
    # unix dialect = double quote + '\n' line ending
    w = DictWriter(csv, fieldnames = list(lambdaCompliance[0].keys()), dialect = 'unix')
    w.writeheader()
    w.writerows(lambdaCompliance)
