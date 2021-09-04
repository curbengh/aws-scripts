#!/usr/bin/env python

# Download a list of resource compliance rules
# Usage: ./aws-config-ruless.py --profile profile-name --output output-dir

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter
from datetime import date
from json import loads
from os import path
from pathlib import Path

parser = ArgumentParser(description = 'For the provided profile, download all web ACLs.')
parser.add_argument('--profile', '-p',
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

# List all rules
rulesList = select_aggregate_resource_config("SELECT configuration.configRuleList.configRuleName WHERE resourceType = 'AWS::Config::ResourceCompliance'")
all_rules = set()
for result in rulesList:
  for rule in loads(result)['configuration']['configRuleList']:
      all_rules.add(rule['configRuleName'])

with open('aws-config-rules.txt', 'w') as f:
  for rule in all_rules:
    f.write(rule + '\n')
