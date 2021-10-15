#!/usr/bin/env python

# Download a list of resource compliance rules
# Usage: ./aws-config-ruless.py --profile profile-name --region {us-east-1} --output output-dir

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter
from datetime import date
from itertools import count
from json import loads
from os import path
from pathlib import Path

parser = ArgumentParser(description = 'List Config rules across all accounts and regions.')
parser.add_argument('--profile', '-p',
  required = True,
  help = 'AWS profile name. Parsed from ~/.aws/credentials.')
parser.add_argument('--region', '-r',
  default = 'us-east-1',
  help = 'AWS Region of Config Aggregator.')
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
region = args.region
dirPath = args.output
Path(dirPath).mkdir(parents = True, exist_ok = True)

session = boto3.session.Session(profile_name = profile)
client = session.client('config', config = my_config = Config(region_name = region))

def select_aggregate_resource_config(Expression):
  results = []
  response = {}
  for i in count():
    params = {
      'Expression': Expression,
      'ConfigurationAggregatorName': 'OrganizationConfigAggregator'
    }
    if i == 0 or 'NextToken' in response:
      if 'NextToken' in response:
        params['NextToken'] = response['NextToken']
      response = client.select_aggregate_resource_config(**params)
      results.extend(response['Results'])
    else:
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
