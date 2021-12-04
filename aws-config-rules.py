#!/usr/bin/env python

'''
Download a list of resource compliance rules
Usage: ./aws-config-rules.py --profile profile-name --region {us-east-1} --output output-dir
'''

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import date
from itertools import count
from json import loads
from os import path
from pathlib import Path

import boto3

TODAY = date.today().strftime('%Y%m%d')

parser = ArgumentParser(
  description = 'List Config rules across all accounts and regions.',
  formatter_class = ArgumentDefaultsHelpFormatter)
parser.add_argument('--profile', '-p',
  required = True,
  help = 'AWS profile name. '
    'Parsed from ~/.aws/config (SSO) or credentials (API key). '
    'Corresponds to the account where Config is deployed.')
parser.add_argument('--region', '-r',
  default = 'us-east-1',
  help = 'AWS Region of Config Aggregator.')
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
region = args.region
dir_path = args.output
Path(dir_path).mkdir(parents = True, exist_ok = True)

session = boto3.session.Session(profile_name = profile, region_name = region)
client = session.client('config')

def select_aggregate_resource_config(expression):
  '''Run Config (SQL) query specified by "expression" argument'''
  results = []
  response = {}
  for i in count():
    params = {
      'Expression': expression,
      'ConfigurationAggregatorName': 'OrganizationConfigAggregator'
    }
    if i == 0 or 'NextToken' in response:
      if 'NextToken' in response:
        params['NextToken'] = response['NextToken']
      response = client.select_aggregate_resource_config(**params)
      results.extend(response['Results'])
    else:
      break

  return results

# List all rules
rule_list = select_aggregate_resource_config('SELECT configuration.configRuleList.configRuleName '
  "WHERE resourceType = 'AWS::Config::ResourceCompliance'")

all_rules = set()
for result in rule_list:
  for rule in loads(result)['configuration']['configRuleList']:
    all_rules.add(rule['configRuleName'])

with open(path.join(dir_path, f'aws-config-rules-{TODAY}.txt', 'w')) as f:
  for rule in all_rules:
    f.write(rule + '\n')
