#!/usr/bin/env python

# List all missing patches identified by SSM
# Usage: ./ssm-patch-compliance.py --profile profile-name --region {us-east-1} --output output-dir
# Refer to README.md for more details

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter
from datetime import date
from itertools import count
from json import loads
from operator import itemgetter
from os import path
from pathlib import Path
from xlsxwriter.workbook import Workbook

ACCOUNT_NAME_DICT = {
  '012345678901': 'account-name'
}

parser = ArgumentParser(description = 'List all missing patches identified by the SSM.')
parser.add_argument('--profile', '-p',
  required = True,
  help = 'AWS profile name. Parsed from ~/.aws/config (SSO) or credentials (API key).')
parser.add_argument('--region', '-r',
  default = 'us-east-1',
  help = 'AWS Region.')
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
region = args.region
dir_path = args.output
Path(dir_path).mkdir(parents = True, exist_ok = True)

session = boto3.session.Session(profile_name = profile)
client = session.client('config', config = Config(region_name = region))

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

patch_status = []

results = select_aggregate_resource_config(f"SELECT accountId, awsRegion, resourceId, configuration WHERE resourceType = 'AWS::SSM::PatchCompliance'")
for resource in results:
  instance = loads(resource)
  account_id = instance['accountId']
  aws_region = instance['awsRegion']
  instance_id = instance['resourceId'].split('/')[1]
  patches = instance['configuration']['AWS:ComplianceItem']['Content']['Patch']

  missing = []
  for patch in patches:
    value = patches[patch]
    if value.get('PatchState', '') == 'Missing':
      missing.append(value['Title'])

  if len(missing) >= 1:
    patch_status.append({
      'ACCOUNT ID': account_id,
      'ACCOUNT': ACCOUNT_NAME_DICT[account_id],
      'REGION': aws_region,
      'INSTANCE ID': instance_id,
      'MISSING PATCHES': '\n'.join(missing)
    })

today = date.today().strftime('%Y%m%d')
summary_csv = path.join(dir_path, f'SSM-patch-compliance-{today}.csv')
summary_xlsx = path.join(dir_path, f'SSM-patch-compliance-{today}.xlsx')

if len(patch_status) >= 1:
  # sort by account name
  sorted_patch_status = sorted(patch_status, key = itemgetter('ACCOUNT'))

  with open(summary_csv, 'w') as f:
    w = DictWriter(f, fieldnames = list(sorted_patch_status[0]), dialect = 'unix')
    w.writeheader()
    w.writerows(sorted_patch_status)

  workbook = Workbook(summary_xlsx)
  worksheet = workbook.add_worksheet()

  # Make the columns wider
  worksheet.set_column(0, 2, 13)
  worksheet.set_column(3, 3, 20)
  worksheet.set_column(4, 4, 73)

  # Bold header row
  worksheet.set_row(0, None, workbook.add_format({ 'bold': 1 }))

  n_row = 0
  n_col = 0

  for r, row in enumerate(sorted_patch_status):
    for c, col in enumerate(row):
      worksheet.write(r + 1, c, row[col])
      if r == 0:
        # header row
        worksheet.write(0, c, col)
        n_col += 1
    n_row += 1

  worksheet.autofilter(0, 0, n_row - 1, n_col - 1)

  workbook.close()
