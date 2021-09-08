#!/usr/bin/env python

# Download AWS WAF's Web ACLs and convert them into human-readable format.
# Usage: ./waf-acl.py --profile profile-name --region {us-east-1} --scope-regional --directory output-dir --original --wcu --ip-set

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from datetime import date
from json import dump
from os import path
from pathlib import Path

parser = ArgumentParser(description = 'For the provided profile, download all web ACLs in human-readable format.')
parser.add_argument('--profile', '-p',
  help = 'AWS profile name. Parsed from ~/.aws/config (SSO) or credentials (API key).',
  required = True)
parser.add_argument('--region', '-r',
  help = 'AWS region',
  default = 'us-east-1')
parser.add_argument('--scope-regional', '-s',
  help = 'Regional scope',
  action = 'store_true')
parser.add_argument('--directory', '-d',
  help = 'Output folder. Exported links will be saved in the current folder if not specified.',
  default = '')
parser.add_argument('--original', '-a',
  help = 'Also save raw ACLs.',
  action = 'store_true')
parser.add_argument('--wcu', '-w',
  help = 'Calculate WCU value of each rule.',
  action = 'store_true')
# parser.add_argument('--total-wcu', '-t',
#   help = 'Shows the total WCU of each web ACL.',
#   action = 'store_true')
parser.add_argument('--ip-set', '-i',
  help = "Save IP address(es) of an IP set. Defaults to the IP set's name.",
  action = 'store_true')
args = parser.parse_args()
profile = args.profile
region = args.region
scope_regional = args.scope_regional
scope = 'REGIONAL' if scope_regional == True else 'CLOUDFRONT'
# CloudFront must specify 'us-east-1' region
if scope_regional == False:
  region = 'us-east-1'
dirPath = args.directory
Path(dirPath).mkdir(parents = True, exist_ok = True)
save_original = args.original
if save_original:
  Path(path.join(dirPath, 'original')).mkdir(parents = True, exist_ok = True)
show_wcu = args.wcu
# show_total_wcu = args.total_wcu
show_ip_set = args.ip_set

today = date.today().strftime('%Y%m%d')

session = boto3.session.Session(profile_name = profile)
my_config = Config(region_name = region)
client = session.client('wafv2', config = my_config)
web_acls = client.list_web_acls(Scope = scope)['WebACLs']

def byteToString(bts):
  if isinstance(bts, bytes):
    return str(bts, encoding = 'utf-8')
  return bts

# Parse first key of a dictionary
def first_key(obj):
  return list(obj)[0]

def field_to_match(obj):
  return first_key(obj).lower() \
  if 'SingleHeader' not in obj \
  else obj['SingleHeader']['Name'].lower()

def parse_statement(obj):
  first_key_obj = first_key(obj)
  text = first_key_obj
  wcu_statement = {}

  if not (first_key_obj == 'SqliMatchStatement' or first_key_obj == 'XssMatchStatement'):
    not_prefix = ''
    search_string = ''
    field_match = ''
    positional_constraint = ''

    if first_key_obj == 'NotStatement':
      not_prefix = 'NOT '
      obj = obj['NotStatement']['Statement']
      first_key_obj = first_key(obj)

    if first_key_obj == 'ByteMatchStatement':
      search_string = byteToString(obj['ByteMatchStatement']['SearchString'])
      field_match = first_key(obj['ByteMatchStatement']['FieldToMatch']) \
      if first_key(obj['ByteMatchStatement']['FieldToMatch']) != 'SingleHeader' \
      else obj['ByteMatchStatement']['FieldToMatch']['SingleHeader']['Name']
      positional_constraint = obj['ByteMatchStatement']['PositionalConstraint']

      # WCU Calculation
      wcu_statement['statement'] = 'string_match'
      # assume single-element TextTransformations
      wcu_statement['text_transform'] = obj['ByteMatchStatement']['TextTransformations'][0]['Type'].lower()
      wcu_statement['base'] = positional_constraint.lower()
      if 'TextTransformations' in obj['ByteMatchStatement']:
        wcu_statement['field'] = field_to_match(obj['ByteMatchStatement']['FieldToMatch'])
    elif first_key_obj == 'IPSetReferenceStatement':
      ip_set_arn = obj['IPSetReferenceStatement']['ARN']
      ip_set_name = ip_set_arn.split('/')[-2]
      ip_set_id = ip_set_arn.split('/')[-1]
      search_string = ip_set_name

      if show_ip_set:
        ip_set = client.get_ip_set(
          Name = ip_set_name,
          Scope = scope,
          Id = ip_set_id
        )
        search_string = ', '.join(ip_set['IPSet']['Addresses'])

      positional_constraint = 'IPSet'
      wcu_statement['statement'] = 'ipset'
    elif first_key_obj == 'GeoMatchStatement':
      search_string = ', '.join(obj['GeoMatchStatement']['CountryCodes'])
      positional_constraint = 'Geomatch'
      wcu_statement['statement'] = 'geomatch'

    separator = '=' if len(field_match) >= 1 else ''
    text = f'{not_prefix}{field_match}{separator}{positional_constraint}({search_string})'
  else:
    text = f'{first_key_obj}({first_key(obj[first_key_obj]["FieldToMatch"])})'
    if first_key_obj == 'SqliMatchStatement':
      wcu_statement['statement'] = 'sql'
      wcu_statement['text_transform'] = obj['SqliMatchStatement']['TextTransformations'][0]['Type'].lower()

      if 'TextTransformations' in obj['SqliMatchStatement']:
        wcu_statement['field'] = field_to_match(obj['SqliMatchStatement']['FieldToMatch'])
    else:
      wcu_statement['statement'] = 'xss'
      wcu_statement['text_transform'] = obj['XssMatchStatement']['TextTransformations'][0]['Type'].lower()

      if 'TextTransformations' in obj['XssMatchStatement']:
        wcu_statement['field'] = field_to_match(obj['XssMatchStatement']['FieldToMatch'])

  return {
    'text': text,
    'wcu_statement': wcu_statement
  }

# Make rule statements human-readable
def parse_rule(obj):
  text = ''
  first_key_obj = first_key(obj)
  wcu_rule = []
  not_prefix = ''

  if first_key_obj == 'NotStatement':
    not_prefix = 'NOT '
    obj = obj['NotStatement']['Statement']
    first_key_obj = first_key(obj)

  if first_key_obj == 'AndStatement' or first_key_obj == 'OrStatement':
    and_or = 'AND' if first_key_obj == 'AndStatement' else 'OR'
    open_paren = '(' if first_key_obj == 'OrStatement' else ''
    close_paren = ')' if first_key_obj == 'OrStatement' else ''
    statements = obj[first_key_obj]['Statements']

    for i in range(0, len(statements)):
      statement = statements[i]
      rule = parse_statement(statement)['text']

      if first_key(statement) == 'AndStatement' or first_key(statement) == 'OrStatement':
        rule = parse_rule(statement)['text']
        wcu_rule.extend(parse_rule(statement)['wcu_rule'])
      else:
        wcu_rule.append(parse_statement(statement)['wcu_statement'])

      if i == 0:
        text = f'{open_paren}{rule}'
      elif i == len(statements) - 1:
        text = f' {text} {and_or} {rule}{close_paren}'
      else:
        text = f' {text} {and_or} {rule}'
  else:
    statement = parse_statement(obj)
    text = statement['text']
    wcu_rule.append(statement['wcu_statement'])

  return {
    'text': text.strip(),
    'wcu_rule': wcu_rule
  }

wcu_dict = {
  'ipset': 1,
  'exactly': 2,
  'starts_with': 2,
  'ends_with': 2,
  'contains': 10,
  'contains_word': 10,
  'geomatch': 1,
  'sql': 20,
  'xss': 40,
  'text_transform': 10
}

def parse_web_acl(web_acl_rule):
  rules = []
  # web_acl_wcu = 0
  web_acl_text_transform = set()
  for rule in web_acl_rule:
    out_rule = {
      # Name: "Rule"
      # Action: "Allow|Block"
    }

    if 'RuleGroupReferenceStatement' in rule['Statement']:
      rulegroup_arn = rule['Statement']['RuleGroupReferenceStatement']['ARN']
      rulegroup_id = rulegroup_arn.split('/')[-1]
      rulegroup = client.get_rule_group(
        Name = rule['Name'],
        Scope = scope,
        Id = rulegroup_id,
        ARN = rulegroup_arn
      )
      parsed = parse_web_acl(rulegroup['RuleGroup']['Rules'])
      rules.extend(parsed['rules'])
      # web_acl_wcu = web_acl_wcu + parsed['web_acl_wcu']
      continue
    else:
      out_rule[rule['Name']] = parse_rule(rule['Statement'])['text']
      out_rule['Action'] = 'Allow' if first_key(rule['Action']) == 'Allow' else 'Block'

    # WCU calculation
    # if show_wcu or show_total_wcu:
    if show_wcu:
      statements = parse_rule(rule['Statement'])['wcu_rule']

      if len(statements) >= 1:
        rule_wcu = 0
        rule_text_transform = set()

        for statement in statements:
          rule_statement = statement['statement']
          if rule_statement == 'ipset' or rule_statement == 'sql' or rule_statement == 'xss':
            # web_acl_wcu = web_acl_wcu + wcu_dict[rule_statement]
            rule_wcu = rule_wcu + wcu_dict[rule_statement]
          elif rule_statement == 'string_match':
            # web_acl_wcu = web_acl_wcu + wcu_dict[statement['base']]
            rule_wcu = rule_wcu + wcu_dict[statement['base']]
          elif rule_statement == 'geomatch':
            rule_wcu = rule_wcu + wcu_dict[rule_statement] + (wcu_dict[rule_statement] * out_rule[rule['Name']].count(','))

          if 'text_transform' in statement:
            text_transform_key = statement['text_transform'] + statement['field']

            if text_transform_key not in web_acl_text_transform:
              # web_acl_wcu = web_acl_wcu + wcu_dict['text_transform']
              web_acl_text_transform.add(text_transform_key)

            if text_transform_key not in rule_text_transform:
              rule_wcu = rule_wcu + wcu_dict['text_transform']
              rule_text_transform.add(text_transform_key)

        if show_wcu:
          out_rule['WCU'] = rule_wcu

    rules.append(out_rule)

  return {
    'rules': rules,
    # 'web_acl_wcu': web_acl_wcu
  }

for web_acl in web_acls:
  web_acl_rule = client.get_web_acl(
    Name = web_acl['Name'],
    Scope = scope,
    Id = web_acl['Id']
  )

  parsed = parse_web_acl(web_acl_rule['WebACL']['Rules'])
  rules = parsed['rules']
  # web_acl_wcu = parsed['web_acl_wcu']

  if save_original:
    with open(path.join(dirPath, 'original', f'{web_acl["Name"]}-original-{today}.json'), 'w') as f:
      # response may contain byte data that json.dump() doesn't like, hence byteToString()
      dump(web_acl_rule['WebACL'], f, indent = 2, default = byteToString)

  with open(path.join(dirPath, f'{web_acl["Name"]}-{today}.json'), 'w') as f:
    dump(rules, f, indent = 2)

  # if show_total_wcu:
  #   print(f'{web_acl["Name"]} consumes {web_acl_wcu} WCU.')
