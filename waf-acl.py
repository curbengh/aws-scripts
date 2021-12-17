#!/usr/bin/env python

'''
./waf-acl.py --profile [altitude-live,parkcharge-live] --directory output-dir --original --wcu --ip-set
'''

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import date
from json import dump
from os import path
from pathlib import Path

import boto3

TODAY = date.today().strftime('%Y%m%d')

parser = ArgumentParser(
  description = 'For the provided profile, download all web ACLs.',
  formatter_class = ArgumentDefaultsHelpFormatter)
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
  help = "Save IP address(es) of IP set. Defaults to IP set's name.",
  action = 'store_true')
args = parser.parse_args()
profile = args.profile
region = args.region
scope_regional = args.scope_regional
scope = 'REGIONAL' if scope_regional is True else 'CLOUDFRONT'
# CloudFront must specify 'us-east-1' region
if scope_regional is False:
  region = 'us-east-1'
dir_path = args.directory
Path(dir_path).mkdir(parents = True, exist_ok = True)
save_original = args.original
if save_original:
  Path(path.join(dir_path, 'original')).mkdir(parents = True, exist_ok = True)
show_wcu = args.wcu
# show_total_wcu = args.total_wcu
show_ip_set = args.ip_set


session = boto3.session.Session(profile_name = profile, region_name = region)
client = session.client('wafv2')
# list_web_acls() doesn't support paginator
web_acls = client.list_web_acls(Scope = scope)['WebACLs']

def byte_to_string(bts):
  '''Convert byte to string'''
  if isinstance(bts, bytes):
    return str(bts, encoding = 'utf-8')
  return bts

def first_key(obj):
  '''Parse first key of a dictionary'''
  return list(obj)[0]

def field_to_match(obj):
  '''Return value of "FieldToMatch" key'''
  return first_key(obj).lower() \
  if 'SingleHeader' not in obj \
  else obj['SingleHeader']['Name'].lower()

def parse_statement(obj):
  '''Parse each rule statement'''
  first_key_obj = first_key(obj)
  text = first_key_obj
  wcu_statement = {}

  if first_key_obj not in ('SqliMatchStatement', 'XssMatchStatement'):
    not_prefix = ''
    search_string = ''
    field_match = ''
    positional_constraint = ''

    if first_key_obj == 'NotStatement':
      not_prefix = 'NOT '
      obj = obj['NotStatement']['Statement']
      first_key_obj = first_key(obj)

    if first_key_obj == 'ByteMatchStatement':
      search_string = byte_to_string(obj['ByteMatchStatement']['SearchString'])
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

def parse_rule(obj):
  '''Parse each rule of a web ACL'''
  text = ''
  first_key_obj = first_key(obj)
  wcu_rule = []

  if first_key_obj == 'NotStatement':
    obj = obj['NotStatement']['Statement']
    first_key_obj = first_key(obj)

  if first_key_obj in ('AndStatement', 'OrStatement'):
    and_or = 'AND' if first_key_obj == 'AndStatement' else 'OR'
    open_paren = '(' if first_key_obj == 'OrStatement' else ''
    close_paren = ')' if first_key_obj == 'OrStatement' else ''
    statements = obj[first_key_obj]['Statements']

    for i in range(0, len(statements)): # pylint: disable=consider-using-enumerate
      statement = statements[i]
      rule = parse_statement(statement)['text']

      if first_key(statement) in ('AndStatement', 'OrStatement'):
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

def parse_web_acl(input_acl):
  '''Convert JSON-formatted web ACL to human-readable string'''
  rule_statements = []
  # web_acl_wcu = 0
  web_acl_text_transform = set()
  for rule in input_acl:
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
      parsed_statements = parse_web_acl(rulegroup['RuleGroup']['Rules'])
      rule_statements.extend(parsed_statements['rules'])
      # web_acl_wcu = web_acl_wcu + parsed_statements['web_acl_wcu']
      continue

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
          if rule_statement in ('ipset', 'sql', 'xss'):
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

    rule_statements.append(out_rule)

  return {
    'rules': rule_statements,
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
    with open(path.join(dir_path, 'original', f'{web_acl["Name"]}-original-{TODAY}.json'), 'w') as f:
      # response may contain byte data that json.dump() doesn't like, hence byte_to_string()
      dump(web_acl_rule['WebACL'], f, indent = 2, default = byte_to_string)

  with open(path.join(dir_path, f'{web_acl["Name"]}-{TODAY}.json'), 'w') as f:
    dump(rules, f, indent = 2)

  # if show_total_wcu:
  #   print(f'{web_acl["Name"]} consumes {web_acl_wcu} WCU.')
