#!/usr/bin/env python

# Usage: ./aws-config.py --profile profile-name --rules space separated rules --output output-dir

from argparse import ArgumentParser
import boto3
from botocore.config import Config
from csv import DictWriter
from datetime import date
from json import dump, dumps, load, loads
from os import path
from pathlib import Path

VALID_RULES = [
  'access-keys-rotated',
  'acm-certificate-expiration-check',
  'alb-http-drop-invalid-header-enabled',
  'alb-http-to-https-redirection-check',
  'api-gw-associated-with-waf',
  'api-gw-execution-logging-enabled',
  'api-gw-ssl-enabled',
  'api-gw-xray-enabled',
  'aurora-mysql-backtracking-enabled',
  'beanstalk-enhanced-health-reporting-enabled',
  'cloud-trail-cloud-watch-logs-enabled',
  'cloud-trail-log-file-validation-enabled',
  'cloud-trail-enabled-in-region',
  'cloud-trail-encryption-enabled',
  'cloudfront-accesslogs-enabled',
  'cloudfront-associated-with-waf',
  'cloudfront-default-root-object-configured',
  'cloudtrail-enabled',
  'cmk-backing-key-rotation-enabled',
  'codebuild-project-envvar-awscred-check',
  'codebuild-project-source-repo-url-check',
  'dynamodb-autoscaling-enabled',
  'dynamodb-pitr-enabled',
  'ebs-snapshot-public-restorable-check',
  'ec2-ebs-encryption-by-default',
  'ec2-imdsv2-check',
  'ec2-instance-managed-by-ssm',
  'ec2-instance-multiple-eni-check',
  'ec2-instance-no-public-ip',
  'ec2-managedinstance-association-compliance-status-check',
  'ec2-managedinstance-patch-compliance',
  'ec2-security-group-attached-to-eni',
  'ec2-stopped-instance',
  'ecs-task-definition-user-for-host-mode-check',
  'efs-encrypted-check',
  'efs-in-backup-plan',
  'eip-attached',
  'elastic-beanstalk-managed-updates-enabled',
  'elb-connection-draining-enabled',
  'elb-logging-enabled',
  'elb-tls-https-listeners-only',
  'encrypted-volumes',
  'fms-shield-resource-policy-check',
  'guardduty-enabled-centralized',
  'iam-customer-policy-blocked-kms-actions',
  'iam-inline-policy-blocked-kms-actions',
  'iam-password-policy-recommended-defaults',
  'iam-password-policy-recommended-defaults-no-symbols-required',
  'iam-policy-no-statements-with-admin-access',
  'iam-policy-no-statements-with-full-access',
  'iam-root-access-key-check',
  'iam-user-mfa-enabled',
  'iam-user-no-policies-check',
  'iam-user-unused-credentials-check',
  'kms-cmk-not-scheduled-for-deletion',
  'lambda-dlq-check',
  'lambda-function-public-access-prohibited',
  'lambda-function-settings-check',
  'lambda-inside-vpc',
  'mfa-set-on-root-account',
  'multi-region-cloud-trail-enabled',
  'rds-automatic-minor-version-upgrade-enabled',
  'rds-cluster-copy-tags-to-snapshots-enabled',
  'rds-cluster-deletion-protection-enabled',
  'rds-cluster-iam-authentication-enabled',
  'rds-cluster-multi-az-enabled',
  'rds-deployed-in-vpc',
  'rds-enhanced-monitoring-enabled',
  'rds-instance-copy-tags-to-snapshots-enabled',
  'rds-instance-deletion-protection-enabled',
  'rds-instance-iam-authentication-enabled',
  'rds-instance-public-access-check',
  'rds-logging-enabled',
  'rds-multi-az-support',
  'rds-no-default-ports',
  'rds-snapshot-encrypted',
  'rds-snapshots-public-prohibited',
  'rds-storage-encrypted',
  'redshift-cluster-audit-logging-enabled',
  'redshift-cluster-maintenancesettings-check',
  'redshift-cluster-public-access-check',
  'redshift-require-tls-ssl',
  'redshift-enhanced-vpc-routing-enabled',
  'resources_tagged',
  'restricted-ssh',
  'root-account-hardware-mfa-enabled',
  'root-account-mfa-enabled',
  's3-bucket-blacklisted-actions-prohibited',
  's3-bucket-level-public-access-prohibited',
  's3-bucket-public-read-prohibited',
  's3-bucket-public-write-prohibited',
  's3-bucket-replication-enabled',
  's3-bucket-server-side-encryption-enabled',
  's3-bucket-ssl-requests-only',
  'secretsmanager-rotation-enabled-check',
  'secretsmanager-secret-periodic-rotation',
  'secretsmanager-secret-unused',
  'service-vpc-endpoint-enabled',
  'shield-advanced-enabled',
  'sns-encrypted-kms',
  'sqs-queue-encrypted',
  'subnet-auto-assign-public-ip-disabled',
  'vpc-default-security-group-closed',
  'vpc-flow-logs-enabled',
  'vpc-network-acl-unused-check',
  'vpc-sg-open-only-to-authorized-ports',
  'vpc-sg-restricted-common-ports'
]

ACCOUNT_NAME_DICT = {
  '012345678901': 'account-name'
}

VPC_RESOURCES = [
  'ec2-imdsv2-check',
  'ec2-instance-managed-by-ssm',
  'ec2-instance-multiple-eni-check',
  'ec2-instance-no-public-ip',
  'ec2-stopped-instance',
  'restricted-ssh',
  'service-vpc-endpoint-enabled',
  'subnet-auto-assign-public-ip-disabled',
  'vpc-default-security-group-closed',
  'vpc-flow-logs-enabled',
  'vpc-network-acl-unused-check',
  'vpc-sg-open-only-to-authorized-ports',
  'vpc-sg-restricted-common-ports'
]

# Some rules don't have resourceId
SKIP_RULES = [
  'cloud-trail-enabled-in-region',
  'cloudtrail-enabled',
  'ebs-snapshot-public-restorable-check',
  'ec2-ebs-encryption-by-default',
  'ecs-task-definition-user-for-host-mode-check',
  'efs-encrypted-check',
  'efs-in-backup-plan',
  'guardduty-enabled-centralized',
  'iam-password-policy-recommended-defaults',
  'iam-password-policy-recommended-defaults-no-symbols-required',
  'iam-root-access-key-check',
  'mfa-set-on-root-account',
  'multi-region-cloud-trail-enabled',
  'resources_tagged',
  'root-account-hardware-mfa-enabled',
  'root-account-mfa-enabled',
  'secretsmanager-rotation-enabled-check',
  'secretsmanager-secret-periodic-rotation',
  'secretsmanager-secret-unused',
  'shield-advanced-enabled',
  'sns-encrypted-kms',
  'sqs-queue-encrypted'
]

parser = ArgumentParser(description = 'AWS Resource Compliance')
parser.add_argument('--profile', '-p',
  default = 'security',
  help = 'AWS profile name. Parsed from ~/.aws/config (SSO) or credentials (API key).')
parser.add_argument('--rules', '-r',
  choices = VALID_RULES,
  help = 'Config Rule',
  required = True,
  nargs = '+')
parser.add_argument('--output', '-o',
  default = '',
  help = 'Output directory of CSV.')
args = parser.parse_args()
profile = args.profile
rules = args.rules
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

today = date.today().strftime('%Y%m%d')

# Cache ResourceCompliance output
RULE_CACHE = f'/tmp/ruleList-cache-{today}.txt'
ruleList = []

if path.exists(RULE_CACHE):
  with open(RULE_CACHE) as f:
    ruleList = load(f)
else:
  ruleList = select_aggregate_resource_config("SELECT accountId, awsRegion, configuration.targetResourceId, configuration.configRuleList.configRuleName, configuration.configRuleList.complianceType WHERE resourceType = 'AWS::Config::ResourceCompliance'")

  with open(RULE_CACHE, 'w') as f:
    dump(ruleList, f)

for rule in rules:
  resourceType = ''

  if rule.startswith('acm'):
    resourceType = 'AWS::ACM::Certificate'
  elif rule.startswith('alb'):
    resourceType = 'AWS::ElasticLoadBalancingV2::LoadBalancer'
  elif rule.startswith('api-gw'):
    resourceType = 'AWS::ApiGateway::Stage'
  elif rule.startswith('aurora') or rule.startswith('rds-cluster'):
    resourceType = 'AWS::RDS::DBCluster'
  elif 'beanstalk' in rule:
    resourceType = 'AWS::ElasticBeanstalk::Environment'
  elif 'cloud-trail' in rule:
    resourceType = 'AWS::CloudTrail::Trail'
  elif rule.startswith('cloudfront'):
    resourceType = "AWS::CloudFront::Distribution' AND configuration.distributionConfig.enabled = 'true"
  elif 'cmk' in rule:
    resourceType = "AWS::KMS::Key' AND configuration.enabled = 'true"
  elif rule.startswith('codebuild'):
    resourceType = 'AWS::CodeBuild::Project'
  elif rule.startswith('dynamodb'):
    resourceType = "AWS::DynamoDB::Table' AND configuration.tableStatus = 'ACTIVE"
  elif rule.startswith('ec2-instance') or rule == 'ec2-imdsv2-check':
    resourceType = "AWS::EC2::Instance' AND configuration.state.name = 'running"
  elif rule == 'ec2-stopped-instance':
    resourceType = 'AWS::EC2::Instance'
  elif rule == 'ec2-managedinstance-association-compliance-status-check':
    resourceType = 'AWS::SSM::AssociationCompliance'
  elif rule == 'ec2-managedinstance-patch-compliance':
    resourceType = 'AWS::SSM::PatchCompliance'
  elif rule.startswith('eip'):
    resourceType = 'AWS::EC2::EIP'
  elif rule.startswith('elb') or rule.startswith('fms'):
    resourceType = 'AWS::ElasticLoadBalancing::LoadBalancer'
  elif rule == 'encrypted-volumes':
    resourceType = 'AWS::EC2::Volume'
  elif rule.startswith('iam-policy'):
    resourceType = 'AWS::IAM::Policy'
  elif rule.startswith('iam-inline') or rule.startswith('iam-user') or rule.startswith('access-keys'):
    resourceType = 'AWS::IAM::User'
  elif rule.startswith('lambda'):
    resourceType = "AWS::Lambda::Function' AND configuration.state.value = 'Active"
  elif rule.startswith('rds-snapshot'):
    resourceType = "AWS::RDS::DBSnapshot' AND configuration.dBInstanceStatus = 'available"
  elif rule.startswith('rds'):
    resourceType = "AWS::RDS::DBInstance' AND configuration.dBInstanceStatus = 'available"
  elif rule.startswith('redshift'):
    resourceType = 'AWS::Redshift::Cluster'
  elif rule == 'restricted-ssh' or 'security-group' in rule or 'sg' in rule:
    resourceType = 'AWS::EC2::SecurityGroup'
  elif rule.startswith('subnet'):
    resourceType = 'AWS::EC2::Subnet'
  elif rule == 'service-vpc-endpoint-enabled' or rule == 'vpc-flow-logs-enabled':
    resourceType = 'AWS::EC2::VPC'
  elif rule.startswith('vpc'):
    resourceType = 'AWS::EC2::NetworkAcl'
  elif rule.startswith('s3'):
    resourceType = 'AWS::S3::Bucket'

  # List all ALBs
  id_name_dict = {
    # 'resourceId': 'resourceName'
  }

  resourceList = select_aggregate_resource_config(f"SELECT resourceId, resourceName, configuration WHERE resourceType = '{resourceType}'")
  resourceInfo = 'resourceName'

  for ele in resourceList:
    resource = loads(ele)
    configuration = resource['configuration']

    if rule == 'acm-certificate-expiration-check' or rule.startswith('cloudfront'):
      id_name_dict[resource['resourceId']] = configuration['domainName']
      resourceInfo = 'domainName'
    elif rule.startswith('alb'):
      id_name_dict[resource['resourceId']] = configuration.get('dNSName', '')
      resourceInfo = 'dNSName'
    elif 'cloud-trail' in rule:
      id_name_dict[resource['resourceId']] = configuration['s3BucketName']
      resourceInfo = 's3BucketName'
    elif 'cmk' in rule:
      id_name_dict[resource['resourceId']] = configuration['description']
      resourceInfo = 'description'
    elif rule.startswith('codebuild'):
      id_name_dict[resource['resourceId']] = configuration['name']
      resourceInfo = 'name'
    elif rule.startswith('dynamodb'):
      id_name_dict[resource['resourceId']] = configuration['tableId']
      resourceInfo = 'tableId'
    elif rule.startswith('ec2-managedinstance'):
      content_key = 'Association'
      if rule == 'ec2-managedinstance-patch-compliance':
        content_key = 'Patch'
      associations = configuration['AWS:ComplianceItem']['Content'][content_key]
      delete_keys = set()

      for key in associations:
        if associations[key]['Status'] == 'COMPLIANT' or associations[key]['Status'] == '':
          delete_keys.add(key)

      if len(delete_keys) >= 1:
        for ele in delete_keys:
          associations.pop(ele, None)
      id_name_dict[resource['resourceId']] = dumps(associations)
      resourceInfo = 'ComplianceItem'
    elif rule == 'encrypted-volumes':
      id_name_dict[resource['resourceId']] = configuration['snapshotId']
      resourceInfo = 'snapshotId'
    elif rule in VPC_RESOURCES:
      id_name_dict[resource['resourceId']] = configuration['vpcId']
      resourceInfo = 'vpcId'
    elif rule.startswith('elb') or rule.startswith('fms'):
      id_name_dict[resource['resourceId']] = configuration.get('dnsname', '')
      resourceInfo = 'dnsname'
    elif rule.startswith('lambda'):
      id_name_dict[resource['resourceId']] = ', '.join(configuration.get('vpcConfig', {}).get('securityGroupIds',[]))
      resourceInfo = 'securityGroupIds'
    elif rule.startswith('rds'):
      id_name_dict[resource['resourceId']] = configuration.get('dBInstanceIdentifier', '')
      resourceInfo = 'dBInstanceIdentifier'
    elif rule.startswith('redshift'):
      id_name_dict[resource['resourceId']] = configuration['dBName']
      resourceInfo = 'dBName'
    elif rule.startswith('s3'):
      id_name_dict[resource['resourceId']] = configuration['creationDate']
      resourceInfo = 'creationDate'
    else:
      id_name_dict[resource['resourceId']] = resource['resourceName']

  compliance_list = []

  for result in ruleList:
    resource = loads(result)
    configuration = resource['configuration']
    id_no = configuration['targetResourceId']

    if rule in SKIP_RULES:
      resourceType = 'resourceId'
      id_name_dict = { id_no: '' }

    for c_rule in configuration['configRuleList']:
      if rule in c_rule['configRuleName'] and id_no in id_name_dict:
        compliance_list.append({
          'accountId': resource['accountId'],
          'accountName': ACCOUNT_NAME_DICT[resource['accountId']],
          'awsRegion': resource['awsRegion'],
          resourceType: id_no,
          resourceInfo: id_name_dict[id_no],
          'compliance': c_rule['complianceType']
        })

  if len(compliance_list) >= 1:
    with open(path.join(dirPath, f'{rule}-{today}.csv'), 'w') as csv:
      # unix dialect = double quote + '\n' line ending
      w = DictWriter(csv, fieldnames = list(compliance_list[0]), dialect = 'unix')
      w.writeheader()
      w.writerows(compliance_list)
