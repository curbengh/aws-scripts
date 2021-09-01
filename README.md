## WAF ACL Review

Each web ACL will be saved to a JSON file named "{web-acl-name}-{YYYYMMDD}.json".

```
$ ./waf-acl.py --profile profile-name --region {us-east-1} --scope-regional --directory output-dir --original --wcu
```

- **profile-name**: The profile name as listed in "~/.aws/credentials".
- **directory**: Output directory. It will be created if not exist. Defaults to current folder.
- **region**: Region of web ACL, defaults to "us-east-1".
- **scope-regional**: Regional-scoped/non-Cloudfront ACL.
- **original**: Preserve the original ACL after conversion and save it with "-original" suffix.
- **wcu**: Output Web ACL Capacity Unit (WCU) of each rule
- **total-wcu** (disabled): Output the total WCU of each web ACL

## Resource Compliance using AWS Config

Script duration is roughly 1 minute per 1000 rules.

### List of resource compliance rules

List of rules across all accounts and regions. Output will be saved to "aws-config-rules.txt".

```
$ ./all-rules.py --profile profile-name --output output-dir
```

### Resource Compliance

List (non-)complient resources according to AWS Config rules.

Output will be saved to "{rule-name}-{YYYYMMDD}.csv" with the following columns:

- accountId
- accountName (_see `ACC_NAME_DICT` constant to configure_)
- awsRegion
- resourceId (e.g. EC2 instance ID)
- resourceName
- compliance (i.e. `COMPLIANT` or `NON_COMPLIANT`)

```
$ ./aws-config.py --profile {profile-name} --rules {space separated rules} --output {output-dir}
```

Supported Rules:
- [access-keys-rotated](https://docs.aws.amazon.com/config/latest/developerguide/access-keys-rotated.html)
- [acm-certificate-expiration-check](https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html)
- [alb-http-drop-invalid-header-enabled](https://docs.aws.amazon.com/config/latest/developerguide/alb-http-drop-invalid-header-enabled.html)
- [alb-http-to-https-redirection-check](https://docs.aws.amazon.com/config/latest/developerguide/alb-http-to-https-redirection-check.html)
- [api-gw-associated-with-waf](https://docs.aws.amazon.com/config/latest/developerguide/api-gw-associated-with-waf.html)
- [aurora-mysql-backtracking-enabled](https://docs.aws.amazon.com/config/latest/developerguide/aurora-mysql-backtracking-enabled.html)
- [autoscaling-group-elb-healthcheck-required](https://docs.aws.amazon.com/config/latest/developerguide/autoscaling-group-elb-healthcheck-required.html)
- [beanstalk-enhanced-health-reporting-enabled](https://docs.aws.amazon.com/config/latest/developerguide/beanstalk-enhanced-health-reporting-enabled.html)
- [cloud-trail-log-file-validation-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-log-file-validation-enabled.html)
- [cloud-trail-cloud-watch-logs-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-cloud-watch-logs-enabled.html)
- [cloud-trail-encryption-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-encryption-enabled.html)
- [cloud-trail-enabled-in-region](https://docs.aws.amazon.com/config/latest/developerguide/cloud-trail-enabled-in-region.html)
- [cloudtrail-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html)
- [cloudfront-accesslogs-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloudfront-accesslogs-enabled.html)
- [cloudfront-associated-with-waf](https://docs.aws.amazon.com/config/latest/developerguide/cloudfront-associated-with-waf.html)
- [cloudfront-default-root-object-configured](https://docs.aws.amazon.com/config/latest/developerguide/cloudfront-default-root-object-configured.html)
- [cmk-backing-key-rotation-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cmk-backing-key-rotation-enabled.html)
- [codebuild-project-envvar-awscred-check](https://docs.aws.amazon.com/config/latest/developerguide/codebuild-project-envvar-awscred-check.html)
- [codebuild-project-source-repo-url-check](https://docs.aws.amazon.com/config/latest/developerguide/codebuild-project-source-repo-url-check.html)
- [dynamodb-autoscaling-enabled](https://docs.aws.amazon.com/config/latest/developerguide/dynamodb-autoscaling-enabled.html)
- [dynamodb-pitr-enabled](https://docs.aws.amazon.com/config/latest/developerguide/dynamodb-pitr-enabled.html)
- [ebs-snapshot-public-restorable-check](https://docs.aws.amazon.com/config/latest/developerguide/ebs-snapshot-public-restorable-check.html)
- [ec2-ebs-encryption-by-default](https://docs.aws.amazon.com/config/latest/developerguide/ec2-ebs-encryption-by-default.html)
- [ec2-imdsv2-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-imdsv2-check.html)
- [ec2-instance-managed-by-ssm](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-managed-by-ssm.html)
- [ec2-instance-multiple-eni-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-multiple-eni-check.html)
- [ec2-instance-no-public-ip](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-no-public-ip.html)
- [ec2-managedinstance-association-compliance-status-check](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-association-compliance-status-check.html)
- [ec2-managedinstance-patch-compliance](https://docs.aws.amazon.com/config/latest/developerguide/ec2-managedinstance-patch-compliance.html)
- [ec2-security-group-attached-to-eni](https://docs.aws.amazon.com/config/latest/developerguide/ec2-security-group-attached-to-eni.html)
- [ec2-stopped-instance](https://docs.aws.amazon.com/config/latest/developerguide/ec2-stopped-instance.html)
- [ecs-task-definition-user-for-host-mode-check](https://docs.aws.amazon.com/config/latest/developerguide/ecs-task-definition-user-for-host-mode-check.html)
- [efs-encrypted-check](https://docs.aws.amazon.com/config/latest/developerguide/efs-encrypted-check.html)
- [efs-in-backup-plan](https://docs.aws.amazon.com/config/latest/developerguide/efs-in-backup-plan.html)
- [eip-attached](https://docs.aws.amazon.com/config/latest/developerguide/eip-attached.html)
- [elastic-beanstalk-managed-updates-enabled](https://docs.aws.amazon.com/config/latest/developerguide/elastic-beanstalk-managed-updates-enabled.html)
- [elb-connection-draining-enabled](https://docs.aws.amazon.com/config/latest/developerguide/elb-connection-draining-enabled.html)
- [elb-logging-enabled](https://docs.aws.amazon.com/config/latest/developerguide/elb-logging-enabled.html)
- [elb-tls-https-listeners-only](https://docs.aws.amazon.com/config/latest/developerguide/elb-tls-https-listeners-only.html)
- [encrypted-volumes](https://docs.aws.amazon.com/config/latest/developerguide/encrypted-volumes.html)
- [fms-shield-resource-policy-check](https://docs.aws.amazon.com/config/latest/developerguide/fms-shield-resource-policy-check.html)
- [guardduty-enabled-centralized](https://docs.aws.amazon.com/config/latest/developerguide/guardduty-enabled-centralized.html)
- [iam-customer-policy-blocked-kms-actions](https://docs.aws.amazon.com/config/latest/developerguide/iam-customer-policy-blocked-kms-actions.html)
- [iam-inline-policy-blocked-kms-actions](https://docs.aws.amazon.com/config/latest/developerguide/iam-inline-policy-blocked-kms-actions.html)
- [iam-password-policy-recommended-defaults](https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy-recommended-defaults.html)
- [iam-password-policy-recommended-defaults-no-symbols-required](https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy-recommended-defaults-no-symbols-required.html)
- [iam-policy-no-statements-with-admin-access](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-admin-access.html)
- [iam-policy-no-statements-with-full-access](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-full-access.html)
- [iam-root-access-key-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-root-access-key-check.html)
- [iam-user-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-mfa-enabled.html)
- [iam-user-no-policies-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-no-policies-check.html)
- [iam-user-unused-credentials-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-unused-credentials-check.html)
- [kms-cmk-not-scheduled-for-deletion](https://docs.aws.amazon.com/config/latest/developerguide/kms-cmk-not-scheduled-for-deletion.html)
- [lambda-dlq-check](https://docs.aws.amazon.com/config/latest/developerguide/lambda-dlq-check.html)
- [lambda-function-public-access-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-public-access-prohibited.html)
- [lambda-function-settings-check](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-settings-check.html)
- [lambda-inside-vpc](https://docs.aws.amazon.com/config/latest/developerguide/lambda-inside-vpc.html)
- [mfa-set-on-root-account](https://docs.aws.amazon.com/config/latest/developerguide/mfa-set-on-root-account.html)
- [multi-region-cloud-trail-enabled](https://docs.aws.amazon.com/config/latest/developerguide/multi-region-cloud-trail-enabled.html)
- [rds-automatic-minor-version-upgrade-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-automatic-minor-version-upgrade-enabled.html)
- [rds-cluster-copy-tags-to-snapshots-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-copy-tags-to-snapshots-enabled.html)
- [rds-cluster-deletion-protection-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-deletion-protection-enabled.html)
- [rds-cluster-iam-authentication-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-iam-authentication-enabled.html)
- [rds-cluster-multi-az-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-multi-az-enabled.html)
- [rds-deployed-in-vpc](https://docs.aws.amazon.com/config/latest/developerguide/rds-deployed-in-vpc.html)
- [rds-enhanced-monitoring-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-enhanced-monitoring-enabled.html)
- [rds-instance-copy-tags-to-snapshots-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-copy-tags-to-snapshots-enabled.html)
- [rds-instance-deletion-protection-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-deletion-protection-enabled.html)
- [rds-instance-iam-authentication-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-iam-authentication-enabled.html)
- [rds-instance-public-access-check](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html)
- [rds-logging-enabled](https://docs.aws.amazon.com/config/latest/developerguide/rds-logging-enabled.html)
- [rds-multi-az-support](https://docs.aws.amazon.com/config/latest/developerguide/rds-multi-az-support.html)
- [rds-no-default-ports](https://docs.aws.amazon.com/config/latest/developerguide/rds-no-default-ports.html)
- [rds-snapshot-encrypted](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshot-encrypted.html)
- [rds-snapshots-public-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html)
- [rds-storage-encrypted](https://docs.aws.amazon.com/config/latest/developerguide/rds-storage-encrypted.html)
- [redshift-cluster-audit-logging-enabled](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-audit-logging-enabled.html)
- [redshift-cluster-maintenancesettings-check](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-maintenancesettings-check.html)
- [redshift-cluster-public-access-check](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-public-access-check.html)
- [redshift-require-tls-ssl](https://docs.aws.amazon.com/config/latest/developerguide/redshift-require-tls-ssl.html)
- [redshift-enhanced-vpc-routing-enabled](https://docs.aws.amazon.com/config/latest/developerguide/redshift-enhanced-vpc-routing-enabled.html)
- resources_tagged
- [restricted-ssh](https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html)
- [root-account-hardware-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/root-account-hardware-mfa-enabled.html)
- [root-account-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/root-account-mfa-enabled.html)
- [s3-bucket-blacklisted-actions-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-blacklisted-actions-prohibited.html)
- [s3-bucket-level-public-access-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-level-public-access-prohibited.html)
- [s3-bucket-public-read-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html)
- [s3-bucket-public-write-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-write-prohibited.html)
- [secretsmanager-rotation-enabled-check](https://docs.aws.amazon.com/config/latest/developerguide/secretsmanager-rotation-enabled-check.html)
- [secretsmanager-secret-periodic-rotation](https://docs.aws.amazon.com/config/latest/developerguide/secretsmanager-secret-periodic-rotation.html)
- [secretsmanager-secret-unused](https://docs.aws.amazon.com/config/latest/developerguide/secretsmanager-secret-unused.html)
- [service-vpc-endpoint-enabled](https://docs.aws.amazon.com/config/latest/developerguide/service-vpc-endpoint-enabled.html)
- [shield-advanced-enabled](https://docs.aws.amazon.com/config/latest/developerguide/shield-advanced-enabled.html)
- [sns-encrypted-kms](https://docs.aws.amazon.com/config/latest/developerguide/sns-encrypted-kms.html)
- [subnet-auto-assign-public-ip-disabled](https://docs.aws.amazon.com/config/latest/developerguide/subnet-auto-assign-public-ip-disabled.html)
- [vpc-default-security-group-closed](https://docs.aws.amazon.com/config/latest/developerguide/vpc-default-security-group-closed.html)
- [vpc-flow-logs-enabled](https://docs.aws.amazon.com/config/latest/developerguide/vpc-flow-logs-enabled.html)
- [vpc-network-acl-unused-check](https://docs.aws.amazon.com/config/latest/developerguide/vpc-network-acl-unused-check.html)
- [vpc-sg-open-only-to-authorized-ports](https://docs.aws.amazon.com/config/latest/developerguide/vpc-sg-open-only-to-authorized-ports.html)
- [vpc-sg-restricted-common-ports](https://docs.aws.amazon.com/config/latest/developerguide/vpc-sg-restricted-common-ports.html)
