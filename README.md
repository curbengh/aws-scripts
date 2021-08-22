## WAF ACL Review

```
$ ./waf-acl.py --profile {profile-name} --directory {output-dir} --original --wcu --total-wcu
```

- **profile-name**: The profile name as listed in "~/.aws/credentials".
- **directory**: Output directory. It will be created if not exist. Defaults to current folder.
- **original**: Preserve the original ACL after conversion and save it with "-original" suffix.
- **wcu**: Output Web ACL Capacity Unit (WCU) of each rule
- **total-wcu**: Output the total WCU of each web ACL

## Resource Compliance using AWS Config

Script duration is roughly 1 minute per 1000 rules.

### List of resource compliance rules

List of rules across all accounts and regions.

```
$ ./all-rules.py --profile {profile-name} --output {output-dir}
```

### Resource Compliance

```
$ ./aws-config.py --profile {profile-name} --rule {rule-name} --output {output-dir}
```

Supported rules:
- [alb-http-drop-invalid-header-enabled](https://docs.aws.amazon.com/config/latest/developerguide/alb-http-drop-invalid-header-enabled.html): Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of `routing.http.drop_invalid_header_fields.enabled` is set to false
- [alb-http-to-https-redirection-check](https://docs.aws.amazon.com/config/latest/developerguide/alb-http-to-https-redirection-check.html): Checks if HTTP to HTTPS redirection is configured on all HTTP listeners of ALB
  * Also checks if one of more HTTP listeners have forwarding to an HTTP listener instead of redirection.
- [ebs-snapshot-public-restorable-check](https://docs.aws.amazon.com/config/latest/developerguide/ebs-snapshot-public-restorable-check.html): Checks whether EBS snapshots are not publicly restorable
- [ec2-instance-managed-by-ssm](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-managed-by-ssm.html): Checks whether the EC2 instances in your account are managed by AWS Systems Manager
- [ec2-instance-no-public-ip](https://docs.aws.amazon.com/config/latest/developerguide/ec2-instance-no-public-ip.html): Checks whether EC2 instances have a public IP association
- [iam-policy-no-statements-with-admin-access](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-admin-access.html): Checks the IAM policies that you create for Allow statements that grant permissions to all actions on all resources
- [iam-policy-no-statements-with-full-access](https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-full-access.html): Checks if IAM policies grant permissions to all actions on individual AWS resources
- [iam-root-access-key-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-root-access-key-check.html): Checks whether the root user access key is available
- [iam-user-mfa-enabled](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-mfa-enabled.html): Checks whether the users have MFA enabled
- [iam-user-unused-credentials-check](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-unused-credentials-check.html): Checks if IAM users have passwords or active access keys that have not been used within the configured number of days
- [lambda-function-public-access-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-public-access-prohibited.html): Checks if the AWS Lambda function policy attached to the Lambda resource prohibits public access
- [rds-instance-public-access-check](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html): Check whether the RDS instances are not publicly accessible
- [rds-snapshots-public-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html): Checks if RDS snapshots are public
- [restricted-ssh](https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html): Checks if the incoming SSH traffic for the security groups is accessible from 0.0.0.0/0
- [s3-bucket-blacklisted-actions-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-blacklisted-actions-prohibited.html): Checks if the S3 bucket policy does not allow blacklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts
- [s3-bucket-level-public-access-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-level-public-access-prohibited.html): Checks if S3 buckets are publicly accessible
- [s3-bucket-public-read-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html): Checks if S3 buckets do not allow public read access
- [s3-bucket-public-write-prohibited](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-write-prohibited.html): Checks if S3 buckets do not allow public write access
- [subnet-auto-assign-public-ip-disabled](https://docs.aws.amazon.com/config/latest/developerguide/subnet-auto-assign-public-ip-disabled.html): Checks if Amazon Virtual Private Cloud (Amazon VPC) subnets are assigned a public IP address
- [vpc-default-security-group-closed](https://docs.aws.amazon.com/config/latest/developerguide/vpc-default-security-group-closed.html): Checks that the default security group of any VPC does not allow inbound or outbound traffic
- [vpc-network-acl-unused-check](https://docs.aws.amazon.com/config/latest/developerguide/vpc-network-acl-unused-check.html): Checks if there are unused network access control lists (network ACLs). The rule is COMPLIANT if each network ACL is associated with a subnet
