# Deploy WAF through CDK Stack

WAF is scoped and attached to a Cloudfront distribution.

## Cloudfront policy

- Allow US IPs only

## WAF policy

- Block IPs other than 1.2.3.4 and 5.6.7.8
- 1.2.3.4 and 5.6.7.8 are still subjected to [AWSManagedRulesCommonRuleSet](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-crs)

## Order of deployment

1. [route53](./route53/)
2. [acm](./acm/)
3. [cloudfront-waf](./cloudfront-waf/)
