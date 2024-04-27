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

## HTTP Error 403

If an API client got HTTP error 403 that is not shown in the WAF [sampled requests](https://us-east-1.console.aws.amazon.com/wafv2/homev2/web-acls?region=global), it means the request has been blocked by CloudFront. Possible causes include:

- IP country is not listed in the `country_allowlist` variable in [cloudfront-waf/app.py](./cloudfront-waf/app.py).
- API client does not support newer ciphers listed in the [cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html) configured in [cloudfront-waf/main.py](./cloudfront-waf/main.py).

Use [Maxmind](https://www.maxmind.com/en/geoip-demo) or [iplocation.net](https://www.iplocation.net/ip-lookup) to determine the IP location. CloudFront [may be](https://repost.aws/questions/QUluTiTTEIQF69c6g8iNq7dA/ip-geolocalization-issue) using Maxmind, but the most accurate method of checking the IP location as seen by CloudFront is through [optional request headers](../cloudfront-httpbin/).
