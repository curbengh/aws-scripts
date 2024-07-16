# Push WAF logs to Splunk using Data Firehose

## Deployment

### Allow Firehose IP in Splunk

Add Firehose's [regional CIDR blocks](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html#using-iam-splunk-vpc) to [IP allow list](https://myhost.splunkcloud.com/en-US/manager/system/manage_system_config/ip_allow_list) for HEC access in Splunk.

### HEC token

Create a new [HEC token](https://myhost.splunkcloud.com/en-US/manager/search/http-eventcollector), set the source type as (existing) "[aws:firehose:waf](https://gitlab.com/curben/splunk-scripts/-/tree/main/Splunk_TA_aws)" and save the token to hec_token.txt. Do not save using shell (echo/printf) [unless](https://www.gnu.org/software/bash/manual/bash.html#index-HISTCONTROL) you know what you're doing.

```
aws secretsmanager create-secret --name "WAF-Firehose-Splunk/hec_token" --secret-string file://hec_token.txt --description "Token to forward WAF logs to Splunk HEC via Firehose" --region "region-name"
rm "hec_token.txt"
```

Save the ARN value to `hec_token_secrets_arn` in [app.py](./app.py)

### S3 bucket in different region (optional)

Depending on preference or data sovereignty requirement, an S3 bucket can be deployed in a different region than the [Firehose's](#firehose). Note that regardless of region, by default the bucket will be used to store events that Firehose failed to deliver to Splunk. To configure Firehose to log all WAF events to S3 (and Splunk), update [`s3_backup_mode`](./main.py) to [`AllEvents`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-kinesisfirehose-deliverystream-splunkdestinationconfiguration.html#cfn-kinesisfirehose-deliverystream-splunkdestinationconfiguration-s3backupmode).

```
mkdir -p cdk.out
cdk synth WAF-Firehose-Splunk-S3Stack > cdk.out/s3stack.yml
cdk deploy -v WAF-Firehose-Splunk-S3Stack
```

Save the ARN value to `bucket_arn` in [app.py](./app.py). If the variable is left as an empty string, a bucket will be created in the [WAF-Firehose-Splunk](#firehose) stack instead.

#### Failed event

Object key: splunk-failed/YYYY/MM/DD/HH/{firehose-stream-name}-1-{YYYY-MM-DD-HH-mm-ss}-{random-uuid}

```json
{
  "attemptsMade": 1,
  "arrivalTimestamp": 1717550436356,
  "errorCode": "Splunk.InvalidToken",
  "errorMessage": "The HEC token is invalid. Update Kinesis Firehose with a valid HEC token.",
  "attemptEndingTimestamp": 1717550499585,
  "rawData": "base64-encoded",
  "subsequenceNumber": 0,
  "EventId": "56-digit.0"
}
```

#### WAF event

Decoded base64 or the WAF event schema:

```json
{
  "timestamp": 1717550468281,
  "formatVersion": 1,
  "webaclId": "waf-arn",
  "terminatingRuleId": "Default_Action",
  "terminatingRuleType": "REGULAR",
  "action": "ALLOW",
  "terminatingRuleMatchDetails": [],
  "httpSourceName": "CF",
  "httpSourceId": "cf-distribution-id",
  "ruleGroupList": [
    {
      "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
      "terminatingRule": null,
      "nonTerminatingMatchingRules": [],
      "excludeRules": null,
      "customerConfig": null
    }
  ],
  "rateBasedRuleList": [],
  "nonTerminatingMatchingRules": [],
  "requestHeadersInserted": null,
  "responseCodeSent": null,
  "httpRequest": {
    "clientIp": "ip-address",
    "country": "country-two-letter-code",
    "headers": [
      { "name": "host", "value": "cloudfront-domain-name" },
      { "name": "user-agent", "value": "curl/8.8.0" },
      { "name": "accept", "value": "*/*" }
    ],
    "uri": "/path",
    "args": "query-key=query-value",
    "httpVersion": "HTTP/2.0",
    "httpMethod": "GET",
    "requestId": "X-Amz-Cf-Id-value"
  },
  "ja3Fingerprint": "32-char-client-hello",
  "requestBodySize": 14,
  "requestBodySizeInspectedByWAF": 14
}
```

`terminatingRuleId` corresponds to the [`name`](https://gitlab.com/curben/aws-scripts/-/blob/91956d8d7b4a5766a13e6ccf1bb0c5e73920cccf/waf-cdk/cloudfront-waf/main.py#L42) of the matching Web ACL rule or `Default_Action` if there is no match.

### Firehose

```
mkdir -p cdk.out
cdk synth WAF-Firehose-Splunk > cdk.out/template.yml
cdk deploy -v WAF-Firehose-Splunk
```

Save the ARN value to `firehose_arn` in [cloudfront-waf-dev/app.py](../cloudfront-waf-dev/app.py)

## L2 construct

As of writing, [L2 construct](https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_kinesisfirehose_alpha/README.html) for Kinesis Firehose is not yet stable.
