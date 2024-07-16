# Push Cloudtrail logs to Splunk using Data Firehose

## Deployment

### Allow Firehose IP in Splunk

Add Firehose's [regional CIDR blocks](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html#using-iam-splunk-vpc) to [IP allow list](https://myhost.splunkcloud.com/en-US/manager/system/manage_system_config/ip_allow_list) for HEC access in Splunk.

### HEC token

Create a new [HEC token](https://myhost.splunkcloud.com/en-GB/manager/search/http-eventcollector), set the source type as (existing) "[aws:firehose:cloudtrail](https://gitlab.com/curben/splunk-scripts/-/tree/main/Splunk_TA_aws?ref_type=heads)" and save the token to hec_token.txt. Do not save using shell (echo/printf) [unless](https://www.gnu.org/software/bash/manual/bash.html#index-HISTCONTROL) you know what you're doing.

```
aws secretsmanager create-secret --name "Cloudtrail-Firehose-Splunk/hec_token" --secret-string file://hec_token.txt --description "Splunk HEC token to ingest Cloudtrail logs using Firehose" --region "region-name"
rm "hec_token.txt"
```

Save the ARN value to `hec_token_secrets_arn` in [app.py](./app.py)

## Cloudtrail event

```json
{
  "version": "0",
  "id": "uuid",
  "detail-type": "AWS API Call via CloudTrail",
  "source": "aws.sts",
  "account": "111111111111",
  "time": "2024-01-02T12:34:56Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "eventVersion": "1.08",
    "userIdentity": {
      "type": "AssumedRole",
      "principalId": "AROAVXF7D5K4U11TPRL57:example@example.com",
      "arn": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AmazonS3ReadOnlyAccess_8jndlndseu21jqn5/example@example.com",
      "accountId": "111111111111",
      "accessKeyId": "ASIAPONVPLPDAYRE495Z",
      "sessionContext": {
        "sessionIssuer": {
          "type": "Role",
          "principalId": "AROAVXF7D5K4U11TPRL57",
          "arn": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AmazonS3ReadOnlyAccess_8jndlndseu21jqn5/",
          "accountId": "111111111111",
          "userName": "AWSReservedSSO_AmazonS3ReadOnlyAccess_8jndlndseu21jqn5"
        },
        "webIdFederationData": {},
        "attributes": {
          "creationDate": "2024-01-02T12:34:55Z",
          "mfaAuthenticated": "false"
        }
      }
    },
    "eventTime": "2024-01-02T12:34:56Z",
    "eventSource": "sts.amazonaws.com",
    "eventName": "GetCallerIdentity",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "1.2.3.4",
    "userAgent": "aws-sdk-nodejs/2.1586.0 linux/v20.15.1 aws-cdk/2.135.0 promise",
    "requestParameters": null,
    "responseElements": null,
    "requestID": "uuid",
    "eventID": "uuid",
    "readOnly": true,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "111111111111",
    "eventCategory": "Management",
    "tlsDetails": {
      "tlsVersion": "TLSv1.3",
      "cipherSuite": "TLS_AES_128_GCM_SHA256",
      "clientProvidedHostHeader": "sts.us-east-1.amazonaws.com"
    }
  }
}
```
