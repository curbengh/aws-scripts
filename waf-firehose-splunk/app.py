#!/usr/bin/env python

"""
Synthesise WAF-Firehose-Splunk-Stack into a CloudFormation template
"""

from os import environ

from aws_cdk import App, Environment
from main import S3Stack, main

app = App()
name = "WAF-Firehose-Splunk"
s3_region = "eu-west-2"
# same region as WAF, if using "../waf-cdk/cloudfront-waf"
# https://docs.aws.amazon.com/waf/latest/developerguide/logging-kinesis.html#logging-kinesis-configuration
firehose_region = "us-east-1"

S3Stack(
    app,
    f"{name}-S3Stack",
    stack_name=f"{name}-S3Stack",
    name=f"{name}-S3Stack",
    env=Environment(
        account=environ["CDK_DEFAULT_ACCOUNT"],
        region=s3_region,
    ),
)

# SSM secure string is not supported in AWS::KinesisFirehose::DeliveryStream.SplunkDestinationConfiguration.hec_token
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-ssm-secure-strings
hec_token_secrets_arn = "arn-value"

hec_endpoint = "https://http-inputs-firehose-myhost.splunkcloud.com:443"
# cross-region reference is still experimental
# https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk/README.html#accessing-resources-in-a-different-stack-and-region
bucket_arn = ""  # output of WAF-Firehose-Splunk-S3Stack (if used)

main(
    app,
    f"{name}",
    stack_name=f"{name}-Stack",
    name=f"{name}",
    env=Environment(
        account=environ["CDK_DEFAULT_ACCOUNT"],
        region=firehose_region,
    ),
    hec_endpoint=hec_endpoint,
    hec_token_secrets_arn=hec_token_secrets_arn,
    bucket_arn=bucket_arn,
)

app.synth()
