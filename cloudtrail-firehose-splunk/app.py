#!/usr/bin/env python

"""
Synthesise Cloudtrail-Firehose-Splunk-Stack into a CloudFormation template
"""

from os import environ

from aws_cdk import App, Environment
from main import main

app = App()
name = "Cloudtrail-Firehose-Splunk"
hec_token_secrets_arn = f"arn:aws:secretsmanager:{environ['CDK_DEFAULT_REGION']}:{environ['CDK_DEFAULT_ACCOUNT']}:secret:{name}/hec_token-xNUhIZ"

hec_endpoint = "https://http-inputs-firehose-myhost.splunkcloud.com:443"

main_stack = main(
    app,
    name,
    stack_name=f"{name}-Stack",
    name=name,
    env=Environment(
        account=environ["CDK_DEFAULT_ACCOUNT"],
        region=environ["CDK_DEFAULT_REGION"],
    ),
    hec_endpoint=hec_endpoint,
    hec_token_secrets_arn=hec_token_secrets_arn,
)


app.synth()
