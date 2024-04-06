#!/usr/bin/env python

"""
Synthesise Sample-Cert-Stack into a CloudFormation template
"""

from os import environ

import aws_cdk as cdk
from main import main

app = cdk.App()
name = "Sample-Cert"
domain = "example.com"

main(
    app,
    name,
    stack_name=f"{name}-Stack",
    name=name,
    domain=domain,
    # env is required for route53.PublicHostedZone.from_lookup()
    # Cloudfront requires cert to be in us-east-1
    env=cdk.Environment(account=environ["CDK_DEFAULT_ACCOUNT"], region="us-east-1"),
)

app.synth()
