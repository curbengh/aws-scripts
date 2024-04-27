#!/usr/bin/env python

"""
Synthesise Sample-Cloudfront-WAF into a CloudFormation template
"""

from os import environ

import aws_cdk as cdk
from main import main

app = cdk.App()
name = "Sample-Cloudfront-WAF"
domain = "example.com"
origin = "origin.com"
# domain's cert
cert_arn = "arn:aws:acm:us-east-1:123456789012:certificate/uuid"
ip_allowlist = [
    "1.2.3.4/32",
    "5.6.7.8/32",
]
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html
cf_headers = [
    "CloudFront-Viewer-Address",
    "CloudFront-Viewer-Country",
    "CloudFront-Viewer-TLS",
]
country_allowlist = ["US"]

main(
    app,
    name,
    stack_name=f"{name}-Stack",
    name=name,
    domain=domain,
    origin=origin,
    cert_arn=cert_arn,
    ip_allowlist=ip_allowlist,
    cf_headers=cf_headers,
    country_allowlist=country_allowlist,
    # Cloudfront can be in any region,
    # but since it requires ACM and WAF to be in us-east-1,
    # it will be deployed there for simplicity
    # Cloudfront can use ACM in other region, but it's still experimental
    # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudfront/README.html#cross-region-certificates
    # env is required for route53.PublicHostedZone.from_lookup()
    env=cdk.Environment(account=environ["CDK_DEFAULT_ACCOUNT"], region="us-east-1"),
)

app.synth()
