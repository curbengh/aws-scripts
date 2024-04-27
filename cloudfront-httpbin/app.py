#!/usr/bin/env python

"""
Synthesise CloudFront-httpbin-Stack into a CloudFormation template
"""


import aws_cdk as cdk
from main import main

app = cdk.App()
name = "CloudFront-httpbin"
origin = "httpbin.org"
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html
cf_headers = [
    "CloudFront-Viewer-Address",
    "CloudFront-Viewer-Country",
    "CloudFront-Viewer-TLS",
]
main(
    app,
    name,
    stack_name=f"{name}-Stack",
    name=name,
    origin=origin,
    cf_headers=cf_headers,
)

app.synth()
