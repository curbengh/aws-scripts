#!/usr/bin/env python

"""
Synthesise Sample-DNS-Zone-Stack into a CloudFormation template
"""

import aws_cdk as cdk
from main import main

app = cdk.App()
name = "Sample-DNS-Zone"
domain = "example.com"

main(app, name, stack_name=f"{name}-Stack", name=name, domain=domain)

app.synth()
