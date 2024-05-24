#!/usr/bin/env python

"""
Synthesize a stack into a CloudFormation template
"""

from sys import exit as sys_exit

import aws_cdk as cdk
from log4shell import Log4Shell

app = cdk.App()
name = "Log4Shell"
key_name = app.node.try_get_context("key_name")
ip = app.node.try_get_context("ip")

if key_name is None or ip is None:
    sys_exit("cdk {synth|deploy} -c key_name=ssh-keypair-name -c ip=your-public-ip")

Log4Shell(
    app,
    name,
    stack_name=f"{name}Stack",
    name=name,
    key_name=key_name,
    ip=ip,
)

app.synth()
