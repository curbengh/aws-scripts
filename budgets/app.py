#!/usr/bin/env python

"""
Synthesise Billing-Alert-Stack into a CloudFormation template
"""


from aws_cdk import App
from main import main

app = App()
name = "Billing-Alert"
emails = [
    "engineer@example.com",
    "cloudmanager@example.com",
    "pm@example.com",
]
# notify when the cost exceeds this USD amount
budget_limit = 100

main_stack = main(
    app,
    name,
    stack_name=f"{name}-Stack",
    name=name,
    emails=emails,
    budget_limit=budget_limit,
)

app.synth()
