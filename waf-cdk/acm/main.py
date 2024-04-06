"""
Create Sample-Cert-Stack
"""

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_route53 as route53
from constructs import Construct


class main(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:

        env = kwargs["env"]
        stack_name = kwargs["stack_name"]
        domain = kwargs["domain"]

        super().__init__(scope, construct_id, stack_name=stack_name, env=env)

        hosted_zone = route53.PublicHostedZone.from_lookup(
            self, f"{domain}-HostedZone", domain_name=domain
        )

        cert = acm.Certificate(
            self,
            f"{domain}-Certificate",
            domain_name=domain,
            validation=acm.CertificateValidation.from_dns(hosted_zone),
        )

        CfnOutput(
            self,
            f"{domain}-ARN",
            value=cert.certificate_arn,
        )
