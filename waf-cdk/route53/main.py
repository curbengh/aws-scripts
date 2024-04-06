"""
Create Sample-DNS-Zone-Stack
"""

from aws_cdk import CfnOutput, Fn, Stack
from aws_cdk import aws_route53 as route53
from constructs import Construct


class main(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:

        stack_name = kwargs["stack_name"]
        domain = kwargs["domain"]

        super().__init__(scope, construct_id, stack_name=stack_name)

        hosted_zone = route53.PublicHostedZone(
            self, f"{domain}-HostedZone", zone_name=domain
        )

        CfnOutput(
            self,
            f"{domain}-NameServers",
            value=Fn.join(" ", hosted_zone.hosted_zone_name_servers),
        )
