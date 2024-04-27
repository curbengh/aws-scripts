"""
Create CloudFront-httpbin-Stack
"""

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from constructs import Construct


def create_cf_dist(
    self, name: str, origin: str, cf_headers: list[str]
) -> cloudfront.IDistribution:
    cf_dist = cloudfront.Distribution(
        self,
        f"{name}-CfDist",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin(origin),
            allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
            origin_request_policy=cloudfront.OriginRequestPolicy(
                self,
                f"{name}-CfOriReqPolicy",
                header_behavior=cloudfront.OriginRequestHeaderBehavior.all(*cf_headers),
                query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.all(),
            ),
        ),
    )
    return cf_dist


class main(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:

        stack_name = kwargs["stack_name"]
        name = kwargs["name"]
        origin = kwargs["origin"]
        cf_headers = kwargs["cf_headers"]

        super().__init__(scope, construct_id, stack_name=stack_name)

        cf_dist = create_cf_dist(self, name, origin, cf_headers)

        CfnOutput(
            self,
            "CloudFront-Domain",
            value=cf_dist.domain_name,
        )
