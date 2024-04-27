"""
Create Sample-Cloudfront-WAF-Stack
"""

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as targets
from aws_cdk import aws_wafv2 as waf
from constructs import Construct


def create_waf(self, name: str, ip_allowlist: list[str]) -> waf.CfnWebACL:
    ip_set = waf.CfnIPSet(
        self,
        f"{name}-IPSet",
        addresses=ip_allowlist,
        ip_address_version="IPV4",
        scope="CLOUDFRONT",
        name=f"{name}-IPSet",
        description="IP Allowlist",
    )

    ip_set_reference_statement = waf.CfnWebACL.IPSetReferenceStatementProperty(
        arn=ip_set.attr_arn
    )

    web_acl = waf.CfnWebACL(
        self,
        f"{name}-WebACL",
        default_action=waf.CfnWebACL.DefaultActionProperty(allow={}),
        scope="CLOUDFRONT",
        visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
            cloud_watch_metrics_enabled=True,
            metric_name=f"{name}-WebACL",
            sampled_requests_enabled=True,
        ),
        rules=[
            waf.CfnWebACL.RuleProperty(
                name=f"{name}-IP-Allowlist",
                priority=100,
                action=waf.CfnWebACL.RuleActionProperty(block={}),
                visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name=f"{name}-IP-Allowlist",
                ),
                statement=waf.CfnWebACL.StatementProperty(
                    not_statement=waf.CfnWebACL.NotStatementProperty(
                        statement=waf.CfnWebACL.StatementProperty(
                            ip_set_reference_statement=ip_set_reference_statement
                        )
                    )
                ),
            ),
            waf.CfnWebACL.RuleProperty(
                name="AWS-AWSManagedRulesCommonRuleSet",
                priority=200,
                statement=waf.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS", name="AWSManagedRulesCommonRuleSet"
                    )
                ),
                override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
                visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name=f"{name}-AWSManagedRulesCommonRuleSet",
                ),
            ),
        ],
    )
    return web_acl


def create_cf_dist(
    self,
    name: str,
    domain: str,
    origin: str,
    cf_headers: list[str],
    cert: acm.ICertificate,
    country_allowlist: list[str],
    waf_arn: str,
) -> cloudfront.IDistribution:
    cf_dist = cloudfront.Distribution(
        self,
        f"{name}-CfDist",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin(origin),
            allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            origin_request_policy=cloudfront.OriginRequestPolicy(
                self,
                f"{name}-CfOrigReqPolicy",
                header_behavior=cloudfront.OriginRequestHeaderBehavior.all(*cf_headers),
                query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.all(),
            ),
        ),
        domain_names=[domain],
        certificate=cert,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
        geo_restriction=cloudfront.GeoRestriction.allowlist(*country_allowlist),
        web_acl_id=waf_arn,
    )
    return cf_dist


class main(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:

        env = kwargs["env"]
        stack_name = kwargs["stack_name"]
        name = kwargs["name"]
        domain = kwargs["domain"]
        origin = kwargs["origin"]
        cert_arn = kwargs["cert_arn"]
        ip_allowlist = kwargs["ip_allowlist"]
        cf_headers = kwargs["cf_headers"]
        country_allowlist = kwargs["country_allowlist"]

        super().__init__(scope, construct_id, stack_name=stack_name, env=env)

        cert = acm.Certificate.from_certificate_arn(self, f"{name}-Cert", cert_arn)
        waf = create_waf(self, name, ip_allowlist)
        cf_dist = create_cf_dist(
            self,
            name,
            domain,
            origin,
            cf_headers,
            cert,
            country_allowlist,
            waf.attr_arn,
        )

        hosted_zone = route53.PublicHostedZone.from_lookup(
            self, f"{name}-HostedZone", domain_name=domain
        )
        route53.ARecord(
            self,
            f"{name}-ARecord",
            zone=hosted_zone,
            target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(cf_dist)),
        )

        CfnOutput(
            self,
            "CloudFront-Domain",
            value=f"{domain} alias of {cf_dist.domain_name}",
        )
