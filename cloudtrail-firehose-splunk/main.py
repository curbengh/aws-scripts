"""
Create Cloudtrail-Firehose-Splunk-Stack
"""

from os import environ

from aws_cdk import Duration, Stack
from aws_cdk import Environment as CdkEnvironment
from aws_cdk import aws_cloudtrail as cloudtrail
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kinesisfirehose as firehose
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secrets
from constructs import Construct


def create_firehose_inline_policy(self, name, firehose_bucket_arn: str) -> iam.IPolicy:
    return iam.Policy(
        self,
        f"{name}-Firehose-RolePolicy",
        statements=[
            iam.PolicyStatement(
                actions=[
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                effect=iam.Effect.ALLOW,
                resources=[
                    firehose_bucket_arn,
                    f"{firehose_bucket_arn}/*",
                ],
            )
        ],
    )


def create_firehose_role(self, name: str, bucket_arn: str) -> iam.IRole:
    bucket_name = bucket_arn.split(":")[-1]
    return iam.Role(
        self,
        f"{name}-Firehose-Role",
        description=f"R/W access to {bucket_name} bucket",
        assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        inline_policies={
            f"{name}-Firehose-RolePolicy": iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[bucket_arn, f"{bucket_arn}/*"],
                    )
                ]
            )
        },
    )


def create_firehose(
    self,
    name: str,
    hec_endpoint: str,
    hec_token: str,
    bucket_arn: str,
    s3_role_arn: str,
) -> firehose.CfnDeliveryStream:
    return firehose.CfnDeliveryStream(
        self,
        f"{name}-FirehoseStream",
        delivery_stream_name=f"aws-waf-logs-{name}-stream",
        delivery_stream_type="DirectPut",
        splunk_destination_configuration=firehose.CfnDeliveryStream.SplunkDestinationConfigurationProperty(
            # https://docs.splunk.com/Documentation/AddOns/released/AWS/ConfigureFirehose
            hec_endpoint=hec_endpoint,
            hec_endpoint_type="Raw",
            hec_token=hec_token,
            # log failed events to S3
            # TODO: https://www.splunk.com/en_us/blog/tips-and-tricks/aws-firehose-to-splunk-two-easy-ways-to-recover-those-failed-events.html
            s3_backup_mode="FailedEventsOnly",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket_arn, role_arn=s3_role_arn
            ),
        ),
    )


def create_trail(self, name: str, bucket: s3.IBucket) -> cloudtrail.Trail:
    return cloudtrail.Trail(
        self,
        f"{name}-Trail",
        bucket=bucket,
        enable_file_validation=True,
        is_multi_region_trail=True,
    )


def create_bucket(self, name: str) -> s3.IBucket:
    expiration = 365

    if name.endswith("Firehose"):
        expiration = 30

    return s3.Bucket(
        self,
        f"{name}-Bucket",
        enforce_ssl=True,
        minimum_tls_version=1.2,
        lifecycle_rules=[
            s3.LifecycleRule(
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(30),
                    )
                ],
                expiration=Duration.days(expiration),
            )
        ],
        versioned=True,
        object_lock_enabled=True,
        object_lock_default_retention=s3.ObjectLockRetention.governance(
            duration=Duration.days(expiration)
        ),
    )


class main(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env: CdkEnvironment,
        stack_name: str,
        name: str,
        hec_endpoint: str,
        hec_token_secrets_arn: str,
    ) -> None:

        super().__init__(scope, construct_id, stack_name=stack_name, env=env)

        firehose_bucket = create_bucket(self, f"{name}-Firehose")
        firehose_role = create_firehose_role(self, name, firehose_bucket.bucket_arn)
        hec_token = secrets.Secret.from_secret_complete_arn(
            self, f"{name}-HECToken", hec_token_secrets_arn
        ).secret_value.unsafe_unwrap()
        firehose_stream = create_firehose(
            self,
            name,
            hec_endpoint,
            hec_token,
            firehose_bucket.bucket_arn,
            firehose_role.role_arn,
        )

        trail_bucket = create_bucket(self, f"{name}-Trail")
        trail = create_trail(
            self,
            name,
            # bucket policy to allow cloudtrail is automatically created
            bucket=trail_bucket,
        )
        trail.on_event(
            self,
            f"{name}-EventBridge",
            target=targets.KinesisFirehoseStream(firehose_stream),
            description="Cloudtrail->EventBridge->Firehose",
        )

        # harden bucket policy
        # s3.IBucket.add_to_resource_policy() is not used to avoid circular dependency
        bucket_policy = s3.BucketPolicy(
            self, f"{name}-Trail-BucketPolicy", bucket=trail_bucket
        )
        # add_statements() replaces bucket policy in s3.Bucket()
        # so need to re-add them
        bucket_policy.document.add_statements(
            iam.PolicyStatement(
                actions=["s3:*"],
                conditions={
                    "Bool": {"aws:SecureTransport": "false"},
                },
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                resources=[trail_bucket.bucket_arn, f"{trail_bucket.bucket_arn}/*"],
            )
        )
        bucket_policy.document.add_statements(
            iam.PolicyStatement(
                actions=["s3:*"],
                conditions={
                    "NumericLessThan": {"s3:TlsVersion": "1.2"},
                },
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                resources=[trail_bucket.bucket_arn, f"{trail_bucket.bucket_arn}/*"],
            )
        )
        bucket_policy.document.add_statements(
            iam.PolicyStatement(
                actions=["s3:GetBucketAcl"],
                conditions={
                    "StringEquals": {"aws:SourceArn": trail.trail_arn},
                },
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                resources=[trail_bucket.bucket_arn],
            )
        )
        bucket_policy.document.add_statements(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                conditions={
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"},
                    # restrict bucket access to a specific trail
                    "ArnEquals": {"aws:SourceArn": trail.trail_arn},
                },
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                resources=[
                    f"{trail_bucket.bucket_arn}/AWSLogs/{environ['CDK_DEFAULT_ACCOUNT']}/*"
                ],
            )
        )
