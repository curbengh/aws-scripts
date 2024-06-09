"""
Create WAF-Firehose-Splunk-Stack
"""

from aws_cdk import CfnOutput, Stack
from aws_cdk import Environment as CdkEnvironment
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kinesisfirehose as firehose
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secrets
from aws_cdk import aws_wafv2 as waf
from constructs import Construct


def create_waf(self, name: str, firehose_arn: str) -> waf.CfnLoggingConfiguration:
    # example: ../waf-cdk/cloudfront-waf/main.py
    web_acl = waf.CfnWebACL()

    return waf.CfnLoggingConfiguration(
        self,
        f"{name}-WebACL-Logging",
        log_destination_configs=[firehose_arn],
        resource_arn=web_acl.attr_arn,
        redacted_fields=[
            waf.CfnLoggingConfiguration.FieldToMatchProperty(
                single_header={"Name": "X-API-Key"}
            )
        ],
    )


def create_bucket(self, name: str) -> s3.IBucket:
    return s3.Bucket(
        self,
        f"{name}-Bucket",
        enforce_ssl=True,
        minimum_tls_version=1.2,
        versioned=True,
        # Optional
        # lifecycle_rules=[
        #     s3.LifecycleRule(
        #         transitions=[
        #             s3.Transition(
        #                 storage_class=s3.StorageClass.INFREQUENT_ACCESS,
        #                 transition_after=Duration.days(30),
        #             )
        #         ],
        #         expiration=Duration.days(180),
        #     )
        # ],
        # object_lock_enabled=True,
        # object_lock_default_retention=s3.ObjectLockRetention.governance(
        #     duration=Duration.days(180)
        # ),
    )


def create_role(self, name: str, bucket_arn: str) -> iam.IRole:
    bucket_name = bucket_arn.split(":")[-1]
    return iam.Role(
        self,
        f"{name}-Role",
        description=f"Write access to {bucket_name} bucket",
        assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        inline_policies={
            f"{name}-RolePolicy": iam.PolicyDocument(
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
    firehose_role_arn: str,
) -> firehose.CfnDeliveryStream:
    return firehose.CfnDeliveryStream(
        self,
        f"{name}-Stream",
        delivery_stream_name=f"aws-waf-logs-{name}-stream",
        delivery_stream_type="DirectPut",
        splunk_destination_configuration=firehose.CfnDeliveryStream.SplunkDestinationConfigurationProperty(
            # https://docs.splunk.com/Documentation/AddOns/released/AWS/ConfigureFirehose
            hec_endpoint=hec_endpoint,
            hec_endpoint_type="Raw",
            hec_token=hec_token,
            # log failed events to S3
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-kinesisfirehose-deliverystream-splunkdestinationconfiguration.html#cfn-kinesisfirehose-deliverystream-splunkdestinationconfiguration-s3backupmode
            s3_backup_mode="FailedEventsOnly",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket_arn,
                role_arn=firehose_role_arn,
                # default and minimum
                # hec_acknowledgment_timeout_in_seconds=180,
            ),
            # https://www.splunk.com/en_us/blog/tips-and-tricks/aws-firehose-to-splunk-two-easy-ways-to-recover-those-failed-events.html
            # Recovering failed events may be desirable,
            # however if firehose fails to write to splunk even after 30 minutes retry,
            # trying to send the "splashback" contents probably will still fail
            retry_options=firehose.CfnDeliveryStream.SplunkRetryOptionsProperty(
                # default 300
                duration_in_seconds=1800
            ),
        ),
    )


class S3Stack(Stack):
    """Create bucket in a different region than Firehose's"""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env: CdkEnvironment,
        stack_name: str,
        name: str,
    ) -> None:

        super().__init__(scope, construct_id, stack_name=stack_name, env=env)

        bucket = create_bucket(self, name)

        CfnOutput(self, f"{name}-Bucket-ARN", value=bucket.bucket_arn)


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
        bucket_arn: str = "",
    ) -> None:

        super().__init__(scope, construct_id, stack_name=stack_name, env=env)

        # create bucket if S3Stack is not used
        if len(bucket_arn) == 0:
            bucket = create_bucket(self, name)
            bucket_arn = bucket.bucket_arn

        firehose_role = create_role(self, name, bucket_arn)
        hec_token = secrets.Secret.from_secret_complete_arn(
            self, f"{name}-HECToken", hec_token_secrets_arn
        ).secret_value.unsafe_unwrap()

        firehose_stream = create_firehose(
            self, name, hec_endpoint, hec_token, bucket_arn, firehose_role.role_arn
        )

        create_waf(self, name, firehose_stream.attr_arn)
