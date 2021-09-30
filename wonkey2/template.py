import datetime
import hashlib
import inspect
import json

import packmodule
from awacs import acm, cloudformation, logs, route53, s3, sns, sqs, sts
from awacs.aws import Allow, Deny, PolicyDocument, Principal, Statement as _Statement
from troposphere import (
    AccountId,
    And,
    Condition,
    Equals,
    FindInMap,
    GetAtt,
    If,
    Join,
    Not,
    NoValue,
    Or,
    Output,
    Parameter,
    Partition,
    Ref,
    Region,
    Select,
    StackName,
    Tags,
    Template,
)
from troposphere.awslambda import (
    Code,
    DeadLetterConfig,
    Environment,
    Function,
    Permission,
    Version,
)
from troposphere.certificatemanager import Certificate
from troposphere.cloudformation import (
    DeploymentTargets,
    OperationPreferences as _OperationPreferences,
    Parameter as StackSetParameter,
    StackInstances,
    StackSet,
    WaitConditionHandle,
)
from troposphere.cloudfront import (
    CacheCookiesConfig,
    CacheHeadersConfig,
    CachePolicy,
    CachePolicyConfig,
    CacheQueryStringsConfig,
    CloudFrontOriginAccessIdentity,
    CloudFrontOriginAccessIdentityConfig,
    DefaultCacheBehavior,
    Distribution,
    DistributionConfig,
    LambdaFunctionAssociation,
    Origin,
    OriginCustomHeader,
    OriginRequestCookiesConfig,
    OriginRequestHeadersConfig,
    OriginRequestPolicy,
    OriginRequestPolicyConfig,
    OriginRequestQueryStringsConfig,
    ParametersInCacheKeyAndForwardedToOrigin,
    S3OriginConfig,
    ViewerCertificate,
)
from troposphere.events import Rule, Target
from troposphere.iam import PolicyProperty, PolicyType, Role
from troposphere.logs import LogGroup
from troposphere.route53 import AliasTarget, RecordSet, RecordSetGroup
from troposphere.s3 import (
    Bucket,
    BucketEncryption,
    BucketPolicy,
    LifecycleConfiguration,
    LifecycleRule,
    LifecycleRuleTransition,
    OwnershipControls,
    OwnershipControlsRule,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.sqs import Queue

from . import certificate_validator, edge_function as edge_function_code


CLOUDWATCH_LOGS_RETENTION_OPTIONS = [
    1,
    3,
    5,
    7,
    14,
    30,
    60,
    90,
    120,
    150,
    180,
    365,
    400,
    545,
    731,
    1827,
    3653,
]


class OperationPreferences(_OperationPreferences):
    props = {**_OperationPreferences.props, "RegionConcurrencyType": (str, False)}


class Statement(_Statement):
    props = {**_Statement.props, "Effect": (str, True)}


def add_condition(template, name, condition):
    template.add_condition(name, condition)
    return name


def add_mapping(template, name, mapping):
    template.add_mapping(name, mapping)
    return name


def create_log_group_template():
    template = Template(Description="Child stack to maintain Lambda@Edge log groups")

    log_group_name = template.add_parameter(Parameter("LogGroupName", Type="String"))
    log_retention_days = template.add_parameter(
        Parameter(
            "LogRetentionDays",
            Type="Number",
            Description=" ".join(
                (
                    "Days to keep Lambda@Edge logs.",
                    f"Allowed values are 0, {', '.join((str(x) for x in CLOUDWATCH_LOGS_RETENTION_OPTIONS))}.",
                    "0 means indefinite retention.",
                )
            ),
            AllowedValues=[0] + CLOUDWATCH_LOGS_RETENTION_OPTIONS,
        )
    )

    log_retention_defined = add_condition(
        template, "LogRetentionDefined", Not(Equals(Ref(log_retention_days), 0))
    )

    template.add_resource(
        LogGroup(
            "EdgeLambdaLogGroup",
            LogGroupName=Ref(log_group_name),
            RetentionInDays=If(log_retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    return template


def create_template(*, allow_debug_logging: bool = True):
    template = Template(Description="Quick file storage and sharing with ShareX.")

    # not actually using any features of this transform, but it's required to upload to SAR
    template.set_transform("AWS::Serverless-2016-10-31")

    partition_config = add_mapping(
        template,
        "PartitionConfig",
        {
            "aws": {
                # the region with the control plane for CloudFront, IAM, Route 53, etc
                "PrimaryRegion": "us-east-1",
                # assume that Lambda@Edge replicates to all default enabled regions, and that
                # future regions will be opt-in. generated with AWS CLI:
                # aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus=='opt-in-not-required'].RegionName|sort(@)"
                "DefaultRegions": [
                    "ap-northeast-1",
                    "ap-northeast-2",
                    "ap-northeast-3",
                    "ap-south-1",
                    "ap-southeast-1",
                    "ap-southeast-2",
                    "ca-central-1",
                    "eu-central-1",
                    "eu-north-1",
                    "eu-west-1",
                    "eu-west-2",
                    "eu-west-3",
                    "sa-east-1",
                    "us-east-1",
                    "us-east-2",
                    "us-west-1",
                    "us-west-2",
                ],
                "CloudFrontHostedZoneId": "Z2FDTNDATAQYW2",
            },
            # this doesn't actually work, because Lambda@Edge isn't supported in aws-cn
            "aws-cn": {
                "PrimaryRegion": "cn-north-1",
                "DefaultRegions": ["cn-north-1", "cn-northwest-1"],
                "CloudFrontHostedZoneId": "Z3RFFRIM2A3IF5",
            },
        },
    )

    upload_password = template.add_parameter(
        Parameter(
            "UploadPassword",
            Description="Password required to upload to the server. (Optional)",
            Type="String",
            NoEcho=True,
            Default="",
        )
    )

    root_redirect_url = template.add_parameter(
        Parameter(
            "RootRedirectUrl",
            Description="Redirect to this URL when server root is requested. (Optional)",
            Type="String",
            Default="",
        )
    )

    dns_name = template.add_parameter(
        Parameter(
            "DomainName",
            Description=" ".join(
                (
                    "Custom domain name for serving content."
                    "At least one of HostedZoneId or AcmCertificateArn must also be provided.",
                    "(Optional)",
                )
            ),
            Type="String",
            AllowedPattern="([a-z0-9.-]+|)",
            Default="",
        )
    )

    hosted_zone_id = template.add_parameter(
        Parameter(
            "HostedZoneId",
            Description=" ".join(
                (
                    "Existing Route 53 hosted zone ID.",
                    "Must be authoritative for the domain configured in DomainName.",
                    "Used to validate new TLS certificates (if AcmCertificateArn is unset)",
                    "and to create records pointing at your new host (if CreateDnsRecords is 'Yes').",
                    "(Optional)",
                )
            ),
            Type="String",
            AllowedPattern="(Z[A-Z0-9]+|)",
            Default="",
        )
    )

    acm_certificate_arn = template.add_parameter(
        Parameter(
            "AcmCertificateArn",
            Description="Existing ACM certificate ARN to use for serving TLS. (Optional)",
            Type="String",
            AllowedPattern="(arn:[^:]+:acm:[^:]+:[^:]+:certificate/.+|)",
            Default="",
        )
    )

    create_dns_records = template.add_parameter(
        Parameter(
            "CreateDnsRecords",
            Description=" ".join(
                (
                    "Create DNS records (A/AAAA) in Route 53 automatically.",
                    "Only applies if HostedZoneId is set.",
                )
            ),
            Type="String",
            AllowedValues=["Yes", "No"],
            Default="Yes",
        )
    )

    content_retention_days = template.add_parameter(
        Parameter(
            "ContentRetentionDays",
            Description="Days to keep uploaded content. 0 means indefinite retention.",
            Type="Number",
            MinValue=0,
            Default=365,
        )
    )

    log_retention_days = template.add_parameter(
        Parameter(
            "LogRetentionDays",
            Description=" ".join(
                (
                    "Days to keep service logs.",
                    "This also affects Lambda@Edge log retention if EnableDebugLogging is 'Yes'.",
                    f"Allowed values are 0, {', '.join((str(x) for x in CLOUDWATCH_LOGS_RETENTION_OPTIONS))}.",
                    "0 means indefinite retention.",
                )
            ),
            Type="Number",
            AllowedValues=[0] + CLOUDWATCH_LOGS_RETENTION_OPTIONS,
            Default=3,
        )
    )

    python_runtime_version = template.add_parameter(
        Parameter(
            "PythonRuntimeVersion",
            Description=" ".join(
                (
                    "Lambda runtime, must be compatible with Lambda@Edge.",
                    "See https://amzn.to/3aPd9Hh for details.",
                )
            ),
            Type="String",
            Default="python3.9",
        )
    )

    tls_protocol_version = template.add_parameter(
        Parameter(
            "TlsProtocolVersion",
            Description=" ".join(
                (
                    "CloudFront TLS security policy.",
                    "See https://amzn.to/2DR91Xq for details.",
                )
            ),
            Type="String",
            Default="TLSv1.2_2019",
        )
    )

    if allow_debug_logging:
        enable_debug_logging = template.add_parameter(
            Parameter(
                "EnableDebugLogging",
                Description=" ".join(
                    (
                        "Allow Lambda@Edge to write debug logs to CloudWatch.",
                        "Logged data will include SSE-C content encryption keys.",
                    )
                ),
                Type="String",
                AllowedValues=["Yes", "No"],
                Default="No",
            )
        )

    template.set_metadata(
        {
            "AWS::CloudFormation::Interface": {
                "ParameterGroups": [
                    {
                        "Label": {"default": "Server behavior"},
                        "Parameters": [upload_password.title, root_redirect_url.title],
                    },
                    {
                        "Label": {"default": "Data retention"},
                        "Parameters": [
                            content_retention_days.title,
                            log_retention_days.title,
                        ],
                    },
                    {
                        "Label": {"default": "Custom domain"},
                        "Parameters": [
                            dns_name.title,
                            hosted_zone_id.title,
                            acm_certificate_arn.title,
                            create_dns_records.title,
                        ],
                    },
                ],
            },
        }
    )

    # if a parameter is only used in one resource definition, SAR's interface tries to group
    # parameters under that resource's logical ID. while I'd rather have the interface defined
    # above, a strictly alphabetical list is preferable to arbitrary groupings. therefore,
    # we'll make at least two resources "depend" on every parameter to break their grouping logic.
    # this Select construct doesn't change the input value, but it does force a dependency on
    # every other element in the list - in this case, every defined template parameter.
    depend_on_all_params = lambda value: Select(
        0,
        [value] + [Ref(param) for param in sorted(template.parameters.keys())],
    )

    content_retention_defined = add_condition(
        template, "ContentRetentionDefined", Not(Equals(Ref(content_retention_days), 0))
    )

    log_retention_defined = add_condition(
        template, "LogRetentionDefined", Not(Equals(Ref(log_retention_days), 0))
    )

    using_acm_certificate = add_condition(
        template, "UsingAcmCertificate", Not(Equals(Ref(acm_certificate_arn), ""))
    )

    using_hosted_zone = add_condition(
        template, "UsingHostedZone", Not(Equals(Ref(hosted_zone_id), ""))
    )

    using_certificate = add_condition(
        template,
        "UsingCertificate",
        Or(Condition(using_acm_certificate), Condition(using_hosted_zone)),
    )

    should_create_certificate = add_condition(
        template,
        "ShouldCreateCertificate",
        And(Condition(using_hosted_zone), Not(Condition(using_acm_certificate))),
    )

    using_dns_name = add_condition(
        template, "UsingDnsName", Not(Equals(Ref(dns_name), ""))
    )

    should_create_dns_records = add_condition(
        template,
        "ShouldCreateDnsRecords",
        And(
            Condition(using_hosted_zone),
            Equals(Ref(create_dns_records), "Yes"),
        ),
    )

    if allow_debug_logging:
        should_enable_debug_logging = add_condition(
            template,
            "ShouldEnableDebugLogging",
            Equals(Ref(enable_debug_logging), "Yes"),
        )

    is_primary_region = add_condition(
        template,
        "IsPrimaryRegion",
        Equals(Region, FindInMap(partition_config, Partition, "PrimaryRegion")),
    )

    precondition_region_is_primary = template.add_resource(
        WaitConditionHandle(
            "PreconditionIsPrimaryRegionForPartition",
            Condition=is_primary_region,
        )
    )

    bucket = template.add_resource(
        Bucket(
            "ContentBucket",
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    LifecycleRule(
                        Transitions=[
                            LifecycleRuleTransition(
                                StorageClass="INTELLIGENT_TIERING",
                                TransitionInDays=1,
                            ),
                        ],
                        Status="Enabled",
                    ),
                    If(
                        content_retention_defined,
                        LifecycleRule(
                            ExpirationInDays=Ref(content_retention_days),
                            Status="Enabled",
                        ),
                        NoValue,
                    ),
                ],
            ),
            BucketEncryption=BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                            # Origin Access Identities can't use KMS
                            SSEAlgorithm="AES256"
                        )
                    )
                ]
            ),
            OwnershipControls=OwnershipControls(
                Rules=[OwnershipControlsRule(ObjectOwnership="BucketOwnerPreferred")],
            ),
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
        )
    )

    origin_access_identity = template.add_resource(
        CloudFrontOriginAccessIdentity(
            "CloudFrontIdentity",
            CloudFrontOriginAccessIdentityConfig=CloudFrontOriginAccessIdentityConfig(
                Comment=depend_on_all_params(GetAtt(bucket, "Arn")),
            ),
        )
    )

    bucket_policy = template.add_resource(
        BucketPolicy(
            "ContentBucketPolicy",
            Bucket=depend_on_all_params(Ref(bucket)),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal(
                            "CanonicalUser",
                            GetAtt(origin_access_identity, "S3CanonicalUserId"),
                        ),
                        Action=[s3.GetObject, s3.PutObject],
                        Resource=[Join("", [GetAtt(bucket, "Arn"), "/*"])],
                    ),
                ],
            ),
        )
    )

    certificate_validator_dlq = template.add_resource(
        Queue(
            "CertificateValidatorDLQ",
            MessageRetentionPeriod=int(datetime.timedelta(days=14).total_seconds()),
            KmsMasterKeyId="alias/aws/sqs",
            Condition=should_create_certificate,
        )
    )

    certificate_validator_role = template.add_resource(
        Role(
            "CertificateValidatorRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
            Policies=[
                PolicyProperty(
                    PolicyName="DLQPolicy",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[sqs.SendMessage],
                                Resource=[GetAtt(certificate_validator_dlq, "Arn")],
                            )
                        ],
                    ),
                ),
                PolicyProperty(
                    PolicyName="CertificateValidatorPermissions",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    route53.ChangeResourceRecordSets,
                                ],
                                Resource=[
                                    Join(
                                        ":",
                                        [
                                            "arn",
                                            Partition,
                                            "route53",
                                            "",
                                            "",
                                            Join(
                                                "/", ["hostedzone", Ref(hosted_zone_id)]
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    acm.DescribeCertificate,
                                ],
                                Resource=[
                                    Join(
                                        ":",
                                        [
                                            "arn",
                                            Partition,
                                            "acm",
                                            Region,
                                            AccountId,
                                            "certificate/*",
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ),
            ],
            Condition=should_create_certificate,
        )
    )

    certificate_validator_function = template.add_resource(
        Function(
            "CertificateValidatorFunction",
            Runtime=Ref(python_runtime_version),
            Handler="index.{}".format(certificate_validator.handler.__name__),
            Code=Code(ZipFile=inspect.getsource(certificate_validator)),
            MemorySize=256,
            Timeout=300,
            Role=GetAtt(certificate_validator_role, "Arn"),
            DeadLetterConfig=DeadLetterConfig(
                TargetArn=GetAtt(certificate_validator_dlq, "Arn")
            ),
            Environment=Environment(
                Variables={
                    certificate_validator.EnvVars.HOSTED_ZONE_ID.name: Ref(
                        hosted_zone_id
                    )
                }
            ),
            Condition=should_create_certificate,
        )
    )

    certificate_validator_log_group = template.add_resource(
        LogGroup(
            "CertificateValidatorLogGroup",
            LogGroupName=Join(
                "", ["/aws/lambda/", Ref(certificate_validator_function)]
            ),
            RetentionInDays=If(log_retention_defined, Ref(log_retention_days), NoValue),
            Condition=should_create_certificate,
        )
    )

    certificate_validator_role_policy = template.add_resource(
        PolicyType(
            "CertificateValidatorRoleLogWritePolicy",
            PolicyName="write-logs",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[
                            GetAtt(certificate_validator_log_group, "Arn"),
                        ],
                    ),
                ],
            ),
            Roles=[Ref(certificate_validator_role)],
            Condition=should_create_certificate,
        )
    )

    certificate_validator_rule = template.add_resource(
        Rule(
            "CertificateValidatorRule",
            EventPattern={
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["acm.amazonaws.com"],
                    "eventName": ["AddTagsToCertificate"],
                    "requestParameters": {
                        "tags": {
                            "key": [certificate_validator_function.title],
                            "value": [GetAtt(certificate_validator_function, "Arn")],
                        }
                    },
                },
            },
            Targets=[
                Target(
                    Id="certificate-validator-lambda",
                    Arn=GetAtt(certificate_validator_function, "Arn"),
                )
            ],
            DependsOn=[
                certificate_validator_log_group,
                certificate_validator_role_policy,
            ],
            Condition=should_create_certificate,
        )
    )

    certificate_validator_permission = template.add_resource(
        Permission(
            "CertificateValidatorPermission",
            FunctionName=GetAtt(certificate_validator_function, "Arn"),
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=GetAtt(certificate_validator_rule, "Arn"),
            Condition=should_create_certificate,
        )
    )

    certificate = template.add_resource(
        Certificate(
            "Certificate",
            DomainName=Ref(dns_name),
            SubjectAlternativeNames=[Ref(dns_name)],
            ValidationMethod="DNS",
            Tags=Tags(
                **{
                    certificate_validator_function.title: GetAtt(
                        certificate_validator_function, "Arn"
                    )
                }
            ),
            DependsOn=[certificate_validator_permission],
            Condition=should_create_certificate,
        )
    )

    edge_function_role = template.add_resource(
        Role(
            "EdgeFunctionRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal(
                            "Service",
                            ["lambda.amazonaws.com", "edgelambda.amazonaws.com"],
                        ),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
        )
    )

    edge_function = template.add_resource(
        Function(
            "EdgeFunction",
            Runtime=Ref(python_runtime_version),
            Handler="index.handler",
            Code=Code(ZipFile=packmodule.pack(inspect.getsource(edge_function_code))),
            MemorySize=128,
            Timeout=3,
            Role=GetAtt(edge_function_role, "Arn"),
        )
    )

    edge_function_hash = (
        hashlib.sha256(
            json.dumps(edge_function.to_dict(), sort_keys=True).encode("utf-8")
        )
        .hexdigest()[:10]
        .upper()
    )

    edge_function_version = template.add_resource(
        Version(
            "EdgeFunctionVersion" + edge_function_hash,
            FunctionName=GetAtt(edge_function, "Arn"),
        )
    )

    replica_log_group_name = Join(
        "/",
        [
            "/aws/lambda",
            Join(
                ".",
                [
                    FindInMap(partition_config, Partition, "PrimaryRegion"),
                    Ref(edge_function),
                ],
            ),
        ],
    )

    if allow_debug_logging:
        edge_function_role_policy = template.add_resource(
            PolicyType(
                "EdgeFunctionRolePolicy",
                PolicyName="write-debug-logs",
                PolicyDocument=PolicyDocument(
                    Version="2012-10-17",
                    Statement=[
                        Statement(
                            Effect=If(should_enable_debug_logging, Allow, Deny),
                            Action=[logs.CreateLogStream, logs.PutLogEvents],
                            Resource=[
                                Join(
                                    ":",
                                    [
                                        "arn",
                                        Partition,
                                        "logs",
                                        "*",
                                        AccountId,
                                        "log-group",
                                        replica_log_group_name,
                                        "log-stream",
                                        "*",
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
                Roles=[Ref(edge_function_role)],
            )
        )

        stack_set_administration_role = template.add_resource(
            Role(
                "StackSetAdministrationRole",
                AssumeRolePolicyDocument=PolicyDocument(
                    Version="2012-10-17",
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Principal=Principal(
                                "Service", "cloudformation.amazonaws.com"
                            ),
                            Action=[sts.AssumeRole],
                        ),
                    ],
                ),
            )
        )

        stack_set_execution_role = template.add_resource(
            Role(
                "StackSetExecutionRole",
                AssumeRolePolicyDocument=PolicyDocument(
                    Version="2012-10-17",
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Principal=Principal(
                                "AWS", GetAtt(stack_set_administration_role, "Arn")
                            ),
                            Action=[sts.AssumeRole],
                        ),
                    ],
                ),
                Policies=[
                    PolicyProperty(
                        PolicyName="create-stackset-instances",
                        PolicyDocument=PolicyDocument(
                            Version="2012-10-17",
                            Statement=[
                                Statement(
                                    Effect=Allow,
                                    Action=[
                                        cloudformation.DescribeStacks,
                                        logs.DescribeLogGroups,
                                        logs.CreateLogGroup,
                                        logs.DeleteLogGroup,
                                        logs.PutRetentionPolicy,
                                        logs.DeleteRetentionPolicy,
                                    ],
                                    Resource=["*"],
                                ),
                                # stack instances communicate with the CFN service via SNS
                                Statement(
                                    Effect=Allow,
                                    Action=[sns.Publish],
                                    NotResource=[
                                        Join(
                                            ":",
                                            [
                                                "arn",
                                                Partition,
                                                "sns",
                                                "*",
                                                AccountId,
                                                "*",
                                            ],
                                        )
                                    ],
                                ),
                                Statement(
                                    Effect=Allow,
                                    Action=[
                                        cloudformation.CreateStack,
                                        cloudformation.DeleteStack,
                                        cloudformation.UpdateStack,
                                    ],
                                    Resource=[
                                        Join(
                                            ":",
                                            [
                                                "arn",
                                                Partition,
                                                "cloudformation",
                                                "*",
                                                AccountId,
                                                Join(
                                                    "/",
                                                    [
                                                        "stack",
                                                        Join(
                                                            "-",
                                                            [
                                                                "StackSet",
                                                                StackName,
                                                                "*",
                                                            ],
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        )
                                    ],
                                ),
                            ],
                        ),
                    ),
                ],
            )
        )

        stack_set_administration_role_policy = template.add_resource(
            PolicyType(
                "StackSetAdministrationRolePolicy",
                PolicyName="assume-execution-role",
                PolicyDocument=PolicyDocument(
                    Version="2012-10-17",
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[sts.AssumeRole],
                            Resource=[GetAtt(stack_set_execution_role, "Arn")],
                        ),
                    ],
                ),
                Roles=[Ref(stack_set_administration_role)],
            )
        )

        edge_log_groups = template.add_resource(
            StackSet(
                "EdgeLambdaLogGroupStackSet",
                AdministrationRoleARN=GetAtt(stack_set_administration_role, "Arn"),
                ExecutionRoleName=Ref(stack_set_execution_role),
                StackSetName=Join("-", [StackName, "EdgeLambdaLogGroup"]),
                PermissionModel="SELF_MANAGED",
                Description="Multi-region log groups for Lambda@Edge replicas",
                Parameters=[
                    StackSetParameter(
                        ParameterKey="LogGroupName",
                        ParameterValue=replica_log_group_name,
                    ),
                    StackSetParameter(
                        ParameterKey="LogRetentionDays",
                        ParameterValue=Ref(log_retention_days),
                    ),
                ],
                OperationPreferences=OperationPreferences(
                    FailureToleranceCount=0,
                    MaxConcurrentPercentage=100,
                    RegionConcurrencyType="PARALLEL",
                ),
                StackInstancesGroup=[
                    StackInstances(
                        DeploymentTargets=DeploymentTargets(Accounts=[AccountId]),
                        Regions=FindInMap(
                            partition_config, Partition, "DefaultRegions"
                        ),
                    )
                ],
                TemplateBody=create_log_group_template().to_json(indent=None),
                DependsOn=[
                    stack_set_administration_role_policy,
                    edge_function_role_policy,
                ],
            )
        )

    cache_policy = template.add_resource(
        CachePolicy(
            "CachePolicy",
            CachePolicyConfig=CachePolicyConfig(
                Name=Join("-", [StackName, "CachePolicy"]),
                DefaultTTL=0,
                MaxTTL=0,
                MinTTL=0,
                ParametersInCacheKeyAndForwardedToOrigin=ParametersInCacheKeyAndForwardedToOrigin(
                    CookiesConfig=CacheCookiesConfig(
                        CookieBehavior="none",
                    ),
                    HeadersConfig=CacheHeadersConfig(
                        HeaderBehavior="none",
                    ),
                    QueryStringsConfig=CacheQueryStringsConfig(
                        QueryStringBehavior="none",
                    ),
                    EnableAcceptEncodingBrotli=False,
                    EnableAcceptEncodingGzip=False,
                ),
            ),
        )
    )

    origin_request_policy = template.add_resource(
        OriginRequestPolicy(
            "OriginRequestPolicy",
            OriginRequestPolicyConfig=OriginRequestPolicyConfig(
                Name=Join("-", [StackName, "OriginRequestPolicy"]),
                CookiesConfig=OriginRequestCookiesConfig(
                    CookieBehavior="none",
                ),
                HeadersConfig=OriginRequestHeadersConfig(
                    HeaderBehavior="whitelist",
                    Headers=["x-wonkey-password"],
                ),
                QueryStringsConfig=OriginRequestQueryStringsConfig(
                    QueryStringBehavior="none",
                ),
            ),
        )
    )

    distribution = template.add_resource(
        Distribution(
            "ContentDistribution",
            DistributionConfig=DistributionConfig(
                Enabled=True,
                Aliases=If(using_dns_name, [Ref(dns_name)], NoValue),
                Origins=[
                    Origin(
                        Id="default",
                        DomainName=GetAtt(bucket, "DomainName"),
                        S3OriginConfig=S3OriginConfig(
                            OriginAccessIdentity=Join(
                                "",
                                [
                                    "origin-access-identity/cloudfront/",
                                    Ref(origin_access_identity),
                                ],
                            )
                        ),
                        OriginCustomHeaders=[
                            OriginCustomHeader(
                                HeaderName="x-wonkey-upload-password",
                                HeaderValue=Ref(upload_password),
                            ),
                            OriginCustomHeader(
                                HeaderName="x-wonkey-root-redirect-url",
                                HeaderValue=Ref(root_redirect_url),
                            ),
                            OriginCustomHeader(
                                HeaderName="x-wonkey-domain-name",
                                HeaderValue=If(using_dns_name, Ref(dns_name), ""),
                            ),
                        ],
                    )
                ],
                DefaultCacheBehavior=DefaultCacheBehavior(
                    TargetOriginId="default",
                    AllowedMethods=[
                        "GET",
                        "HEAD",
                        "OPTIONS",
                        "PUT",
                        "PATCH",
                        "POST",
                        "DELETE",
                    ],
                    CachePolicyId=Ref(cache_policy),
                    OriginRequestPolicyId=Ref(origin_request_policy),
                    ViewerProtocolPolicy="redirect-to-https",
                    LambdaFunctionAssociations=[
                        LambdaFunctionAssociation(
                            EventType="origin-request",
                            LambdaFunctionARN=Ref(edge_function_version),
                        ),
                        LambdaFunctionAssociation(
                            EventType="origin-response",
                            LambdaFunctionARN=Ref(edge_function_version),
                        ),
                    ],
                ),
                HttpVersion="http2",
                IPV6Enabled=True,
                ViewerCertificate=ViewerCertificate(
                    AcmCertificateArn=If(
                        using_acm_certificate,
                        Ref(acm_certificate_arn),
                        If(using_hosted_zone, Ref(certificate), NoValue),
                    ),
                    SslSupportMethod=If(using_certificate, "sni-only", NoValue),
                    CloudFrontDefaultCertificate=If(using_certificate, NoValue, True),
                    MinimumProtocolVersion=Ref(tls_protocol_version),
                ),
                PriceClass="PriceClass_All",
            ),
            DependsOn=[
                bucket_policy,
                precondition_region_is_primary,
            ]
            + ([edge_log_groups] if allow_debug_logging else []),
        )
    )

    template.add_resource(
        RecordSetGroup(
            "RecordSetGroup",
            HostedZoneId=Ref(hosted_zone_id),
            RecordSets=[
                RecordSet(
                    Name=Ref(dns_name),
                    Type=record_type,
                    AliasTarget=AliasTarget(
                        HostedZoneId=FindInMap(
                            partition_config, Partition, "CloudFrontHostedZoneId"
                        ),
                        DNSName=GetAtt(distribution, "DomainName"),
                        EvaluateTargetHealth=False,
                    ),
                )
                for record_type in ("A", "AAAA")
            ],
            Condition=should_create_dns_records,
        )
    )

    template.add_output(Output("DistributionId", Value=Ref(distribution)))

    template.add_output(
        Output("DistributionDomain", Value=GetAtt(distribution, "DomainName"))
    )

    template.add_output(
        Output(
            "DistributionUrl",
            Value=Join("", ["https://", GetAtt(distribution, "DomainName"), "/"]),
        )
    )

    template.add_output(Output("ContentBucketArn", Value=GetAtt(bucket, "Arn")))

    return template
