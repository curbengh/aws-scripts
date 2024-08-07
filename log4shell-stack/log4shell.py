"""
Main stack
Define AWS resources to be created
"""

from os import environ

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from constructs import Construct


def create_ssm_role(self, name: str) -> iam.IRole:
    """Create an IAM role with minimal SSM permissions"""
    role = iam.Role(
        self,
        f"{name}Role",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        ],
    )
    return role


def create_vpc(self, name: str) -> ec2.IVpc:
    """Create a VPC with 1 public subnets"""
    vpc = ec2.Vpc(
        self,
        f"{name}VPC",
        vpc_name=f"{name}VPC",
        cidr="192.168.1.0/24",
        subnet_configuration=[
            ec2.SubnetConfiguration(
                name=f"{name}PublicSubnet",
                subnet_type=ec2.SubnetType.PUBLIC,
                map_public_ip_on_launch=True,
            ),
        ],
        max_azs=1,
    )
    return vpc


def create_security_group(
    self, name: str, vpc: ec2.IVpc, your_ip: str
) -> ec2.ISecurityGroup:
    """Create a security group to allow SSH and DNS access"""
    security_group = ec2.SecurityGroup(
        self,
        f"{name}SecurityGroup",
        security_group_name=f"{name}SecurityGroup",
        vpc=vpc,
        description="Allow ssh, dns & http access",
        allow_all_outbound=True,
    )

    security_group.add_ingress_rule(security_group, ec2.Port.all_traffic())

    security_group.add_ingress_rule(ec2.Peer.ipv4(f"{your_ip}/32"), ec2.Port.tcp(22))
    security_group.add_ingress_rule(ec2.Peer.ipv4(f"{your_ip}/32"), ec2.Port.tcp(53))
    security_group.add_ingress_rule(ec2.Peer.ipv4(f"{your_ip}/32"), ec2.Port.udp(53))
    security_group.add_ingress_rule(ec2.Peer.ipv4(f"{your_ip}/32"), ec2.Port.tcp(80))

    return security_group


def create_dns_instance(
    self,
    name: str,
    vpc: ec2.IVpc,
    role: iam.IRole,
    security_group: ec2.ISecurityGroup,
    key_name: str,
) -> ec2.IInstance:
    """Create an instance with Unbound installed"""

    region = environ["CDK_DEFAULT_REGION"]
    commands = """\
apt update
ln -sf /dev/null /etc/systemd/system/unbound.service
apt install -y unbound

mkdir -p "/etc/unbound/unbound.conf.d/"
echo '# Based on https://www.linuxbabe.com/ubuntu/set-up-unbound-dns-resolver-on-ubuntu-20-04-server
server:
  directory: "/etc/unbound"
  username: unbound
  log-queries: yes
  interface: 0.0.0.0
  prefetch: yes
  access-control: 0.0.0.0/0 allow
  hide-identity: yes
  hide-version: yes

remote-control:
  control-enable: no

forward-zone:
  name: "."
  forward-addr: 9.9.9.9
  forward-addr: 149.112.112.112' > "/etc/unbound/unbound.conf.d/custom.conf"

systemctl disable --now systemd-resolved
systemctl mask systemd-resolved

HOSTNAME=$(hostname -s)
echo "127.0.0.1 $HOSTNAME" >> "/etc/hosts"
systemctl unmask unbound.service
systemctl enable --now unbound.service"""

    # workaround for SSM agent to work
    resolv = "\n".join(
        [
            "rm -f /etc/resolv.conf",
            "echo 'nameserver 127.0.0.1",
            "options edns0 trust-ad",
            f"search {region}.compute.internal' > /etc/resolv.conf",
        ]
    )

    user_data = ec2.UserData.for_linux()
    user_data.add_commands(commands, resolv)

    instance = ec2.Instance(
        self,
        f"{name}DNSInstance",
        instance_name=f"{name}DNSInstance",
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        security_group=security_group,
        role=role,
        user_data=user_data,
        key_name=key_name,
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.from_ssm_parameter(
            # latest ubuntu 20.04
            "/aws/service/canonical/ubuntu/server/focal/stable/current/amd64/hvm/ebs-gp2/ami-id",
            # always use the latest AMI
            cached_in_context=False,
        ),
    )

    return instance


def create_log4j_instance(
    self,
    name: str,
    vpc: ec2.IVpc,
    role: iam.IRole,
    security_group: ec2.ISecurityGroup,
    key_name: str,
) -> ec2.IInstance:
    """Create an instance with vulnerable app installed"""

    commands = """\
. /etc/os-release
REPO="https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable"
echo "deb ${REPO}/xUbuntu_${VERSION_ID}/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L "${REPO}/xUbuntu_${VERSION_ID}/Release.key" | apt-key add -
apt update
apt upgrade -y
apt install -y podman

podman run -d --name log4shell-app --rm -p 80:8080 ghcr.io/christophetd/log4shell-vulnerable-app
"""

    user_data = ec2.UserData.for_linux()
    user_data.add_commands(commands)

    instance = ec2.Instance(
        self,
        f"{name}Log4JInstance",
        instance_name=f"{name}Log4JInstance",
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        security_group=security_group,
        role=role,
        user_data=user_data,
        key_name=key_name,
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.from_ssm_parameter(
            "/aws/service/canonical/ubuntu/server/focal/stable/current/amd64/hvm/ebs-gp2/ami-id",
            cached_in_context=False,
        ),
    )

    return instance


class Log4Shell(Stack):
    """Inherit Stack class"""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        stack_name = kwargs["stack_name"]
        name = kwargs["name"]
        key_name = kwargs["key_name"]
        your_ip = kwargs["ip"]

        super().__init__(scope, construct_id, stack_name=stack_name)

        role = create_ssm_role(self, name)
        vpc = create_vpc(self, name)
        security_group = create_security_group(self, name, vpc, your_ip)
        dns_instance = create_dns_instance(
            self, name, vpc, role, security_group, key_name
        )
        log4j_instance = create_log4j_instance(
            self, name, vpc, role, security_group, key_name
        )

        CfnOutput(
            self, f"{name}DNSInstance-PrivateIP", value=dns_instance.instance_private_ip
        )
        CfnOutput(
            self,
            f"{name}Log4JInstance-PublicIP",
            value=log4j_instance.instance_public_ip,
        )
