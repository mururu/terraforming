require "aws-sdk-autoscaling"
require "aws-sdk-cloudwatch"
require "aws-sdk-ec2"
require "aws-sdk-efs"
require "aws-sdk-elasticache"
require "aws-sdk-elasticloadbalancing"
require "aws-sdk-elasticloadbalancingv2"
require "aws-sdk-iam"
require "aws-sdk-kms"
require "aws-sdk-rds"
require "aws-sdk-redshift"
require "aws-sdk-route53"
require "aws-sdk-s3"
require "aws-sdk-sns"
require "aws-sdk-sqs"

require "erb"
require "multi_json"
require "thor"
require "zlib"

require "terraforming/util"
require "terraforming/version"

require "terraforming/cli"
require "terraforming/resource/alb"
require "terraforming/resource/auto_scaling_group"
require "terraforming/resource/cloud_watch_alarm"
require "terraforming/resource/db_parameter_group"
require "terraforming/resource/db_security_group"
require "terraforming/resource/db_subnet_group"
require "terraforming/resource/ec2"
require "terraforming/resource/eip"
require "terraforming/resource/elasti_cache_cluster"
require "terraforming/resource/elasti_cache_subnet_group"
require "terraforming/resource/efs_file_system"
require "terraforming/resource/elb"
require "terraforming/resource/iam_group"
require "terraforming/resource/iam_group_membership"
require "terraforming/resource/iam_group_policy"
require "terraforming/resource/iam_instance_profile"
require "terraforming/resource/iam_policy"
require "terraforming/resource/iam_policy_attachment"
require "terraforming/resource/iam_role"
require "terraforming/resource/iam_role_policy"
require "terraforming/resource/iam_user"
require "terraforming/resource/iam_user_policy"
require "terraforming/resource/kms_alias"
require "terraforming/resource/kms_key"
require "terraforming/resource/launch_configuration"
require "terraforming/resource/internet_gateway"
require "terraforming/resource/nat_gateway"
require "terraforming/resource/network_acl"
require "terraforming/resource/network_interface"
require "terraforming/resource/rds"
require "terraforming/resource/redshift"
require "terraforming/resource/route_table"
require "terraforming/resource/route_table_association"
require "terraforming/resource/route53_record"
require "terraforming/resource/route53_zone"
require "terraforming/resource/s3"
require "terraforming/resource/security_group"
require "terraforming/resource/security_group2"
require "terraforming/resource/subnet"
require "terraforming/resource/sqs"
require "terraforming/resource/vpc"
require "terraforming/resource/vpn_gateway"
require "terraforming/resource/sns_topic"
require "terraforming/resource/sns_topic_subscription"
