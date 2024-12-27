import boto3
import json
import logging
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Suppress boto3 and botocore logs
boto3_logger = logging.getLogger("boto3")
boto3_logger.setLevel(logging.WARNING)

botocore_logger = logging.getLogger("botocore")
botocore_logger.setLevel(logging.WARNING)


def lambda_handler(event, context):
    try:
        logger.info("Event: %s", event)

        account_id = event.get("queryStringParameters", {}).get("accountId")
        region = event.get("queryStringParameters", {}).get("regionCode")

        if not all([account_id, region]):
            raise ValueError("Missing required parameters: accountId or regionCode")

        instances = get_instances(account_id, region)

        return {
            "statusCode": 200,
            "body": json.dumps(
                instances, sort_keys=True, indent=1, default=datetime_handler
            ),
        }

    except ValueError as ve:
        logger.error("ValueError: %s", str(ve))
        return generate_response(400, f"Value Error: {str(ve)}")

    except ClientError as ce:
        logger.error("ClientError: %s", str(ce))
        return generate_response(502, f"Client Error: {str(ce)}")

    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        return generate_response(500, f"Unexpected Error: {str(e)}")


def get_instances(account_id, region):
    try:
        ec2 = cross_account_client(account_id, region)["ec2"]
        paginator = ec2.get_paginator("describe_instances")
        pages = paginator.paginate()
        instance_list = []

        for page in pages:
            reservations = page.get("Reservations", [])
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instance_public_ip = instance.get(
                        "PublicIpAddress", "Not Available"
                    )
                    instance_name = "NA"
                    try:
                        for tag in instance.get("Tags", []):
                            if "Name" in tag["Key"]:
                                instance_name = tag["Value"]
                    except Exception as e:
                        logger.warning("Error extracting instance name: %s", str(e))

                    instance_info = {
                        "InstanceName": instance_name,
                        "InstanceId": instance.get("InstanceId", "NA"),
                        "InstanceType": instance.get("InstanceType", "NA"),
                        "InstanceState": instance.get("State", {}).get("Name", "NA"),
                        "AvailabilityZone": instance.get("Placement", {}).get(
                            "AvailabilityZone", "NA"
                        ),
                        "Volumes": instance.get("BlockDeviceMappings", "NA"),
                        "PublicIpAddress": instance_public_ip,
                        "PrivateIpAddress": instance.get("PrivateIpAddress", "NA"),
                        "SubnetId": instance.get("SubnetId", "NA"),
                        "VpcId": instance.get("VpcId", "NA"),
                    }
                    instance_list.append(instance_info)

        return instance_list

    except Exception as e:
        logger.error("Error fetching instances: %s", str(e))
        raise


def cross_account_client(account_id, region_code):
    try:
        sts = boto3.client("sts")
        role_arn = f"arn:aws:iam::{account_id}:role/{os.environ.get('ROLE_NAME')}"
        session_name = os.environ.get("SESSION_NAME", "default-session")

        acct = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        credentials = acct["Credentials"]

        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region_code,
        )
        return {"ec2": ec2}

    except ClientError as ce:
        logger.error("ClientError during cross-account client creation: %s", str(ce))
        raise
    except Exception as e:
        logger.error(
            "Unexpected error during cross-account client creation: %s", str(e)
        )
        raise


def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


def generate_response(status_code, message):
    return {"statusCode": status_code, "body": json.dumps({"message": message})}
