import json
import logging
import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Suppress boto3 and botocore logs
boto3_logger = logging.getLogger("boto3")
boto3_logger.setLevel(logging.WARNING)

botocore_logger = logging.getLogger("botocore")
botocore_logger.setLevel(logging.WARNING)


def generate_response(status_code, message, data=None):
    return {
        "statusCode": status_code,
        "body": json.dumps({"message": message, "data": data}),
    }


def lambda_handler(event, context):
    try:
        logger.info("Event received: %s", event)

        # Retrieve parameters dynamically from the event (queryStringParameters)
        accountid = event.get("queryStringParameters", {}).get("accountid")
        region = event.get("queryStringParameters", {}).get("region")

        # Validate the parameters
        if not accountid or not region:
            raise ValueError("Missing accountid or region")

        # Call the function to get snapshot schedules for the account and region
        snapshot_schedule = get_snapshotschedule(accountid, region)

        return generate_response(
            200, "Snapshot schedule fetched successfully", snapshot_schedule
        )

    except ValueError as ve:
        logger.error("ValueError: %s", str(ve))
        return generate_response(400, f"Value Error: {str(ve)}")

    except ClientError as ce:
        logger.error("ClientError: %s", str(ce))
        return generate_response(502, f"Client Error: {str(ce)}")

    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        return generate_response(500, f"Unexpected Error: {str(e)}")


def get_snapshotschedule(accountId, region):
    try:
        resparr = []
        ec2 = cross_account_client(accountId, region)

        # Using paginator to fetch snapshots
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[accountId]):
            for item in page["Snapshots"]:
                for val in range(8):
                    day = datetime.now() - timedelta(days=val)

                    # Check if the snapshot's start time matches the date in the last 8 days
                    if datetime.strftime(item["StartTime"], "%Y-%m-%d") == day.strftime(
                        "%Y-%m-%d"
                    ):
                        respobj = {
                            "SnapshotId": item["SnapshotId"],
                            "StartTime": datetime.strftime(
                                item["StartTime"], "%Y-%m-%d"
                            ),
                            "VolumeSize": item["VolumeSize"],
                        }
                        resparr.append(respobj)

        return resparr

    except ClientError as ce:
        logger.error("Error fetching snapshots: %s", str(ce))
        raise

    except Exception as e:
        logger.error("Unexpected error in get_snapshotschedule: %s", str(e))
        raise


def cross_account_client(accountId, region):
    try:
        sts = boto3.client("sts")
        role_arn = f"arn:aws:iam::{accountId}:role/CWMSessionRole"
        acct = sts.assume_role(RoleArn=role_arn, RoleSessionName="wm-rnd-account")

        # Use temporary credentials to create EC2 client for cross-account access
        access_key = acct["Credentials"]["AccessKeyId"]
        secret_access_key = acct["Credentials"]["SecretAccessKey"]
        session_token = acct["Credentials"]["SessionToken"]

        client = boto3.client(
            "ec2",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=region,
        )

        return client

    except ClientError as ce:
        logger.error("ClientError during cross-account client creation: %s", str(ce))
        raise

    except Exception as e:
        logger.error("Unexpected error in cross_account_client: %s", str(e))
        raise


def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


if __name__ == "__main__":
    test_event = {
        "queryStringParameters": {"accountid": "123456789012", "region": "us-east-1"}
    }
    test_context = {}  # Context can be mocked as empty in testing
    print(lambda_handler(test_event, test_context))
