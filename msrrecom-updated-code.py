import json, logging, boto3, datetime
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

        accountid = event.get("queryStringParameters", {}).get("accountid")
        if not accountid:
            raise ValueError("Missing or empty 'accountid' parameter.")

        response = get_recommendations(accountid)
        return {
            "statusCode": 200,
            "body": json.dumps(response, sort_keys=True, indent=1, default=default),
        }

    except ValueError as ve:
        logger.error("ValueError: %s", str(ve))
        return {"statusCode": 400, "body": json.dumps({"error": str(ve)})}

    except ClientError as ce:
        logger.error("ClientError: %s", str(ce))
        return {"statusCode": 502, "body": json.dumps({"error": str(ce)})}

    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}


def get_recommendations(account_id):
    resparr = []
    client = cross_account_client(account_id)
    try:
        ebsresp = client.get_ebs_volume_recommendations(accountIds=[account_id])
        ec2resp = client.get_ec2_instance_recommendations(accountIds=[account_id])

        for item1, item2 in zip(
            ebsresp.get("volumeRecommendations", []),
            ec2resp.get("instanceRecommendations", []),
        ):
            respbdy = {"EBSRecommendations": item1, "EC2Recommendations": item2}
            resparr.append(respbdy)

    except ClientError as ce:
        logger.error("AWS ClientError: %s", str(ce))
        resparr.append(
            {
                "EBSRecommendations": "Account is not registered for recommendations.",
                "EC2Recommendations": "Account is not registered for recommendations.",
            }
        )
    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        raise

    return resparr


def cross_account_client(account_id):
    try:
        sts = boto3.client("sts")

        role_arn = (
            event.get("roleArn") or f"arn:aws:iam::{account_id}:role/CWMSessionRole"
        )
        region_name = event.get("region") or "ap-south-1"

        acct = sts.assume_role(RoleArn=role_arn, RoleSessionName="wm-rnd-account")

        access_key = acct["Credentials"]["AccessKeyId"]
        secret_access_key = acct["Credentials"]["SecretAccessKey"]
        session_token = acct["Credentials"]["SessionToken"]

        return boto3.client(
            "compute-optimizer",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=region_name,
        )

    except ClientError as ce:
        logger.error("Error assuming role or creating client: %s", str(ce))
        raise


def default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
