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
        role_name = event.get("queryStringParameters", {}).get("roleName")
        session_name = event.get("queryStringParameters", {}).get(
            "sessionName", "default-session"
        )

        if not all([account_id, region, role_name]):
            raise ValueError(
                "Missing required parameters: accountId, regionCode, or roleName"
            )

        # Call get_reserved_instances_and_savings_plans
        result = get_reserved_instances_and_savings_plans(
            account_id, region, role_name, session_name
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                result, sort_keys=True, indent=1, default=datetime_handler
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


def get_reserved_instances_and_savings_plans(
    account_id, region, role_name, session_name
):
    try:
        # Cross-account access
        clients = cross_account_client(account_id, region, role_name, session_name)
        ec2 = clients["ec2"]
        ce = clients["ce"]  # Cost Explorer

        # Get Reserved Instances
        reserved_instances = []
        paginator = ec2.get_paginator("describe_reserved_instances")
        pages = paginator.paginate()

        for page in pages:
            for ri in page.get("ReservedInstances", []):
                reserved_instance_info = {
                    "InstanceType": ri.get("InstanceType", "NA"),
                    "AvailabilityZone": ri.get("AvailabilityZone", "NA"),
                    "State": ri.get("State", "NA"),
                    "OfferingType": ri.get("OfferingType", "NA"),
                    "Start": ri.get("Start", "NA"),
                    "End": ri.get("End", "NA"),
                    "InstanceCount": ri.get("InstanceCount", "NA"),
                }
                reserved_instances.append(reserved_instance_info)

        # Get Savings Plans
        savings_plans = []
        response = ce.get_savings_plans(
            Filters={
                "savingsPlanOfferingId": "All",
            }
        )

        for plan in response.get("SavingsPlans", []):
            savings_plan_info = {
                "SavingsPlanId": plan.get("SavingsPlanId", "NA"),
                "SavingsPlanType": plan.get("SavingsPlanType", "NA"),
                "PaymentOption": plan.get("PaymentOption", "NA"),
                "EffectiveDate": plan.get("EffectiveDate", "NA"),
                "TermDuration": plan.get("TermDuration", "NA"),
                "Amount": plan.get("Amount", "NA"),
            }
            savings_plans.append(savings_plan_info)

        return {"ReservedInstances": reserved_instances, "SavingsPlans": savings_plans}

    except Exception as e:
        logger.error("Error fetching Reserved Instances and Savings Plans: %s", str(e))
        raise


def cross_account_client(account_id, region_code, role_name, session_name):
    try:
        sts = boto3.client("sts")
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        acct = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        credentials = acct["Credentials"]

        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region_code,
        )

        ce = boto3.client(
            "ce",  # Cost Explorer client
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region_code,
        )

        return {"ec2": ec2, "ce": ce}

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
