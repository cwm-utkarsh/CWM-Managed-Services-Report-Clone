import json
import logging
import boto3
import os
from botocore.exceptions import ClientError
from dateutil.relativedelta import relativedelta
from boto3.dynamodb.conditions import Key, Attr
from response import generate_response

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
        logger.info("Event received: %s", json.dumps(event))
        accountid = event.get("queryStringParameters", {}).get("accountid")
        if not accountid:
            return generate_response(200, "Empty Parameters")

        table_name = event.get("tableName")
        if not tableisempty(accountid, table_name):
            addec2count(accountid, event)
            addnewservices(
                getDataforeachService(accountid, event), accountid, table_name
            )
            return generate_response(200, json.dumps(getsevices(accountid, table_name)))

        return generate_response(200, json.dumps(getsevices(accountid, table_name)))

    except ValueError as ve:
        logger.error("ValueError: %s", str(ve))
        return generate_response(400, f"Value Error: {str(ve)}")

    except ClientError as ce:
        logger.error("ClientError: %s", str(ce))
        return generate_response(502, f"Client Error: {str(ce)}")

    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        return generate_response(500, f"Unexpected Error: {str(e)}")


def tableisempty(account, table_name):
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)
        response = table.scan(FilterExpression=Attr("AccountId").eq(account))
        items = response["Items"]
        return items

    except Exception as e:
        logger.error("Error in tableisempty: %s", str(e))
        raise


def getDataforeachService(accountid, event):
    try:
        region = event.get("region", "ap-south-1")
        client = cross_account_client(accountid, region, event)[0]
        colt = []
        exp = r"arn:aws:\w*"
        events = []
        proxyarr = []
        response = client.get_resources()["ResourceTagMappingList"]
        for item in response:
            results = set(re.findall(exp, item["ResourceARN"]))
            for result in results:
                events.append(result.split(":")[2])
        for elemt in events:
            if elemt not in proxyarr and elemt != "ec2":
                proxyarr.append(elemt)
        if proxyarr:
            colt.append({"Count": len(proxyarr), "Services": proxyarr[:]})
        return colt

    except Exception as e:
        logger.error("Error in getDataforeachService: %s", str(e))
        raise


def addec2count(accountid, event):
    try:
        region = event.get("region", "ap-south-1")
        client = cross_account_client(accountid, region, event)[1]
        ec2paginator = client.get_paginator("describe_instances")
        instances = ec2paginator.paginate()
        ec2count = len(
            [
                obj
                for instance in instances
                for dp in instance["Reservations"]
                for obj in dp["Instances"]
            ]
        )
        servicecol = [{"Count": ec2count, "Services": ["ec2"]}]
        addnewservices(servicecol, accountid, event.get("tableName"))
        return True

    except Exception as e:
        logger.error("Error in addec2count: %s", str(e))
        raise


def addnewservices(service, accountid, table_name):
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)
        for item in service:
            for obj in item["Services"]:
                try:
                    table.put_item(
                        Item={
                            "id": str(uuid.uuid4()),
                            "AccountId": accountid,
                            "ServiceName": obj,
                            "Count": item["Count"],
                        }
                    )
                except Exception as e:
                    logger.error("Error inserting item into DynamoDB: %s", str(e))
                    raise
        return True

    except Exception as e:
        logger.error("Error in addnewservices: %s", str(e))
        raise


def getsevices(accountid, table_name):
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)
        response = table.scan(FilterExpression=Attr("AccountId").eq(accountid))
        items = response["Items"]
        return [
            {
                "AccountId": item["AccountId"],
                "ServiceName": item["ServiceName"],
                "Count": str(item["Count"]),
            }
            for item in items
        ]

    except Exception as e:
        logger.error("Error in getsevices: %s", str(e))
        raise


def cross_account_client(accountid, region, event):
    try:
        role_arn = event.get("roleArn", f"arn:aws:iam::{accountid}:role/CWMSessionRole")
        role_session_name = event.get("roleSessionName", "wm-rnd-account")

        sts_connection = boto3.client("sts")
        acct_b = sts_connection.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
        )
        credentials = acct_b["Credentials"]

        rstag = boto3.client(
            "resourcegroupstaggingapi",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )

        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )

        return [rstag, ec2]

    except Exception as e:
        logger.error("Error in cross_account_client: %s", str(e))
        raise


def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")
