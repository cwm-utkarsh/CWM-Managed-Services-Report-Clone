import json
import boto3
import base64
from datetime import datetime
import multiprocessing
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

boto3_logger = logging.getLogger("boto3")
boto3_logger.setLevel(logging.WARNING)

botocore_logger = logging.getLogger("botocore")
botocore_logger.setLevel(logging.WARNING)


def lambda_handler(event, context):
    try:
        logger.info("Event: %s", event)

        accountid = event["queryStringParameters"]["accountid"]
        region = event["queryStringParameters"]["region"]
        start = event["queryStringParameters"]["start"]
        end = event["queryStringParameters"]["end"]
        role_name = event["queryStringParameters"].get("role_name", "CWMSessionRole")
        widget_height = int(event["queryStringParameters"].get("widget_height", 300))
        widget_width = int(event["queryStringParameters"].get("widget_width", 300))

        if not all([accountid, start, end, region]):
            logger.error("Missing required parameters")
            return {"statusCode": 400, "body": json.dumps("Empty Parameters")}

        processes = []
        dict1 = multiprocessing.Manager().list()

        for item in getImagejson(
            accountid, start, end, region, widget_height, widget_width, role_name
        ):
            process = multiprocessing.Process(
                target=getImagepng, args=(accountid, item, region, dict1, role_name)
            )
            processes.append(process)

        for process in processes:
            process.start()
        for process in processes:
            process.join()

        return {
            "statusCode": 200,
            "body": json.dumps(dict1[:], default=datetime_handler),
        }

    except ValueError as ve:
        logger.error("ValueError: %s", str(ve))
        return {"statusCode": 400, "body": json.dumps(f"Value Error: {str(ve)}")}

    except ClientError as ce:
        logger.error("ClientError: %s", str(ce))
        return {"statusCode": 502, "body": json.dumps(f"Client Error: {str(ce)}")}

    except Exception as e:
        logger.error("Unexpected Error: %s", str(e))
        return {"statusCode": 500, "body": json.dumps(f"Unexpected Error: {str(e)}")}


def getList(accountid, region, role_name):
    try:
        cwclient = cross_account_client(accountid, region, role_name)
        response = cwclient.list_dashboards()
        return response["DashboardEntries"]
    except ClientError as ce:
        logger.error("ClientError in getList: %s", str(ce))
        raise
    except Exception as e:
        logger.error("Unexpected error in getList: %s", str(e))
        raise


def getproperties(accountid, region, role_name):
    try:
        cwclient = cross_account_client(accountid, region, role_name)
        respbdy = []
        for name in getList(accountid, region, role_name):
            response = cwclient.get_dashboard(DashboardName=name["DashboardName"])
            respbdy.append(json.loads(response["DashboardBody"]))
        return respbdy
    except ClientError as ce:
        logger.error("ClientError in getproperties: %s", str(ce))
        raise
    except Exception as e:
        logger.error("Unexpected error in getproperties: %s", str(e))
        raise


def getImagejson(accountid, start, end, region, height, width, role_name):
    try:
        respbdy = []
        for item in getproperties(accountid, region, role_name):
            for widget in item["widgets"]:
                widgetobj = {
                    "height": height,
                    "width": width,
                    "metrics": widget["properties"]["metrics"],
                    "region": widget["properties"]["region"],
                    "stacked": False,
                    "view": widget["properties"]["view"],
                    "type": widget["type"],
                    "start": start,
                    "end": end,
                }
                respbdy.append(widgetobj)
        return respbdy
    except ClientError as ce:
        logger.error("ClientError in getImagejson: %s", str(ce))
        raise
    except Exception as e:
        logger.error("Unexpected error in getImagejson: %s", str(e))
        raise


def getImagepng(accountid, item, region, collection, role_name):
    try:
        cwclient = cross_account_client(accountid, region, role_name)
        dashboard_image = cwclient.get_metric_widget_image(
            MetricWidget=json.dumps(item)
        )["MetricWidgetImage"]
        dashboard_image = base64.b64encode(dashboard_image).decode("utf-8")
        respobj = {"Image": dashboard_image}
        collection.append(respobj)
    except ClientError as ce:
        logger.error("ClientError in getImagepng: %s", str(ce))
        raise
    except Exception as e:
        logger.error("Unexpected error in getImagepng: %s", str(e))
        raise


def cross_account_client(accountid, region, role_name):
    try:
        sts = boto3.client("sts")
        role_arn = f"arn:aws:iam::{accountid}:role/{role_name}"
        acct = sts.assume_role(RoleArn=role_arn, RoleSessionName="wm-rnd-account")
        access_key = acct["Credentials"]["AccessKeyId"]
        secret_access_key = acct["Credentials"]["SecretAccessKey"]
        session_token = acct["Credentials"]["SessionToken"]
        cw = boto3.client(
            "cloudwatch",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=region,
        )
        return cw
    except ClientError as ce:
        logger.error("ClientError in cross_account_client: %s", str(ce))
        raise
    except Exception as e:
        logger.error("Unexpected error in cross_account_client: %s", str(e))
        raise


def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")
