import os
import sys

import boto3
from boto3_type_annotations.s3 import Client as S3Client
import logging

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def handler(event, context):
    client: S3Client = boto3.client('s3', region_name='us-east-1')
    LOGGER.info(client.list_buckets())
