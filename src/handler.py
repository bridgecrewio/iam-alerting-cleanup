import boto3
from boto3_type_annotations.s3 import Client as S3Client

def handler(event, context):
    client: S3Client = boto3.client('s3', region_name='us-east-1')
    print(client.list_buckets())
