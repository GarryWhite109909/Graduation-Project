# 样本: 硬编码密钥 - Python AWS 凭证
# 期望: 检测到硬编码的访问密钥
import boto3

# 漏洞：硬编码 AWS 访问密钥
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"


def upload_file(bucket: str, key: str, data: bytes) -> None:
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    client.put_object(Bucket=bucket, Key=key, Body=data)
