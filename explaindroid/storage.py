import os
import shutil

from . import config


def s3_enabled():
    return all([
        config.S3_BUCKET,
        config.S3_ACCESS_KEY_ID,
        config.S3_SECRET_ACCESS_KEY,
    ])


def backend_name():
    return "s3" if s3_enabled() else "local"


def object_key(job_id, filename):
    safe_name = filename.replace("/", "_")
    return f"{config.S3_PREFIX}/{job_id}/{safe_name}"


def local_path_for_key(key):
    return os.path.join(config.UPLOADS_DIR, key.replace("/", os.sep))


def s3_client():
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("Install boto3 to use S3-compatible APK storage") from exc

    return boto3.client(
        "s3",
        endpoint_url=config.S3_ENDPOINT_URL or None,
        region_name=config.S3_REGION,
        aws_access_key_id=config.S3_ACCESS_KEY_ID,
        aws_secret_access_key=config.S3_SECRET_ACCESS_KEY,
    )


def create_upload_target(key, filename, max_bytes):
    if s3_enabled():
        url = s3_client().generate_presigned_url(
            "put_object",
            Params={
                "Bucket": config.S3_BUCKET,
                "Key": key,
                "ContentType": "application/vnd.android.package-archive",
            },
            ExpiresIn=3600,
        )
        return {
            "mode": "s3_put",
            "url": url,
            "fields": {},
            "method": "PUT",
        }

    return {
        "mode": "local",
        "url": None,
        "fields": {},
        "method": "PUT",
    }


def save_local_upload(key, file_storage):
    path = local_path_for_key(key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    file_storage.save(path)
    return os.path.getsize(path)


def download_to_file(key, destination):
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    if s3_enabled():
        s3_client().download_file(config.S3_BUCKET, key, destination)
    else:
        shutil.copyfile(local_path_for_key(key), destination)


def delete_object(key):
    if s3_enabled():
        s3_client().delete_object(Bucket=config.S3_BUCKET, Key=key)
        return

    path = local_path_for_key(key)
    if os.path.exists(path):
        os.remove(path)
