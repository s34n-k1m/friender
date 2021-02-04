import boto3
from secret import S3_KEY, S3_SECRET, S3_BUCKET, S3_LOCATION

s3 = boto3.client(
   "s3",
   aws_access_key_id=S3_KEY,
   aws_secret_access_key=S3_SECRET
)

def upload_file_to_s3(file, bucket_name, acl="public-read"):
    """ Helper function upload file to AWS s3 """
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )

    except Exception as e:
        # This is a catch all exception, edit this part to fit your needs.
        print("Error: ", e)
        return e
    
    return "{}{}".format(S3_LOCATION, file.filename)