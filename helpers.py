import boto3
from secret import S3_KEY, S3_SECRET, S3_BUCKET, S3_LOCATION

# Connect to AWS S3
s3 = boto3.client(
   "s3",
   aws_access_key_id=S3_KEY,
   aws_secret_access_key=S3_SECRET
)

def upload_file_to_s3(bucket_name, filename, acl="public-read"):
    """ Helper function upload file to AWS s3 """
    try:
        s3.upload_file(
            Bucket = bucket_name,
            Filename = filename,
            Key = filename,
            ExtraArgs={
                "ACL": acl
            }
        )

    except Exception as e:
        # This is a catch all exception, edit this part to fit your needs.
        print("Error: ", e)
        return e
    
    return "{}{}".format(S3_LOCATION, filename)