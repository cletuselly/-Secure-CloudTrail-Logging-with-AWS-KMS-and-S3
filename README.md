# **Project Title: Secure CloudTrail Logging with AWS KMS and S3**

## **Overview**
This project focuses on implementing a secure logging system using AWS CloudTrail, AWS Key Management Service (KMS), and Amazon S3. The goal was to ensure all CloudTrail logs were encrypted, stored securely, and only accessible to authorized users.

## **Objectives**
- Enable AWS CloudTrail logging for monitoring API activity.
- Encrypt logs using AWS KMS for enhanced security.
- Store logs securely in Amazon S3 with proper IAM policies.
- Verify log integrity and accessibility.
- Ensure compliance with cloud security best practices.

## **Architecture**
The project consists of:
- **AWS CloudTrail** for logging API events.
- **Amazon S3** as the storage location for log files.
- **AWS KMS** for encrypting the CloudTrail logs.
- **IAM Policies** to manage access control.

## **Implementation Steps**
### 1️⃣ **Configure Amazon S3 Bucket for CloudTrail Logs**
- Created an Amazon S3 bucket: `elly-secure-bucket`
- Configured S3 bucket policy to allow CloudTrail access

### 2️⃣ **Create a CloudTrail for Logging Events**
- Enabled CloudTrail with a new trail `s3-activity-trail`
- Configured log delivery to `elly-secure-bucket`
- Enabled log file validation

### 3️⃣ **Encrypt CloudTrail Logs with AWS KMS**
- Created a customer-managed KMS key
- Updated the KMS key policy to allow CloudTrail to encrypt logs

### 4️⃣ **Apply IAM Policies for Secure Access**
- Created an IAM policy to allow only specific users and services access to CloudTrail logs
- Verified access permissions

### 5️⃣ **Testing and Validation**
- Verified CloudTrail was successfully logging events to S3
- Checked that logs were encrypted with KMS
- Used AWS CLI to retrieve logs and confirm access control

## **AWS IAM and KMS Policies Used**
### **S3 Bucket Policy for CloudTrail Logging**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::elly-secure-bucket",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceArn": "arn:aws:cloudtrail:us-east-2:124355676326:trail/s3-activity-trail"
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::elly-secure-bucket/AWSLogs/124355676326/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "AWS:SourceArn": "arn:aws:cloudtrail:us-east-2:124355676326:trail/s3-activity-trail"
                }
            }
        }
    ]
}
```

### **KMS Key Policy for CloudTrail Encryption**
```json
{
    "Version": "2012-10-17",
    "Id": "kms-cloudtrail-policy",
    "Statement": [
        {
            "Sid": "AllowCloudTrailAccess",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowAdminUserAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::124355676326:user/adminUser"
            },
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}
```

## **Challenges Faced**
- **Invalid Base64 Encoding Error**: Resolved by using base64 encoding for AWS CLI inputs.
- **IAM Policy Restrictions**: Ensured CloudTrail had the correct permissions to access the S3 bucket and KMS key.
- **Log Integrity Validation**: Enabled log file validation to ensure no tampering of logs.

## **Testing & Validation**
### **Confirm CloudTrail is Writing Logs**
```sh
aws s3 ls s3://elly-secure-bucket/AWSLogs/124355676326/
```

### **Verify IAM User Permissions**
```sh
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::124355676326:user/adminUser --action-names kms:Decrypt
```

### **Test CloudTrail Logs in S3**
```sh
aws s3 cp s3://elly-secure-bucket/AWSLogs/124355676326/CloudTrail/us-east-2/2025/03/15/ logfile.json
cat logfile.json
```

## **Project Outcome**
- Successfully secured AWS CloudTrail logs with encryption and access control.
- Verified logs were stored in Amazon S3 with proper permissions.
- Demonstrated IAM and KMS policy best practices.

## **Next Steps**
- Automate log monitoring with AWS Lambda and SNS alerts.
- Implement SIEM integration for real-time security analysis.
- Apply threat detection mechanisms with Amazon GuardDuty.

## **Conclusion**
This project provided a hands-on experience in securing AWS CloudTrail logs using Amazon S3 and AWS KMS. Proper IAM policies ensured restricted access, enhancing the overall security posture of the cloud environment.
