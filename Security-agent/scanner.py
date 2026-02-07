import boto3
import json

class AWSSecurityScanner:
    def __init__(self):
        self.s3_client = boto3.client('s3')

    def scan_s3_buckets(self):
        """Check all S3 buckets for public access via ACLs or bucket policies"""
        findings = []
        buckets = self.s3_client.list_buckets()['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']

            # --- Check ACLs ---
            try:
                acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                        permission = grant.get('Permission')
                        if permission in ["READ", "READ_ACP"]:
                            findings.append({
                                'type': 'S3_PUBLIC_BUCKET_ACL_READ',
                                'resource': bucket_name,
                                'severity': 'HIGH',
                                'details': 'Bucket ACL allows public read access'
                            })
                        elif permission in ["WRITE", "WRITE_ACP", "FULL_CONTROL"]:
                            findings.append({
                                'type': 'S3_PUBLIC_BUCKET_ACL_WRITE',
                                'resource': bucket_name,
                                'severity': 'CRITICAL',
                                'details': 'Bucket ACL allows public write access'
                            })
            except self.s3_client.exceptions.ClientError as e:
                if "AccessControlListNotSupported" not in str(e):
                    print(f"ACL check error for {bucket_name}: {e}")

            # --- Check Bucket Policy ---
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])
                for stmt in policy_doc.get('Statement', []):
                    principal = stmt.get('Principal')
                    actions = stmt.get('Action')
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        # Normalize actions into a list
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(actions, list):
                            for action in actions:
                                if action == "s3:GetObject":
                                    findings.append({
                                        'type': 'S3_PUBLIC_BUCKET_POLICY_READ',
                                        'resource': bucket_name,
                                        'severity': 'HIGH',
                                        'details': 'Bucket policy allows public read access'
                                    })
                                elif action in ["s3:PutObject", "s3:DeleteObject", "s3:*"]:
                                    findings.append({
                                        'type': 'S3_PUBLIC_BUCKET_POLICY_WRITE',
                                        'resource': bucket_name,
                                        'severity': 'CRITICAL',
                                        'details': 'Bucket policy allows public write access'
                                    })
            except self.s3_client.exceptions.NoSuchBucketPolicy:
                pass
            except self.s3_client.exceptions.ClientError as e:
                print(f"Policy check error for {bucket_name}: {e}")

        return findings