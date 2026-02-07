AWS AI Security Agent Vulnerability Finder

Architecture:
┌─────────────────────────────────────────┐
│  YOUR AI AGENT (Python Script)          │
│                                          │
│  1. Scanner Module                       │
│     └─> Checks AWS resources             │
│                                          │
│  2. AI Brain Module                      │
│     └─> Claude/GPT analyzes findings     │
│                                          │
│  3. Action Module                        │
│     └─> Sends email alert                │
└─────────────────────────────────────────┘

Steps to follow:
1. Create AWS account and install aws-cli in your pc locally.
  
2. Install python libraries locally
  pip install awscli boto3 anthropic python-dotenv

3. aws configure

4. Build Vulnerable S3 Bucket. The bucket is publicly accessible to everyone. Also anyone can upload files into this s3bucket.
  aws s3 mb s3://my-test-vulnerable-bucket-12345
  aws s3api put-bucket-policy --bucket my-test-vulnerable-bucket-12345 --policy file://public-s3.json
  aws s3 cp prabhas.jpg s3://my-test-vulnerable-bucket-12345/

5. Run python agent.py in your terminal. 

You should see agent starts running.
