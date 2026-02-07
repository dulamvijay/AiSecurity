from scanner import AWSSecurityScanner
from analyzer import AIAnalyzer
from notifier import EmailNotifier
from dotenv import load_dotenv

def main():
    print("Starting AI Security Agent...")
    
    # Load environment variables
    load_dotenv()
    
    # Initialize modules
    scanner = AWSSecurityScanner()
    analyzer = AIAnalyzer()
    notifier = EmailNotifier()
    
    # Step 1: Scan AWS
    print("Scanning AWS environment...")
    findings = scanner.scan_s3_buckets()
    print(f"Found {len(findings)} potential issues")
    
    # Step 2: AI Analysis
    print("AI is analyzing findings...")
    analysis = analyzer.analyze_findings(findings)
    print(analysis)
    
    # Step 3: Send Alert
    print("Sending email alert...")
    notifier.send_alert(analysis)
    
    print("✅ Agent completed successfully!")

if __name__ == "__main__":

    main()
