import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

class EmailNotifier:
    def send_alert(self, analysis_report):
        """Send email alert with findings"""
        
        # Email configuration (using Gmail as example)
        sender_email = os.environ.get("SENDER_EMAIL")
        sender_password = os.environ.get("SENDER_PASSWORD")
        receiver_email = os.environ.get("RECEIVER_EMAIL")
        
        # Create email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = "🚨 AWS Security Alert from Your AI Agent"
        
        # Email body
        body = f"""
        Your AI Security Agent has completed a scan!
        
        {analysis_report}
        
        ---
        Automated by your AI Security Agent 🤖
        """
        
        message.attach(MIMEText(body, "plain"))
        
        # Send email
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, sender_password)
                server.send_message(message)
            print("✅ Email sent successfully!")
        except Exception as e:
            print(f"❌ Error sending email: {e}")