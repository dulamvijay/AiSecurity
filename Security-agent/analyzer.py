import anthropic
import os
import json

class AIAnalyzer:
    def __init__(self):
        # Connect to Claude
        self.client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )
    
    def analyze_findings(self, findings):
        """Use AI to analyze security findings"""
        
        if not findings:
            return "No security issues found! 🎉"
        
        # Prepare findings for AI
        findings_text = json.dumps(findings, indent=2)
        
        # Ask Claude to analyze
        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{
                "role": "user",
                "content": f"""You are a security expert. Analyze these AWS security findings and provide:
                1. A clear summary of the risks
                2. Why each issue is dangerous
                3. How to fix each issue
                
                Findings:
                {findings_text}
                
                Keep it simple and actionable."""
            }]
        )
        
        return message.content[0].text