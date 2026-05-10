import os
import json
from anthropic import Anthropic
from pydantic import BaseModel
from typing import Dict, Any

class AIExplanation(BaseModel):
    explanation: str
    remediation: str
    risk_level: str

class AIExplainer:
    def __init__(self, api_key: str = None):
        self.client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))

    def explain_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        prompt = (
            f"Explain the following security finding in a professional manner. "
            f"Finding: {finding.get('message')} "
            f"Code Snippet: {finding.get('snippet', 'N/A')} "
            f"Return the response as a JSON object with keys: 'explanation', 'remediation', and 'risk_level'."
        )

        try:
            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            # Attempt to parse JSON from the response
            text = response.content[0].text
            # Basic cleaning for JSON parsing
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            return json.loads(text)
        except Exception as e:
            return {
                "explanation": f"Error generating AI explanation: {str(e)}",
                "remediation": "Consult security documentation for a fix.",
                "risk_level": "Unknown"
            }
