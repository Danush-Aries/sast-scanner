import os
import json
from anthropic import Anthropic
from typing import Dict, Any


class AIExplainer:
    """
    Uses the Claude API to generate professional security explanations and
    remediation guidance for each SAST finding.
    """

    MODEL = "claude-haiku-4-5"

    # System prompt is static — mark it for prompt caching to save tokens.
    _SYSTEM_PROMPT = (
        "You are a senior application security engineer. "
        "When given a security finding, respond ONLY with a valid JSON object "
        "(no markdown fences, no prose) containing exactly three keys: "
        "\"explanation\" (concise technical description of the vulnerability), "
        "\"remediation\" (concrete fix with a short code example where applicable), "
        "and \"risk_level\" (one of: Critical, High, Medium, Low)."
    )

    def __init__(self, api_key: str = None):
        self.client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))

    def explain_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        user_message = (
            f"Security finding ID: {finding.get('id', 'unknown')}\n"
            f"Message: {finding.get('message', 'N/A')}\n"
            f"Code snippet: {finding.get('snippet', 'N/A')}\n"
            f"File: {finding.get('file', 'N/A')} (line {finding.get('line', 'N/A')})\n\n"
            "Provide the JSON response now."
        )

        try:
            response = self.client.messages.create(
                model=self.MODEL,
                max_tokens=512,
                system=[
                    {
                        "type": "text",
                        "text": self._SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_message}],
            )
            text = response.content[0].text.strip()
            # Strip any accidental markdown fences the model may still include
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            return json.loads(text)
        except json.JSONDecodeError:
            # Return the raw text so callers can still display something
            return {
                "explanation": text if "text" in dir() else "Could not parse AI response.",
                "remediation": "Consult OWASP guidelines for remediation advice.",
                "risk_level": "Unknown",
            }
        except Exception as e:
            return {
                "explanation": f"AI explanation unavailable: {str(e)}",
                "remediation": "Consult OWASP guidelines for remediation advice.",
                "risk_level": "Unknown",
            }
