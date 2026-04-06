import google.generativeai as genai
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()

class ConfigAnalyzer:
    def __init__(self):
        # Configure Gemini
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        
        # Use Gemini 2.5 Flash model
        self.model = genai.GenerativeModel('gemini-2.5-flash')
    
    def analyze_config(self, config_text):
        """Analyze Cisco config using Gemini 2.5 Flash"""
        
        if not config_text or len(config_text.strip()) < 10:
            return {
                "score": 0,
                "risk_level": "Unknown",
                "violations": [{
                    "severity": "Medium",
                    "issue": "Config is empty or too short",
                    "fix": "Paste a valid Cisco running-config"
                }]
            }
        
        prompt = f"""
You are a Cisco security expert with CCNA/CCNP knowledge. Analyze this Cisco running-config.

IMPORTANT: Return ONLY valid JSON. No markdown, no explanations outside JSON.

Format EXACTLY like this:
{{
    "score": 85,
    "risk_level": "Medium",
    "violations": [
        {{
            "severity": "High",
            "issue": "Telnet is enabled on VTY lines",
            "fix": "line vty 0 4\\n transport input ssh\\n login local"
        }}
    ]
}}

Risk levels: "Critical" (0-40), "High" (41-60), "Medium" (61-80), "Low" (81-100)

Check for these issues:
1. Telnet enabled (transport input telnet) → High
2. SSH disabled or not configured → High
3. HTTP server enabled (ip http-server) → High
4. Default/weak passwords (password cisco, password admin) → Critical
5. No password encryption (missing service password-encryption) → Medium
6. SNMP with public/private community → High
7. CDP enabled on edge ports → Low
8. No login banner (banner motd missing) → Low
9. No logging configured → Medium
10. Enable secret missing or weak → Critical

Config to analyze:
{config_text[:4000]}

Return ONLY valid JSON. No other text.
"""
        
        try:
            # Call Gemini API
            response = self.model.generate_content(prompt)
            
            # Clean the response (remove markdown if present)
            clean_response = response.text.strip()
            clean_response = re.sub(r'```json\s*', '', clean_response)
            clean_response = re.sub(r'```\s*', '', clean_response)
            
            # Parse JSON
            result = json.loads(clean_response)
            
            # Validate required fields
            if "score" not in result:
                result["score"] = 50
            if "risk_level" not in result:
                result["risk_level"] = "Medium"
            if "violations" not in result:
                result["violations"] = []
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"JSON Parse Error: {e}")
            return self._fallback_analysis(config_text)
        except Exception as e:
            print(f"Gemini API Error: {e}")
            return self._fallback_analysis(config_text)
    
    def _fallback_analysis(self, config_text):
        """Rule-based fallback when AI fails"""
        config_lower = config_text.lower()
        violations = []
        
        # Check for Telnet
        if "transport input telnet" in config_lower:
            violations.append({
                "severity": "High",
                "issue": "Telnet is enabled - sends passwords in plain text",
                "fix": "line vty 0 4\n transport input ssh\n login local"
            })
        
        # Check for HTTP server
        if "ip http-server" in config_lower:
            violations.append({
                "severity": "High",
                "issue": "HTTP server is enabled - web interface vulnerable",
                "fix": "no ip http-server\nip http secure-server"
            })
        
        # Check for password encryption
        if "service password-encryption" not in config_lower:
            violations.append({
                "severity": "Medium",
                "issue": "Password encryption is disabled",
                "fix": "service password-encryption"
            })
        
        # Check for weak passwords
        if "password cisco" in config_lower or "password admin" in config_lower or "password 123" in config_lower:
            violations.append({
                "severity": "Critical",
                "issue": "Default or weak password detected",
                "fix": "Configure strong password with 12+ characters"
            })
        
        # Check for CDP
        if "cdp run" in config_lower:
            violations.append({
                "severity": "Low",
                "issue": "CDP is enabled globally - can leak network info",
                "fix": "no cdp run"
            })
        
        # Calculate score
        critical_count = sum(1 for v in violations if v["severity"] == "Critical")
        high_count = sum(1 for v in violations if v["severity"] == "High")
        medium_count = sum(1 for v in violations if v["severity"] == "Medium")
        low_count = sum(1 for v in violations if v["severity"] == "Low")
        
        score = 100 - (critical_count * 15) - (high_count * 10) - (medium_count * 5) - (low_count * 2)
        score = max(0, min(100, score))
        
        if score >= 81:
            risk_level = "Low"
        elif score >= 61:
            risk_level = "Medium"
        elif score >= 41:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            "score": score,
            "risk_level": risk_level,
            "violations": violations if violations else [{
                "severity": "Low",
                "issue": "No major issues detected",
                "fix": "Review config for best practices"
            }]
        }