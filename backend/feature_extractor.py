"""
Feature Extractor - Extract ML features from HTTP traffic
"""
import re
import math
from collections import Counter
from typing import Dict
from datetime import datetime

class FeatureExtractor:
    def __init__(self):
        self.sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"('|\")(.*?)('|\")",
            r"(--|#|/\*)",
            r"(\bor\b.*=.*)",
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<embed",
            r"<object",
        ]
        
    def extract(self, traffic: Dict) -> Dict:
        """Extract all features from traffic"""
        features = {}
        
        # Basic features
        features.update(self._extract_basic_features(traffic))
        
        # Path analysis
        features.update(self._extract_path_features(traffic.get('path', '')))
        
        # Header analysis
        features.update(self._extract_header_features(traffic.get('headers', {})))
        
        # Attack patterns
        features.update(self._extract_attack_patterns(traffic))
        
        # Timing features
        features.update(self._extract_time_features())
        
        # Additional security features
        features.update(self._extract_security_features(traffic))
        
        return features
    
    def _extract_basic_features(self, traffic: Dict) -> Dict:
        """Extract basic HTTP features"""
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 4, 'HEAD': 5}
        
        return {
            'method_encoded': method_map.get(traffic.get('method', 'GET'), 6),
            'path_length': len(traffic.get('path', '')),
            'content_length': len(traffic.get('body', '')),
            'query_param_count': traffic.get('query_string', '').count('&') + 1 if traffic.get('query_string') else 0,
        }
    
    def _extract_path_features(self, path: str) -> Dict:
        """Extract path-related features"""
        return {
            'path_entropy': self._calculate_entropy(path),
            'special_char_ratio': sum(not c.isalnum() for c in path) / max(len(path), 1),
            'digit_ratio': sum(c.isdigit() for c in path) / max(len(path), 1),
            'upper_ratio': sum(c.isupper() for c in path) / max(len(path), 1),
        }
    
    def _extract_header_features(self, headers: Dict) -> Dict:
        """Extract header-related features"""
        return {
            'num_headers': len(headers),
            'user_agent_length': len(headers.get('user-agent', headers.get('User-Agent', ''))),
            'has_referer': 1.0 if 'referer' in headers or 'Referer' in headers else 0.0,
            'cookie_count': headers.get('cookie', '').count(';') + 1 if headers.get('cookie') else 0,
            'accept_header_present': 1.0 if 'accept' in headers or 'Accept' in headers else 0.0,
            'authorization_present': 1.0 if 'authorization' in headers or 'Authorization' in headers else 0.0,
        }
    
    def _extract_attack_patterns(self, traffic: Dict) -> Dict:
        """Check for attack patterns"""
        path = traffic.get('path', '')
        body = traffic.get('body', '')
        full_text = f"{path} {body}"
        
        return {
            'sql_injection_score': self._pattern_score(full_text, self.sql_patterns),
            'xss_score': self._pattern_score(full_text, self.xss_patterns),
            'has_sql_keywords': 1.0 if self._pattern_score(full_text, self.sql_patterns) > 0 else 0.0,
            'has_xss_patterns': 1.0 if self._pattern_score(full_text, self.xss_patterns) > 0 else 0.0,
            'path_traversal_score': self._check_path_traversal(path),
            'command_injection_score': self._check_command_injection(full_text),
        }
    
    def _extract_time_features(self) -> Dict:
        """Extract time-based features"""
        now = datetime.now()
        return {
            'hour': now.hour,
            'day_of_week': now.weekday(),
        }
    
    def _extract_security_features(self, traffic: Dict) -> Dict:
        """Extract additional security features"""
        return {
            'requests_per_minute': 0,  # Will be filled by rate limiter
            'content_type_encoded': 0,
            'suspicious_header_count': 0,
            'unusual_port': 0,
            'ip_reputation_score': 0.5,
            'geo_risk_score': 0.1,
            'known_bot_ua': 0,
            'request_size_total': len(str(traffic)),
            'header_order_anomaly': 0,
            'protocol_version_encoded': 1,
            'cipher_strength': 0.8,
            'tls_version_encoded': 3,
            'cert_valid': 1,
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy
    
    def _pattern_score(self, text: str, patterns: list) -> float:
        """Calculate pattern match score"""
        text_lower = text.lower()
        matches = sum(
            1 for pattern in patterns
            if re.search(pattern, text_lower, re.IGNORECASE)
        )
        return min(matches / max(len(patterns), 1), 1.0)
    
    def _check_path_traversal(self, path: str) -> float:
        """Check for path traversal attempts"""
        indicators = ['../', '..\\', '%2e%2e', 'etc/passwd', 'windows\\system']
        matches = sum(1 for ind in indicators if ind in path.lower())
        return min(matches / 3, 1.0)
    
    def _check_command_injection(self, text: str) -> float:
        """Check for command injection"""
        indicators = [';', '|', '&&', '`', '$(',  'wget', 'curl', 'nc ', 'bash']
        matches = sum(1 for ind in indicators if ind in text.lower())
        return min(matches / 5, 1.0)