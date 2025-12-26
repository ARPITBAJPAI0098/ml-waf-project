import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import re
from typing import Tuple, Dict
import datetime

class MLWAFModel:
    def __init__(self, model_path="/app/models/ml_waf_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.last_trained_time = None
        self.feature_count = 15
        
        self.sql_patterns = [
            r"(union.*select)", r"(select.*from)", r"(insert.*into)",
            r"(delete.*from)", r"(drop.*table)", r"('.*or.*'.*=.*')",
            r"(;.*--)", r"(\/\*.*\*\/)"
        ]
        
        self.xss_patterns = [
            r"(<script)", r"(javascript:)", r"(onerror=)", r"(onload=)",
            r"(<iframe)", r"(eval\()", r"(alert\()"
        ]
        
        self.path_traversal = [
            r"(\.\./)", r"(\.\.\\)", r"(/etc/passwd)", r"(c:\\windows)"
        ]
    
    def extract_features(self, method: str, path: str, headers: Dict, 
                        body: str, ip_address: str, user_agent: str) -> np.ndarray:
        features = []
        
        features.append(len(path))
        features.append(path.count('/'))
        
        query_len = len(path.split('?')[1]) if '?' in path else 0
        features.append(query_len)
        
        param_count = path.count('&') + (1 if '?' in path else 0)
        features.append(param_count)
        
        special_chars = sum(1 for c in path if not c.isalnum() and c not in ['/', '?', '&', '='])
        features.append(special_chars)
        
        sql_score = sum(1 for pattern in self.sql_patterns 
                       if re.search(pattern, path.lower() + body.lower()))
        features.append(sql_score)
        
        xss_score = sum(1 for pattern in self.xss_patterns 
                       if re.search(pattern, path.lower() + body.lower()))
        features.append(xss_score)
        
        traversal_score = sum(1 for pattern in self.path_traversal 
                             if re.search(pattern, path.lower()))
        features.append(traversal_score)
        
        features.append(len(body))
        features.append(len(headers))
        
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3}
        features.append(method_map.get(method.upper(), 4))
        
        suspicious_ua = int(any(x in user_agent.lower() for x in ['bot', 'crawler', 'scanner']))
        features.append(suspicious_ua)
        
        entropy = self._calculate_entropy(path)
        features.append(entropy)
        
        numeric_ratio = sum(c.isdigit() for c in path) / max(len(path), 1)
        features.append(numeric_ratio)
        
        has_extension = int('.' in path.split('/')[-1])
        features.append(has_extension)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        entropy = 0
        for c in set(text):
            p = text.count(c) / len(text)
            entropy -= p * np.log2(p)
        return entropy
    
    def predict(self, features: np.ndarray) -> Tuple[bool, float, str]:
        if not self.is_trained:
            return self._rule_based_detection(features)
        
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = self.model.score_samples(features_scaled)[0]
        confidence = abs(anomaly_score)
        
        is_malicious = prediction == -1
        threat_type = self._classify_threat(features[0]) if is_malicious else "benign"
        
        return is_malicious, confidence, threat_type
    
    def _rule_based_detection(self, features: np.ndarray) -> Tuple[bool, float, str]:
        f = features[0]
        
        if f[5] > 0:
            return True, 0.9, "sql_injection"
        if f[6] > 0:
            return True, 0.85, "xss"
        if f[7] > 0:
            return True, 0.88, "path_traversal"
        if f[0] > 200 or f[4] > 20:
            return True, 0.7, "suspicious_pattern"
        
        return False, 0.95, "benign"
    
    def _classify_threat(self, features: np.ndarray) -> str:
        if features[5] > 0:
            return "sql_injection"
        elif features[6] > 0:
            return "xss"
        elif features[7] > 0:
            return "path_traversal"
        elif features[11] == 1:
            return "bot_attack"
        else:
            return "anomaly"
    
    def train(self, X: np.ndarray):
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        
        self.is_trained = True
        self.last_trained_time = datetime.datetime.utcnow().isoformat()
        self._save_model()
    
    def _save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'last_trained': self.last_trained_time
        }, self.model_path)
    
    def load_or_train(self):
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.last_trained_time = data.get('last_trained')
                self.is_trained = True
                print("Model loaded successfully")
            except Exception as e:
                print(f"Error loading model: {e}, training new model")
                self._train_with_sample_data()
        else:
            print("No model found, training new model")
            self._train_with_sample_data()
    
    def _train_with_sample_data(self):
        normal_data = []
        for _ in range(1000):
            features = [
                np.random.randint(10, 50),
                np.random.randint(1, 5),
                np.random.randint(0, 30),
                np.random.randint(0, 5),
                np.random.randint(0, 5),
                0, 0, 0,
                np.random.randint(0, 100),
                np.random.randint(5, 15),
                0,
                0,
                np.random.uniform(2, 4),
                np.random.uniform(0, 0.3),
                1
            ]
            normal_data.append(features)
        
        X = np.array(normal_data)
        self.train(X)
        print("Model trained with sample data")
    
    def retrain(self):
        self._train_with_sample_data()