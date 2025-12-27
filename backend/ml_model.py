import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import re
from typing import Tuple, Dict
import datetime
from feature_extractor import FeatureExtractor

class MLWAFModel:
    def __init__(self, model_path="/app/models/ml_waf_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.last_trained_time = None
        self.feature_count = 35
        self.feature_extractor = FeatureExtractor()
        self.feature_keys = None  # to lock feature order
    
    def build_feature_vector(self, traffic: Dict) -> np.ndarray:
        
    # 1. Extract features using FeatureExtractor
        feature_dict = self.feature_extractor.extract(traffic)

        # 2. Fix feature order ONCE
        if self.feature_keys is None:
            self.feature_keys = sorted(feature_dict.keys())

        # 3. Build feature vector in fixed order
        feature_vector = [feature_dict[k] for k in self.feature_keys]

        # 4. Convert to numpy array
        return np.array(feature_vector).reshape(1, -1)
    
    def predict(self, traffic: Dict):
        features = self.build_feature_vector(traffic)

        if not self.is_trained:
            return self._rule_based_detection(features)

        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = self.model.score_samples(features_scaled)[0]

        confidence = abs(anomaly_score)
        is_malicious = prediction == -1
        threat_type = self._classify_threat(features[0]) if is_malicious else "benign"

        return is_malicious, confidence, threat_type

    def _rule_based_detection(self, features: np.ndarray):
        f = features[0]

        # Update indexes after first run print
        SQL_IDX = self.feature_keys.index('sql_injection_score')
        XSS_IDX = self.feature_keys.index('xss_score')
        PATH_IDX = self.feature_keys.index('path_traversal_score')

        if f[SQL_IDX] > 0:
            return True, 0.9, "sql_injection"
        if f[XSS_IDX] > 0:
            return True, 0.85, "xss"
        if f[PATH_IDX] > 0:
            return True, 0.88, "path_traversal"

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
                # Basic features (4)
                np.random.randint(0, 6),      # method_encoded
                np.random.randint(10, 50),    # path_length
                np.random.randint(0, 1000),   # content_length
                np.random.randint(0, 5),      # query_param_count
                
                # Path features (4)
                np.random.uniform(2, 4),      # path_entropy
                np.random.uniform(0, 0.3),    # special_char_ratio
                np.random.uniform(0, 0.2),    # digit_ratio
                np.random.uniform(0, 0.1),    # upper_ratio
                
                # Header features (6)
                np.random.randint(5, 20),     # num_headers
                np.random.randint(50, 200),   # user_agent_length
                np.random.randint(0, 2),      # has_referer
                np.random.randint(0, 5),      # cookie_count
                np.random.randint(0, 2),      # accept_header_present
                np.random.randint(0, 2),      # authorization_present
                
                # Attack patterns (6)
                0,                             # sql_injection_score
                0,                             # xss_score
                0,                             # has_sql_keywords
                0,                             # has_xss_patterns
                0,                             # path_traversal_score
                0,                             # command_injection_score
                
                # Time features (2)
                np.random.randint(0, 24),     # hour
                np.random.randint(0, 7),      # day_of_week
                
                # Security features (13)
                0,                             # requests_per_minute
                0,                             # content_type_encoded
                0,                             # suspicious_header_count
                0,                             # unusual_port
                np.random.uniform(0.3, 0.7),  # ip_reputation_score
                np.random.uniform(0, 0.2),    # geo_risk_score
                0,                             # known_bot_ua
                np.random.randint(100, 2000), # request_size_total
                0,                             # header_order_anomaly
                1,                             # protocol_version_encoded
                np.random.uniform(0.7, 1.0),  # cipher_strength
                3,                             # tls_version_encoded
                1,                             # cert_valid
            ]
            normal_data.append(features)
        
        X = np.array(normal_data)
        self.train(X)
        print(f"Model trained with sample data - {X.shape[1]} features")
    def retrain(self):
        self._train_with_sample_data()