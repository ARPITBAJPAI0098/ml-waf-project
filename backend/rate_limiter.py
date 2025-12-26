"""
Rate Limiter using Redis
"""
import redis
import os
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
            logger.info("✅ Redis connected")
        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}")
            self.redis_client = None
    
    def check_rate(self, source_ip: str, path: str) -> Dict:
        """Check if IP is rate limited"""
        if not self.redis_client:
            return {
                "is_rate_limited": False,
                "requests_per_minute": 0
            }
        
        try:
            # Track requests per minute
            key = f"rate:{source_ip}:1min"
            
            # Increment counter
            count = self.redis_client.incr(key)
            
            # Set expiry on first request
            if count == 1:
                self.redis_client.expire(key, 60)
            
            # Rate limit threshold: 10 requests per minute
            is_limited = count > 10
            
            return {
                "is_rate_limited": is_limited,
                "requests_per_minute": count
            }
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return {
                "is_rate_limited": False,
                "requests_per_minute": 0
            }