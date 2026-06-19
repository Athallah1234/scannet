import time
import threading

class RateLimiter:
    """Thread-safe rate limiter to control scanning speed."""
    def __init__(self, rate_limit: int = 0):
        """
        rate_limit: actions per second. 0 means unlimited.
        """
        self.rate_limit = rate_limit
        self.delay = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self.last_time = time.time()
        self.lock = threading.Lock()

    def limit(self):
        if self.delay <= 0:
            return
        
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_time
            sleep_time = self.delay - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.last_time = time.time()
