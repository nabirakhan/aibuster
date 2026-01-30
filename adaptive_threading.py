#!/usr/bin/env python3
import time
import threading
import requests
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import deque
from queue import Queue, Empty
import statistics
import logging

@dataclass
class PerformanceMetrics:
    """Track performance metrics for adaptive tuning"""
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    error_rates: deque = field(default_factory=lambda: deque(maxlen=100))
    success_rates: deque = field(default_factory=lambda: deque(maxlen=100))
    rate_limit_hits: int = 0
    timeout_count: int = 0
    connection_errors: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    
    def add_response(self, response_time: float, success: bool, error_type: Optional[str] = None):
        """Record a response"""
        self.response_times.append(response_time)
        self.total_requests += 1
        
        if success:
            self.successful_requests += 1
            self.success_rates.append(1)
            self.error_rates.append(0)
        else:
            self.success_rates.append(0)
            self.error_rates.append(1)
            
            if error_type == 'timeout':
                self.timeout_count += 1
            elif error_type == 'connection':
                self.connection_errors += 1
            elif error_type == 'rate_limit':
                self.rate_limit_hits += 1
    
    def get_avg_response_time(self) -> float:
        """Get average response time"""
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    def get_error_rate(self) -> float:
        """Get current error rate"""
        if not self.error_rates:
            return 0.0
        return statistics.mean(self.error_rates)
    
    def get_success_rate(self) -> float:
        """Get current success rate"""
        if not self.success_rates:
            return 0.0
        return statistics.mean(self.success_rates)
    
    def get_p95_response_time(self) -> float:
        """Get 95th percentile response time"""
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        index = int(len(sorted_times) * 0.95)
        return sorted_times[min(index, len(sorted_times) - 1)]

class AdaptiveThreadPool:
    """Self-optimizing thread pool that adjusts based on performance"""
    
    def __init__(self, initial_threads: int = 10, min_threads: int = 1, 
                 max_threads: int = 50, auto_adjust: bool = True):
        self.current_threads = initial_threads
        self.min_threads = min_threads
        self.max_threads = max_threads
        self.auto_adjust = auto_adjust
        
        self.metrics = PerformanceMetrics()
        self.logger = logging.getLogger(__name__)
        
        self.adjustment_interval = 10
        self.requests_since_adjustment = 0
        
        self.target_response_time = 2.0
        self.max_error_rate = 0.15
        
        self.lock = threading.Lock()
        
        self.performance_history = deque(maxlen=10)
        
    def should_increase_threads(self) -> bool:
        """Determine if we should increase thread count"""
        if self.current_threads >= self.max_threads:
            return False
        
        avg_response_time = self.metrics.get_avg_response_time()
        error_rate = self.metrics.get_error_rate()
        
        if avg_response_time < self.target_response_time * 0.5 and error_rate < 0.05:
            self.logger.info(f"Fast responses ({avg_response_time:.2f}s), low errors ({error_rate:.2%}) - increasing threads")
            return True
        
        if self.current_threads < self.max_threads and self.metrics.total_requests > 20:
            success_rate = self.metrics.get_success_rate()
            if success_rate > 0.9 and avg_response_time > 0:
                self.logger.info(f"High success rate ({success_rate:.2%}) - increasing threads")
                return True
        
        return False
    
    def should_decrease_threads(self) -> bool:
        """Determine if we should decrease thread count"""
        if self.current_threads <= self.min_threads:
            return False
        
        error_rate = self.metrics.get_error_rate()
        avg_response_time = self.metrics.get_avg_response_time()
        
        if error_rate > self.max_error_rate:
            self.logger.warning(f"High error rate ({error_rate:.2%}) - decreasing threads")
            return True
        
        if self.metrics.timeout_count > 5:
            self.logger.warning(f"Multiple timeouts ({self.metrics.timeout_count}) - decreasing threads")
            return True
        
        if self.metrics.rate_limit_hits > 3:
            self.logger.warning(f"Rate limit hits ({self.metrics.rate_limit_hits}) - decreasing threads")
            return True
        
        if avg_response_time > self.target_response_time * 2:
            self.logger.warning(f"Slow responses ({avg_response_time:.2f}s) - decreasing threads")
            return True
        
        return False
    
    def adjust_threads(self) -> int:
        """Adjust thread count based on performance"""
        if not self.auto_adjust:
            return self.current_threads
        
        with self.lock:
            old_threads = self.current_threads
            
            if self.should_increase_threads():
                increment = max(1, self.current_threads // 5)
                self.current_threads = min(self.current_threads + increment, self.max_threads)
            
            elif self.should_decrease_threads():
                decrement = max(1, self.current_threads // 4)
                self.current_threads = max(self.current_threads - decrement, self.min_threads)
                
                self.metrics.timeout_count = 0
                self.metrics.rate_limit_hits = 0
            
            if old_threads != self.current_threads:
                self.logger.info(f"Thread count adjusted: {old_threads} → {self.current_threads}")
                self._record_performance()
            
            return self.current_threads
    
    def _record_performance(self):
        """Record current performance snapshot"""
        snapshot = {
            'threads': self.current_threads,
            'avg_response_time': self.metrics.get_avg_response_time(),
            'error_rate': self.metrics.get_error_rate(),
            'success_rate': self.metrics.get_success_rate(),
            'timestamp': time.time()
        }
        self.performance_history.append(snapshot)
    
    def record_request(self, response_time: float, success: bool, error_type: Optional[str] = None):
        """Record a request for adaptive learning"""
        with self.lock:
            self.metrics.add_response(response_time, success, error_type)
            self.requests_since_adjustment += 1
            
            if self.requests_since_adjustment >= self.adjustment_interval:
                self.adjust_threads()
                self.requests_since_adjustment = 0
    
    def get_current_threads(self) -> int:
        """Get current thread count"""
        return self.current_threads
    
    def get_statistics(self) -> Dict:
        """Get performance statistics"""
        return {
            'current_threads': self.current_threads,
            'min_threads': self.min_threads,
            'max_threads': self.max_threads,
            'total_requests': self.metrics.total_requests,
            'successful_requests': self.metrics.successful_requests,
            'avg_response_time': self.metrics.get_avg_response_time(),
            'p95_response_time': self.metrics.get_p95_response_time(),
            'error_rate': self.metrics.get_error_rate(),
            'success_rate': self.metrics.get_success_rate(),
            'timeouts': self.metrics.timeout_count,
            'connection_errors': self.metrics.connection_errors,
            'rate_limit_hits': self.metrics.rate_limit_hits,
            'performance_history': list(self.performance_history)
        }

class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on server responses"""
    
    def __init__(self, initial_rate: Optional[int] = None, auto_detect: bool = True):
        self.requests_per_second = initial_rate
        self.auto_detect = auto_detect
        self.logger = logging.getLogger(__name__)
        
        self.request_times = deque(maxlen=100)
        self.rate_limit_responses = []
        
        self.lock = threading.Lock()
        
        self.backoff_multiplier = 1.0
        self.max_backoff = 5.0
    
    def wait(self):
        """Wait if necessary to respect rate limit"""
        if not self.requests_per_second:
            return
        
        with self.lock:
            now = time.time()
            
            window = 1.0 / (self.requests_per_second / self.backoff_multiplier)
            
            if self.request_times:
                time_since_last = now - self.request_times[-1]
                if time_since_last < window:
                    sleep_time = window - time_since_last
                    time.sleep(sleep_time)
            
            self.request_times.append(time.time())
    
    def record_rate_limit(self, retry_after: Optional[int] = None):
        """Record a rate limit response"""
        with self.lock:
            self.rate_limit_responses.append(time.time())
            
            if retry_after:
                self.logger.warning(f"Rate limited. Retry-After: {retry_after}s")
                time.sleep(retry_after)
            
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, self.max_backoff)
            self.logger.warning(f"Increasing backoff to {self.backoff_multiplier:.2f}x")
    
    def record_success(self):
        """Record successful request to gradually reduce backoff"""
        with self.lock:
            if self.backoff_multiplier > 1.0:
                self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.95)
    
    def detect_rate_limit(self, status_code: int, headers: dict) -> bool:
        """Detect if response indicates rate limiting"""
        if status_code == 429:
            retry_after = headers.get('Retry-After')
            if retry_after:
                try:
                    retry_after = int(retry_after)
                except:
                    retry_after = 60
            else:
                retry_after = 60
            
            self.record_rate_limit(retry_after)
            return True
        
        if status_code == 503:
            rate_limit_headers = ['X-RateLimit-Limit', 'X-Rate-Limit-Remaining', 'RateLimit-Limit']
            if any(h in headers for h in rate_limit_headers):
                self.record_rate_limit(30)
                return True
        
        return False
    
    def get_statistics(self) -> Dict:
        """Get rate limiter statistics"""
        return {
            'requests_per_second': self.requests_per_second,
            'backoff_multiplier': self.backoff_multiplier,
            'rate_limit_hits': len(self.rate_limit_responses),
            'current_rate': self.requests_per_second / self.backoff_multiplier if self.requests_per_second else None
        }

class SmartConnectionPool:
    """Connection pool with intelligent reuse and management"""
    
    def __init__(self, max_connections: int = 20):
        self.max_connections = max_connections
        self.sessions: Dict[int, requests.Session] = {}
        self.session_usage: Dict[int, int] = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def get_session(self) -> requests.Session:
        """Get or create a session for current thread"""
        thread_id = threading.get_ident()
        
        with self.lock:
            if thread_id not in self.sessions:
                if len(self.sessions) >= self.max_connections:
                    least_used = min(self.session_usage.items(), key=lambda x: x[1])[0]
                    self.sessions[least_used].close()
                    del self.sessions[least_used]
                    del self.session_usage[least_used]
                
                session = requests.Session()
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=10,
                    pool_maxsize=20,
                    max_retries=3,
                    pool_block=False
                )
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                
                self.sessions[thread_id] = session
                self.session_usage[thread_id] = 0
                
                self.logger.debug(f"Created new session for thread {thread_id}")
            
            self.session_usage[thread_id] += 1
            return self.sessions[thread_id]
    
    def cleanup(self):
        """Clean up all sessions"""
        with self.lock:
            for session in self.sessions.values():
                try:
                    session.close()
                except:
                    pass
            self.sessions.clear()
            self.session_usage.clear()
    
    def get_statistics(self) -> Dict:
        """Get pool statistics"""
        return {
            'active_sessions': len(self.sessions),
            'max_connections': self.max_connections,
            'total_requests': sum(self.session_usage.values())
        }