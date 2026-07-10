# utils/request_handler.py

"""
HTTP Request Handler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced HTTP request handler with session management,
retry logic, proxy support, and error handling.
"""

import time
import random
from typing import Dict, Any, Optional, Tuple

import requests
from requests.exceptions import (
    RequestException,
    ConnectionError,
    Timeout,
    TooManyRedirects,
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RequestHandler:
    """
    Advanced HTTP request handler.
    
    Provides session management, automatic retries,
    proxy support, and comprehensive error handling.
    """
    
    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 1.0
    STATUS_FORCELIST = [429, 500, 502, 503, 504]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the request handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', self.DEFAULT_TIMEOUT)
        self.max_retries = self.config.get('max_retries', self.MAX_RETRIES)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.allow_redirects = self.config.get('allow_redirects', True)
        self.proxy = self.config.get('proxy', None)
        self.user_agent = self.config.get(
            'user_agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        self.session = self._create_session()
        self.request_count = 0
        self.error_count = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
    
    def _create_session(self) -> requests.Session:
        """
        Create a configured requests session.
        
        Returns:
            Configured Session object
        """
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.BACKOFF_FACTOR,
            status_forcelist=self.STATUS_FORCELIST,
            allowed_methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if self.proxy:
            session.proxies.update({
                'http': self.proxy,
                'https': self.proxy,
            })
        
        return session
    
    def update_headers(self, headers: Dict[str, str]) -> None:
        """
        Update session headers.
        
        Args:
            headers: Dictionary of headers to add/update
        """
        self.session.headers.update(headers)
    
    def set_proxy(self, proxy_url: str) -> None:
        """
        Set proxy for session.
        
        Args:
            proxy_url: Proxy URL string
        """
        self.proxy = proxy_url
        self.session.proxies.update({
            'http': proxy_url,
            'https': proxy_url,
        })
    
    def set_user_agent(self, user_agent: str) -> None:
        """
        Set User-Agent header.
        
        Args:
            user_agent: User-Agent string
        """
        self.user_agent = user_agent
        self.session.headers.update({'User-Agent': user_agent})
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send GET request.
        
        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('GET', url, params=params, headers=headers, timeout=timeout, **kwargs)
    
    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send POST request.
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('POST', url, data=data, json=json, headers=headers, timeout=timeout, **kwargs)
    
    def put(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send PUT request.
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('PUT', url, data=data, json=json, headers=headers, timeout=timeout, **kwargs)
    
    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send DELETE request.
        
        Args:
            url: Target URL
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('DELETE', url, headers=headers, timeout=timeout, **kwargs)
    
    def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send HEAD request.
        
        Args:
            url: Target URL
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('HEAD', url, headers=headers, timeout=timeout, **kwargs)
    
    def options(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send OPTIONS request.
        
        Args:
            url: Target URL
            headers: Additional headers
            timeout: Request timeout
            
        Returns:
            Response object
        """
        return self._make_request('OPTIONS', url, headers=headers, timeout=timeout, **kwargs)
    
    def _make_request(
        self,
        method: str,
        url: str,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make HTTP request with error handling.
        
        Args:
            method: HTTP method
            url: Target URL
            timeout: Request timeout
            
        Returns:
            Response object
        """
        request_timeout = timeout or self.timeout
        
        self.request_count += 1
        
        try:
            response = self.session.request(
                method,
                url,
                timeout=request_timeout,
                verify=self.verify_ssl,
                allow_redirects=self.allow_redirects,
                **kwargs
            )
            
            if response.content:
                self.total_bytes_received += len(response.content)
            
            return response
            
        except ConnectionError as e:
            self.error_count += 1
            raise ConnectionError(f"Connection failed for {url}: {str(e)}")
        except Timeout as e:
            self.error_count += 1
            raise Timeout(f"Request timed out for {url}: {str(e)}")
        except TooManyRedirects as e:
            self.error_count += 1
            raise TooManyRedirects(f"Too many redirects for {url}: {str(e)}")
        except RequestException as e:
            self.error_count += 1
            raise RequestException(f"Request failed for {url}: {str(e)}")
    
    def reset_session(self) -> None:
        """Reset session to fresh state."""
        self.session.close()
        self.session = self._create_session()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get request statistics.
        
        Returns:
            Dictionary with request statistics
        """
        return {
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'error_rate': (self.error_count / self.request_count * 100) if self.request_count > 0 else 0,
            'total_bytes_sent': self.total_bytes_sent,
            'total_bytes_received': self.total_bytes_received,
            'current_proxy': self.proxy,
            'current_user_agent': self.user_agent,
        }
    
    def close(self) -> None:
        """Close the session."""
        self.session.close()