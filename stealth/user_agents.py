# stealth/user_agents.py

"""
User-Agent Rotation Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages User-Agent rotation with extensive database
of real browser and device user agents.
"""

import random
from typing import Dict, List, Any, Optional


class UserAgentManager:
    """
    User-Agent rotation manager.
    
    Provides random User-Agent selection from a large
    database of real browser and device agents.
    """
    
    DEFAULT_USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    ]
    
    MOBILE_USER_AGENTS = [
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    ]
    
    BOT_USER_AGENTS = [
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    ]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the User-Agent manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.custom_agents = self.config.get('custom_agents', [])
        self.use_mobile = self.config.get('use_mobile', False)
        self.use_bot = self.config.get('use_bot', False)
        self.current_agent = self.config.get(
            'default_agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        self._build_agent_pool()
    
    def _build_agent_pool(self) -> None:
        """Build the complete user agent pool."""
        self.agent_pool = self.DEFAULT_USER_AGENTS.copy()
        
        if self.use_mobile:
            self.agent_pool.extend(self.MOBILE_USER_AGENTS)
        
        if self.use_bot:
            self.agent_pool.extend(self.BOT_USER_AGENTS)
        
        if self.custom_agents:
            self.agent_pool.extend(self.custom_agents)
    
    def get_random(self) -> str:
        """
        Get a random User-Agent string.
        
        Returns:
            Random User-Agent string
        """
        if not self.agent_pool:
            return self.current_agent
        
        self.current_agent = random.choice(self.agent_pool)
        return self.current_agent
    
    def get_desktop(self) -> str:
        """
        Get a random desktop browser User-Agent.
        
        Returns:
            Desktop User-Agent string
        """
        desktop_agents = [
            ua for ua in self.DEFAULT_USER_AGENTS
            if 'Mobile' not in ua and 'Android' not in ua and 'bot' not in ua.lower()
        ]
        
        if desktop_agents:
            return random.choice(desktop_agents)
        
        return self.get_random()
    
    def get_mobile(self) -> str:
        """
        Get a random mobile device User-Agent.
        
        Returns:
            Mobile User-Agent string
        """
        if self.MOBILE_USER_AGENTS:
            return random.choice(self.MOBILE_USER_AGENTS)
        
        return self.get_random()
    
    def get_bot(self) -> str:
        """
        Get a random bot/crawler User-Agent.
        
        Returns:
            Bot User-Agent string
        """
        if self.BOT_USER_AGENTS:
            return random.choice(self.BOT_USER_AGENTS)
        
        return self.get_random()
    
    def add_agent(self, user_agent: str) -> None:
        """
        Add a custom User-Agent to the pool.
        
        Args:
            user_agent: User-Agent string to add
        """
        if user_agent and user_agent not in self.agent_pool:
            self.agent_pool.append(user_agent)
    
    def get_all(self) -> List[str]:
        """
        Get all available User-Agent strings.
        
        Returns:
            List of all User-Agent strings
        """
        return self.agent_pool.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get User-Agent pool statistics.
        
        Returns:
            Dictionary with pool statistics
        """
        return {
            'total_agents': len(self.agent_pool),
            'desktop_count': len([
                ua for ua in self.DEFAULT_USER_AGENTS
                if 'Mobile' not in ua and 'Android' not in ua
            ]),
            'mobile_count': len(self.MOBILE_USER_AGENTS),
            'bot_count': len(self.BOT_USER_AGENTS),
            'current_agent': self.current_agent,
        }