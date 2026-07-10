# modules/crawler/__init__.py

"""
WOLFSTRIKE Crawler Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced web crawling and spidering module for discovering
endpoints, mapping site structure, and analyzing content.
"""

from typing import Dict, List, Any, Optional

from modules.crawler.spider import WebSpider
from modules.crawler.ajax_crawler import AjaxCrawler
from modules.crawler.sitemap_gen import SitemapGenerator
from modules.crawler.link_checker import LinkChecker
from modules.crawler.wayback_machine import WaybackMachine

__all__ = [
    'WebSpider',
    'AjaxCrawler',
    'SitemapGenerator',
    'LinkChecker',
    'WaybackMachine',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all crawler modules.
    
    Args:
        target: Target URL
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    crawler_modules = [
        ('spider', WebSpider),
        ('ajax_crawler', AjaxCrawler),
        ('sitemap_gen', SitemapGenerator),
        ('link_checker', LinkChecker),
        ('wayback_machine', WaybackMachine),
    ]
    
    for name, module_class in crawler_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in crawler/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }