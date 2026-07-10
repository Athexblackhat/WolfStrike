# modules/crawler/__init__.py

"""
WOLFSTRIKE Crawler Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced web crawling and spidering module for discovering
endpoints, mapping site structure, and analyzing content.
"""

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