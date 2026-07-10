# integrations/__init__.py

"""
WOLFSTRIKE Integrations Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Third-party service integrations for notifications,
ticketing, and CI/CD pipeline automation.
"""

from integrations.slack_notify import SlackNotifier
from integrations.telegram_bot import TelegramNotifier
from integrations.discord_webhook import DiscordNotifier
from integrations.jira_integration import JiraIntegration
from integrations.ci_cd import CICDIntegration

__all__ = [
    'SlackNotifier',
    'TelegramNotifier',
    'DiscordNotifier',
    'JiraIntegration',
    'CICDIntegration',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'