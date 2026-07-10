# modules/network/bgp_info.py

"""
BGP Information Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Gathers BGP routing information including prefixes,
AS paths, and upstream providers for network analysis.
"""

import json
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError


class BGPInfo:
    """
    BGP routing information gatherer.
    
    Queries BGP data sources for prefix announcements,
    AS paths, and network topology information.
    """
    
    BGP_SOURCES = {
        'bgpview': 'https://api.bgpview.io/ip/{target}',
        'bgpview_asn': 'https://api.bgpview.io/asn/{asn}',
        'bgpview_prefix': 'https://api.bgpview.io/prefix/{prefix}',
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the BGP info module.
        
        Args:
            target: Target IP or ASN
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        
        self.errors: List[str] = []
    
    def query_bgpview_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Query BGPView for IP information.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with BGP data or None
        """
        try:
            url = self.BGP_SOURCES['bgpview'].format(target=ip)
            request = Request(url, headers={'User-Agent': 'WOLFSTRIKE/1.0'})
            
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get('status') == 'ok':
                    return data.get('data', {})
            
            return None
            
        except URLError as e:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            self.errors.append(f"BGPView IP query failed: {str(e)}")
            return None
    
    def query_bgpview_asn(self, asn: str) -> Optional[Dict[str, Any]]:
        """
        Query BGPView for ASN information.
        
        Args:
            asn: ASN number
            
        Returns:
            Dictionary with ASN data or None
        """
        try:
            url = self.BGP_SOURCES['bgpview_asn'].format(asn=asn)
            request = Request(url, headers={'User-Agent': 'WOLFSTRIKE/1.0'})
            
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get('status') == 'ok':
                    return data.get('data', {})
            
            return None
            
        except URLError:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            self.errors.append(f"BGPView ASN query failed: {str(e)}")
            return None
    
    def extract_prefixes(self, bgp_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract prefix information from BGP data.
        
        Args:
            bgp_data: BGP data dictionary
            
        Returns:
            List of prefix dictionaries
        """
        prefixes = []
        
        ip_data = bgp_data.get('ip', {})
        if ip_data:
            prefix_list = ip_data.get('prefixes', [])
            
            for prefix in prefix_list:
                prefixes.append({
                    'prefix': prefix.get('prefix', ''),
                    'ip': prefix.get('ip', ''),
                    'cidr': prefix.get('cidr', ''),
                    'country_code': prefix.get('country_code', ''),
                    'description': prefix.get('description', ''),
                    'asn': prefix.get('asn', {}).get('asn', ''),
                    'asn_name': prefix.get('asn', {}).get('name', ''),
                })
        
        return prefixes
    
    def extract_upstreams(self, asn_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract upstream provider information.
        
        Args:
            asn_data: ASN data dictionary
            
        Returns:
            List of upstream provider dictionaries
        """
        upstreams = []
        
        prefixes_v4 = asn_data.get('prefixes', {}).get('ipv4', [])
        
        seen_asns = set()
        
        for prefix_data in prefixes_v4:
            upstreams_list = prefix_data.get('upstreams', [])
            
            for upstream in upstreams_list:
                asn = upstream.get('asn', '')
                
                if asn and asn not in seen_asns:
                    seen_asns.add(asn)
                    upstreams.append({
                        'asn': asn,
                        'name': upstream.get('name', ''),
                        'description': upstream.get('description', ''),
                        'country_code': upstream.get('country_code', ''),
                    })
        
        return upstreams
    
    def run(self) -> Dict[str, Any]:
        """
        Run BGP information gathering.
        
        Returns:
            Dictionary with BGP data
        """
        bgp_data = self.query_bgpview_ip(self.target)
        
        if not bgp_data:
            return {
                'findings': [],
                'errors': self.errors,
                'ip': self.target,
            }
        
        prefixes = self.extract_prefixes(bgp_data)
        
        asn_info = None
        upstreams = []
        
        if prefixes:
            first_prefix = prefixes[0]
            asn = first_prefix.get('asn', '')
            
            if asn:
                asn_data = self.query_bgpview_asn(asn)
                
                if asn_data:
                    asn_info = {
                        'asn': asn_data.get('asn', ''),
                        'name': asn_data.get('name', ''),
                        'description': asn_data.get('description', ''),
                        'country_code': asn_data.get('country_code', ''),
                    }
                    
                    upstreams = self.extract_upstreams(asn_data)
        
        findings = []
        
        if prefixes:
            findings.append({
                'type': 'BGP Prefix Information',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(prefixes)} BGP prefixes',
                'evidence': {
                    'prefixes': [p['prefix'] for p in prefixes[:10]],
                    'asn': asn_info,
                    'upstreams': upstreams[:5] if upstreams else [],
                },
                'remediation': 'Review BGP announcements for unauthorized prefixes',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'ip': self.target,
            'prefixes': prefixes,
            'asn_info': asn_info,
            'upstreams': upstreams,
        }