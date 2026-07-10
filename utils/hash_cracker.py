# utils/hash_cracker.py

"""
Hash Identification and Cracking Utility
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Identifies hash types and provides basic cracking
capabilities for common hash formats.
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple


class HashCracker:
    """
    Hash identification and cracking utility.
    
    Identifies hash types by pattern and provides
    dictionary-based cracking for common formats.
    """
    
    HASH_PATTERNS = {
        'MD5': r'^[a-f0-9]{32}$',
        'SHA1': r'^[a-f0-9]{40}$',
        'SHA224': r'^[a-f0-9]{56}$',
        'SHA256': r'^[a-f0-9]{64}$',
        'SHA384': r'^[a-f0-9]{96}$',
        'SHA512': r'^[a-f0-9]{128}$',
        'MD4': r'^[a-f0-9]{32}$',
        'MySQL': r'^\*[a-f0-9]{40}$',
        'MySQL5': r'^\*[A-F0-9]{40}$',
        'NTLM': r'^[A-F0-9]{32}$',
        'LM': r'^[A-F0-9]{32}$',
        'bcrypt': r'^\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$',
        'SHA256-CRYPT': r'^\$5\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43}$',
        'SHA512-CRYPT': r'^\$6\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}$',
        'MD5-CRYPT': r'^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$',
        'APR1': r'^\$apr1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$',
        'CRC32': r'^[a-f0-9]{8}$',
        'RIPEMD160': r'^[a-f0-9]{40}$',
        'Whirlpool': r'^[a-f0-9]{128}$',
    }
    
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty',
        'admin', 'letmein', 'welcome', 'monkey',
        'dragon', 'master', 'pass123', 'Password1',
        'Admin123', 'Test123', 'changeme', 'secret',
        'iloveyou', 'sunshine', 'princess', 'football',
        'shadow', 'superman', 'michael', 'ninja',
        'mustang', 'batman', 'starwars', 'trustno1',
    ]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the hash cracker.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.wordlist: List[str] = self.config.get(
            'wordlist',
            self.COMMON_PASSWORDS
        )
        self.attempts = 0
        self.cracked = 0
    
    def identify_hash(self, hash_string: str) -> List[str]:
        """
        Identify possible hash types.
        
        Args:
            hash_string: Hash string to identify
            
        Returns:
            List of possible hash type names
        """
        possible_types = []
        
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if re.match(pattern, hash_string, re.IGNORECASE):
                possible_types.append(hash_type)
        
        if not possible_types:
            if len(hash_string) == 32:
                possible_types.append('MD5')
            elif len(hash_string) == 40:
                possible_types.append('SHA1')
            elif len(hash_string) == 64:
                possible_types.append('SHA256')
        
        return possible_types
    
    def hash_string(self, text: str, algorithm: str = 'md5') -> str:
        """
        Hash a string using specified algorithm.
        
        Args:
            text: Text to hash
            algorithm: Hash algorithm name
            
        Returns:
            Hash string
        """
        algorithm = algorithm.lower()
        
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
        }
        
        if algorithm in hash_functions:
            return hash_functions[algorithm](text.encode()).hexdigest()
        
        return ''
    
    def crack_hash(
        self,
        hash_string: str,
        hash_type: Optional[str] = None,
        wordlist: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Attempt to crack a hash using dictionary attack.
        
        Args:
            hash_string: Hash to crack
            hash_type: Hash type (auto-detect if None)
            wordlist: Custom wordlist to use
            
        Returns:
            Cracked password or None
        """
        if wordlist is None:
            wordlist = self.wordlist
        
        if hash_type is None:
            possible_types = self.identify_hash(hash_string)
            
            if not possible_types:
                return None
            
            hash_type = possible_types[0].lower()
        else:
            hash_type = hash_type.lower()
        
        if hash_type not in ['md5', 'sha1', 'sha256', 'sha512', 'md4']:
            return None
        
        for word in wordlist:
            self.attempts += 1
            
            computed_hash = self.hash_string(word, hash_type)
            
            if computed_hash.lower() == hash_string.lower():
                self.cracked += 1
                return word
            
            variations = [
                word.upper(),
                word.lower(),
                word.capitalize(),
                word + '123',
                word + '1',
                word + '!',
                '123' + word,
            ]
            
            for variation in variations:
                self.attempts += 1
                computed_variation = self.hash_string(variation, hash_type)
                
                if computed_variation.lower() == hash_string.lower():
                    self.cracked += 1
                    return variation
        
        return None
    
    def crack_hashes(
        self,
        hashes: List[str],
        hash_type: Optional[str] = None,
        wordlist: Optional[List[str]] = None
    ) -> Dict[str, Optional[str]]:
        """
        Crack multiple hashes.
        
        Args:
            hashes: List of hash strings
            hash_type: Hash type
            wordlist: Custom wordlist
            
        Returns:
            Dictionary mapping hash to cracked password
        """
        results = {}
        
        for hash_string in hashes:
            result = self.crack_hash(hash_string, hash_type, wordlist)
            results[hash_string] = result
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cracking statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_attempts': self.attempts,
            'cracked_count': self.cracked,
            'success_rate': (self.cracked / self.attempts * 100) if self.attempts > 0 else 0,
            'wordlist_size': len(self.wordlist),
        }