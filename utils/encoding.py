# utils/encoding.py

"""
Encoding and Decoding Utilities
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides encoding/decoding functions for various formats
including URL, Base64, Hex, Unicode, and HTML entities.
"""

import base64
import binascii
import html
import urllib.parse
from typing import Any, Optional


class EncodingUtils:
    """
    Encoding and decoding utility class.
    
    Provides static methods for common encoding
    operations used in security testing.
    """
    
    @staticmethod
    def url_encode(text: str, safe: str = '') -> str:
        """
        URL encode a string.
        
        Args:
            text: Text to encode
            safe: Characters to not encode
            
        Returns:
            URL encoded string
        """
        return urllib.parse.quote(text, safe=safe)
    
    @staticmethod
    def url_decode(text: str) -> str:
        """
        URL decode a string.
        
        Args:
            text: URL encoded text
            
        Returns:
            Decoded string
        """
        return urllib.parse.unquote(text)
    
    @staticmethod
    def double_url_encode(text: str) -> str:
        """
        Double URL encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Double URL encoded string
        """
        return EncodingUtils.url_encode(EncodingUtils.url_encode(text))
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """
        Base64 encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded string
        """
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """
        Base64 decode a string.
        
        Args:
            text: Base64 encoded text
            
        Returns:
            Decoded string
        """
        try:
            return base64.b64decode(text.encode()).decode()
        except (binascii.Error, UnicodeDecodeError):
            return ''
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """
        Hex encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Hex encoded string
        """
        return binascii.hexlify(text.encode()).decode()
    
    @staticmethod
    def hex_decode(text: str) -> str:
        """
        Hex decode a string.
        
        Args:
            text: Hex encoded text
            
        Returns:
            Decoded string
        """
        try:
            return binascii.unhexlify(text.encode()).decode()
        except (binascii.Error, UnicodeDecodeError):
            return ''
    
    @staticmethod
    def html_encode(text: str) -> str:
        """
        HTML entity encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            HTML encoded string
        """
        return html.escape(text)
    
    @staticmethod
    def html_decode(text: str) -> str:
        """
        HTML entity decode a string.
        
        Args:
            text: HTML encoded text
            
        Returns:
            Decoded string
        """
        return html.unescape(text)
    
    @staticmethod
    def unicode_encode(text: str) -> str:
        """
        Unicode escape a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Unicode escaped string
        """
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    @staticmethod
    def unicode_decode(text: str) -> str:
        """
        Unicode unescape a string.
        
        Args:
            text: Unicode escaped text
            
        Returns:
            Decoded string
        """
        try:
            return text.encode().decode('unicode-escape')
        except (UnicodeDecodeError, UnicodeEncodeError):
            return text
    
    @staticmethod
    def binary_encode(text: str) -> str:
        """
        Binary encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Binary encoded string
        """
        return ' '.join(f'{ord(c):08b}' for c in text)
    
    @staticmethod
    def rot13(text: str) -> str:
        """
        ROT13 encode/decode a string.
        
        Args:
            text: Text to transform
            
        Returns:
            ROT13 transformed string
        """
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def encode_all(text: str) -> dict:
        """
        Encode text in all available formats.
        
        Args:
            text: Text to encode
            
        Returns:
            Dictionary with all encodings
        """
        return {
            'url': EncodingUtils.url_encode(text),
            'double_url': EncodingUtils.double_url_encode(text),
            'base64': EncodingUtils.base64_encode(text),
            'hex': EncodingUtils.hex_encode(text),
            'html': EncodingUtils.html_encode(text),
            'unicode': EncodingUtils.unicode_encode(text),
            'binary': EncodingUtils.binary_encode(text),
            'rot13': EncodingUtils.rot13(text),
        }