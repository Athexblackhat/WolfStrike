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
from typing import Any, Optional, Dict, List, Tuple


class EncodingUtils:
    """
    Encoding and decoding utility class.
    
    Provides static methods for common encoding
    operations used in security testing.
    """
    
    _errors: List[str] = []
    
    @classmethod
    def _validate_input(cls, text: Any, method_name: str) -> bool:
        """
        Validate input before processing.
        
        Args:
            text: Input to validate
            method_name: Name of calling method
            
        Returns:
            True if input is valid
        """
        if text is None:
            cls._errors.append(f"{method_name}: Input is None")
            return False
        
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                cls._errors.append(f"{method_name}: Cannot convert input to string")
                return False
        
        return True
    
    @classmethod
    def _safe_encode(cls, text: str, encoding: str = 'utf-8', errors: str = 'ignore') -> bytes:
        """
        Safely encode string to bytes.
        
        Args:
            text: String to encode
            encoding: Encoding to use
            errors: Error handling strategy
            
        Returns:
            Encoded bytes or empty bytes on error
        """
        try:
            return text.encode(encoding, errors=errors)
        except (UnicodeEncodeError, AttributeError, TypeError):
            return b''
    
    @classmethod
    def _safe_decode(cls, data: bytes, encoding: str = 'utf-8', errors: str = 'ignore') -> str:
        """
        Safely decode bytes to string.
        
        Args:
            data: Bytes to decode
            encoding: Encoding to use
            errors: Error handling strategy
            
        Returns:
            Decoded string or empty string on error
        """
        if data is None:
            return ''
        
        try:
            return data.decode(encoding, errors=errors)
        except (UnicodeDecodeError, AttributeError, TypeError):
            return ''
    
    @classmethod
    def _normalize_unicode(cls, text: str) -> str:
        """
        Normalize unicode string.
        
        Args:
            text: String to normalize
            
        Returns:
            Normalized string
        """
        if not text:
            return text
        
        try:
            import unicodedata
            return unicodedata.normalize('NFKC', text)
        except ImportError:
            return text
    
    @classmethod
    def _safe_unicode_decode(cls, text: str) -> str:
        """
        Safely decode unicode escape sequences with multiple fallbacks.
        
        Args:
            text: String with unicode escapes
            
        Returns:
            Decoded string
        """
        if not text:
            return text
        
        # Method 1: Try unicode-escape
        try:
            return text.encode('utf-8').decode('unicode-escape')
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        
        # Method 2: Try raw_unicode_escape
        try:
            return text.encode('utf-8').decode('raw_unicode_escape')
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        
        # Method 3: Manual replacement for common escapes
        try:
            result = text
            # Replace \uXXXX patterns
            import re
            def replace_unicode(match):
                try:
                    code_point = int(match.group(1), 16)
                    return chr(code_point)
                except (ValueError, OverflowError):
                    return match.group(0)
            
            result = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, result)
            result = re.sub(r'\\U([0-9a-fA-F]{8})', replace_unicode, result)
            return result
        except Exception:
            pass
        
        # Return original if all methods fail
        return text
    
    @classmethod
    def _safe_base64_decode(cls, text: str) -> str:
        """
        Safely base64 decode with multiple fallbacks.
        
        Args:
            text: Base64 encoded text
            
        Returns:
            Decoded string or empty string on error
        """
        if not text:
            return ''
        
        # Try standard base64
        try:
            # Add padding if needed
            padding = 4 - (len(text) % 4)
            if padding != 4:
                text_padded = text + '=' * padding
            else:
                text_padded = text
            return base64.b64decode(text_padded.encode()).decode('utf-8', errors='ignore')
        except (binascii.Error, UnicodeDecodeError, ValueError, TypeError):
            pass
        
        # Try URL-safe base64
        try:
            text_safe = text.replace('-', '+').replace('_', '/')
            padding = 4 - (len(text_safe) % 4)
            if padding != 4:
                text_safe += '=' * padding
            return base64.b64decode(text_safe.encode()).decode('utf-8', errors='ignore')
        except (binascii.Error, UnicodeDecodeError, ValueError, TypeError):
            pass
        
        return ''
    
    @classmethod
    def _safe_hex_decode(cls, text: str) -> str:
        """
        Safely hex decode with multiple fallbacks.
        
        Args:
            text: Hex encoded text
            
        Returns:
            Decoded string or empty string on error
        """
        if not text:
            return ''
        
        # Remove whitespace and common separators
        text_clean = ''.join(text.split())
        text_clean = text_clean.replace(':', '').replace('-', '').replace(' ', '')
        
        # Ensure even length
        if len(text_clean) % 2 != 0:
            text_clean = '0' + text_clean
        
        try:
            return binascii.unhexlify(text_clean.encode()).decode('utf-8', errors='ignore')
        except (binascii.Error, UnicodeDecodeError, ValueError, TypeError):
            pass
        
        return ''
    
    @classmethod
    def get_errors(cls) -> List[str]:
        """
        Get accumulated errors.
        
        Returns:
            List of error messages
        """
        return cls._errors.copy()
    
    @classmethod
    def clear_errors(cls) -> None:
        """Clear accumulated errors."""
        cls._errors.clear()
    
    @staticmethod
    def is_valid_encoding(text: str, encoding_type: str) -> bool:
        """
        Check if a string is valid for a specific encoding type.
        
        Args:
            text: Text to check
            encoding_type: Type of encoding ('base64', 'hex', 'url', 'html')
            
        Returns:
            True if valid
        """
        if not text:
            return False
        
        if encoding_type == 'base64':
            import re
            # Check if it looks like base64
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
                return False
            try:
                EncodingUtils._safe_base64_decode(text)
                return True
            except Exception:
                return False
        
        elif encoding_type == 'hex':
            text_clean = ''.join(text.split()).replace(':', '').replace('-', '')
            if len(text_clean) % 2 != 0:
                return False
            try:
                int(text_clean, 16)
                return True
            except ValueError:
                return False
        
        elif encoding_type == 'url':
            try:
                urllib.parse.unquote(text)
                return True
            except Exception:
                return False
        
        elif encoding_type == 'html':
            try:
                html.unescape(text)
                return True
            except Exception:
                return False
        
        return False
    
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
        if not EncodingUtils._validate_input(text, 'url_encode'):
            return ''
        
        try:
            return urllib.parse.quote(text, safe=safe)
        except Exception:
            return text
    
    @staticmethod
    def url_decode(text: str) -> str:
        """
        URL decode a string.
        
        Args:
            text: URL encoded text
            
        Returns:
            Decoded string
        """
        if not EncodingUtils._validate_input(text, 'url_decode'):
            return ''
        
        try:
            return urllib.parse.unquote(text)
        except Exception:
            return text
    
    @staticmethod
    def double_url_encode(text: str) -> str:
        """
        Double URL encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Double URL encoded string
        """
        if not EncodingUtils._validate_input(text, 'double_url_encode'):
            return ''
        
        try:
            return EncodingUtils.url_encode(EncodingUtils.url_encode(text))
        except Exception:
            return text
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """
        Base64 encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded string
        """
        if not EncodingUtils._validate_input(text, 'base64_encode'):
            return ''
        
        try:
            return base64.b64encode(text.encode()).decode()
        except Exception:
            return ''
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """
        Base64 decode a string.
        
        Args:
            text: Base64 encoded text
            
        Returns:
            Decoded string
        """
        if not EncodingUtils._validate_input(text, 'base64_decode'):
            return ''
        
        return EncodingUtils._safe_base64_decode(text)
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """
        Hex encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Hex encoded string
        """
        if not EncodingUtils._validate_input(text, 'hex_encode'):
            return ''
        
        try:
            return binascii.hexlify(text.encode()).decode()
        except Exception:
            return ''
    
    @staticmethod
    def hex_decode(text: str) -> str:
        """
        Hex decode a string.
        
        Args:
            text: Hex encoded text
            
        Returns:
            Decoded string
        """
        if not EncodingUtils._validate_input(text, 'hex_decode'):
            return ''
        
        return EncodingUtils._safe_hex_decode(text)
    
    @staticmethod
    def html_encode(text: str) -> str:
        """
        HTML entity encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            HTML encoded string
        """
        if not EncodingUtils._validate_input(text, 'html_encode'):
            return ''
        
        try:
            return html.escape(text)
        except Exception:
            return text
    
    @staticmethod
    def html_decode(text: str) -> str:
        """
        HTML entity decode a string.
        
        Args:
            text: HTML encoded text
            
        Returns:
            Decoded string
        """
        if not EncodingUtils._validate_input(text, 'html_decode'):
            return ''
        
        try:
            return html.unescape(text)
        except Exception:
            return text
    
    @staticmethod
    def unicode_encode(text: str) -> str:
        """
        Unicode escape a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Unicode escaped string
        """
        if not EncodingUtils._validate_input(text, 'unicode_encode'):
            return ''
        
        try:
            return ''.join(f'\\u{ord(c):04x}' for c in text)
        except Exception:
            return text
    
    @staticmethod
    def unicode_decode(text: str) -> str:
        """
        Unicode unescape a string.
        
        Args:
            text: Unicode escaped text
            
        Returns:
            Decoded string
        """
        if not EncodingUtils._validate_input(text, 'unicode_decode'):
            return ''
        
        return EncodingUtils._safe_unicode_decode(text)
    
    @staticmethod
    def binary_encode(text: str) -> str:
        """
        Binary encode a string.
        
        Args:
            text: Text to encode
            
        Returns:
            Binary encoded string
        """
        if not EncodingUtils._validate_input(text, 'binary_encode'):
            return ''
        
        try:
            return ' '.join(f'{ord(c):08b}' for c in text)
        except Exception:
            return ''
    
    @staticmethod
    def rot13(text: str) -> str:
        """
        ROT13 encode/decode a string.
        
        Args:
            text: Text to transform
            
        Returns:
            ROT13 transformed string
        """
        if not EncodingUtils._validate_input(text, 'rot13'):
            return ''
        
        try:
            result = []
            for char in text:
                if 'a' <= char <= 'z':
                    result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(char)
            return ''.join(result)
        except Exception:
            return text
    
    @staticmethod
    def encode_all(text: str) -> Dict[str, str]:
        """
        Encode text in all available formats.
        
        Args:
            text: Text to encode
            
        Returns:
            Dictionary with all encodings
        """
        if not EncodingUtils._validate_input(text, 'encode_all'):
            return {}
        
        try:
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
        except Exception:
            return {}
    
    @staticmethod
    def encode_all_safe(text: str) -> Dict[str, str]:
        """
        Encode text in all available formats with error handling.
        
        Args:
            text: Text to encode
            
        Returns:
            Dictionary with all encodings or error messages
        """
        result = {}
        
        if not text:
            return {'error': 'Input is empty'}
        
        encodings = {
            'url': EncodingUtils.url_encode,
            'double_url': EncodingUtils.double_url_encode,
            'base64': EncodingUtils.base64_encode,
            'hex': EncodingUtils.hex_encode,
            'html': EncodingUtils.html_encode,
            'unicode': EncodingUtils.unicode_encode,
            'binary': EncodingUtils.binary_encode,
            'rot13': EncodingUtils.rot13,
        }
        
        for name, func in encodings.items():
            try:
                result[name] = func(text)
            except Exception as e:
                result[name] = f'ERROR: {str(e)}'
        
        return result
