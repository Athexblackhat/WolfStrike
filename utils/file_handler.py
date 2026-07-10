# utils/file_handler.py

"""
File Operations Handler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Handles file operations including reading, writing,
wordlist loading, and secure file handling.
"""

import os
import json
import csv
import gzip
import shutil
from typing import Dict, List, Any, Optional, Iterator


class FileHandler:
    """
    File operations utility.
    
    Provides file reading, writing, and management
    functions for various data formats.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the file handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.base_dir = self.config.get('base_dir', '.')
    
    def read_file(self, filepath: str, binary: bool = False) -> Optional[str]:
        """
        Read a file's contents.
        
        Args:
            filepath: Path to file
            binary: Whether to read in binary mode
            
        Returns:
            File contents or None
        """
        mode = 'rb' if binary else 'r'
        
        try:
            with open(filepath, mode, encoding=None if binary else 'utf-8') as f:
                return f.read()
        except (IOError, UnicodeDecodeError):
            return None
    
    def read_lines(self, filepath: str, strip: bool = True) -> List[str]:
        """
        Read file lines into a list.
        
        Args:
            filepath: Path to file
            strip: Whether to strip whitespace
            
        Returns:
            List of lines
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if strip:
                lines = [line.strip() for line in lines]
            
            return [line for line in lines if line]
            
        except (IOError, UnicodeDecodeError):
            return []
    
    def read_wordlist(self, filepath: str) -> List[str]:
        """
        Read a wordlist file.
        
        Args:
            filepath: Path to wordlist file
            
        Returns:
            List of words
        """
        words = []
        
        try:
            if filepath.endswith('.gz'):
                with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith('#'):
                            words.append(word)
            else:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith('#'):
                            words.append(word)
            
            return words
            
        except (IOError, UnicodeDecodeError, gzip.BadGzipFile):
            return []
    
    def write_file(
        self,
        filepath: str,
        content: str,
        append: bool = False,
        binary: bool = False
    ) -> bool:
        """
        Write content to a file.
        
        Args:
            filepath: Path to file
            content: Content to write
            append: Whether to append to file
            binary: Whether to write in binary mode
            
        Returns:
            True if successful
        """
        mode = 'ab' if (append and binary) else 'wb' if binary else 'a' if append else 'w'
        
        try:
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            
            with open(filepath, mode, encoding=None if binary else 'utf-8') as f:
                f.write(content)
            
            return True
            
        except (IOError, UnicodeEncodeError):
            return False
    
    def write_json(
        self,
        filepath: str,
        data: Any,
        pretty: bool = True
    ) -> bool:
        """
        Write data as JSON file.
        
        Args:
            filepath: Path to JSON file
            data: Data to serialize
            pretty: Whether to format with indentation
            
        Returns:
            True if successful
        """
        try:
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(data, f, ensure_ascii=False)
            
            return True
            
        except (IOError, TypeError):
            return False
    
    def read_json(self, filepath: str) -> Optional[Any]:
        """
        Read and parse a JSON file.
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            Parsed JSON data or None
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return None
    
    def write_csv(
        self,
        filepath: str,
        data: List[Dict[str, Any]],
        headers: Optional[List[str]] = None
    ) -> bool:
        """
        Write data as CSV file.
        
        Args:
            filepath: Path to CSV file
            data: List of row dictionaries
            headers: Column headers
            
        Returns:
            True if successful
        """
        if not data:
            return False
        
        try:
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            
            if headers is None:
                headers = list(data[0].keys())
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)
            
            return True
            
        except IOError:
            return False
    
    def read_csv(self, filepath: str) -> List[Dict[str, str]]:
        """
        Read and parse a CSV file.
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            List of row dictionaries
        """
        try:
            with open(filepath, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                return list(reader)
        except (IOError, csv.Error):
            return []
    
    def file_exists(self, filepath: str) -> bool:
        """
        Check if a file exists.
        
        Args:
            filepath: Path to file
            
        Returns:
            True if file exists
        """
        return os.path.isfile(filepath)
    
    def dir_exists(self, dirpath: str) -> bool:
        """
        Check if a directory exists.
        
        Args:
            dirpath: Path to directory
            
        Returns:
            True if directory exists
        """
        return os.path.isdir(dirpath)
    
    def create_dir(self, dirpath: str) -> bool:
        """
        Create a directory.
        
        Args:
            dirpath: Path to directory
            
        Returns:
            True if created
        """
        try:
            os.makedirs(dirpath, exist_ok=True)
            return True
        except OSError:
            return False
    
    def delete_file(self, filepath: str) -> bool:
        """
        Delete a file.
        
        Args:
            filepath: Path to file
            
        Returns:
            True if deleted
        """
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False
    
    def list_files(self, dirpath: str, extension: Optional[str] = None) -> List[str]:
        """
        List files in a directory.
        
        Args:
            dirpath: Path to directory
            extension: Filter by file extension
            
        Returns:
            List of file paths
        """
        if not os.path.isdir(dirpath):
            return []
        
        files = []
        
        for filename in os.listdir(dirpath):
            filepath = os.path.join(dirpath, filename)
            
            if os.path.isfile(filepath):
                if extension is None or filename.endswith(extension):
                    files.append(filepath)
        
        return sorted(files)
    
    def get_file_size(self, filepath: str) -> int:
        """
        Get file size in bytes.
        
        Args:
            filepath: Path to file
            
        Returns:
            File size in bytes
        """
        try:
            return os.path.getsize(filepath)
        except OSError:
            return 0
    
    def copy_file(self, source: str, destination: str) -> bool:
        """
        Copy a file.
        
        Args:
            source: Source file path
            destination: Destination file path
            
        Returns:
            True if copied
        """
        try:
            os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
            shutil.copy2(source, destination)
            return True
        except (IOError, OSError):
            return False
    
    def move_file(self, source: str, destination: str) -> bool:
        """
        Move a file.
        
        Args:
            source: Source file path
            destination: Destination file path
            
        Returns:
            True if moved
        """
        try:
            os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
            shutil.move(source, destination)
            return True
        except (IOError, OSError):
            return False