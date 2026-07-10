# cli/tables.py

"""
Table Formatter for Terminal Output
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides formatted table output for scan results,
vulnerability listings, and data display in terminal.
"""

from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


class TableStyle(Enum):
    """Styles for table borders."""
    SIMPLE = "simple"
    GRID = "grid"
    MINIMAL = "minimal"
    HEADER_ONLY = "header_only"
    COMPACT = "compact"


class Alignment(Enum):
    """Column alignment options."""
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"


@dataclass
class Column:
    """Defines a table column."""
    name: str
    key: str
    width: Optional[int] = None
    alignment: Alignment = Alignment.LEFT
    formatter: Optional[callable] = None
    visible: bool = True
    sortable: bool = False


@dataclass
class TableConfig:
    """Configuration for table formatting."""
    style: TableStyle = TableStyle.GRID
    max_width: int = 120
    padding: int = 1
    title: Optional[str] = None
    show_row_numbers: bool = False
    sort_by: Optional[str] = None
    sort_reverse: bool = False
    truncate: bool = True
    truncate_marker: str = "..."


class TableFormatter:
    """
    Advanced table formatter for terminal output.
    
    Creates well-formatted tables with various styles,
    alignment options, and automatic width calculation.
    """
    
    def __init__(self, config: Optional[TableConfig] = None):
        """
        Initialize the table formatter.
        
        Args:
            config: Table configuration
        """
        self.config = config or TableConfig()
        self.columns: List[Column] = []
        self.rows: List[Dict[str, Any]] = []
    
    def add_column(
        self,
        name: str,
        key: str,
        width: Optional[int] = None,
        alignment: Alignment = Alignment.LEFT,
        formatter: Optional[callable] = None,
        sortable: bool = False
    ) -> None:
        """
        Add a column definition.
        
        Args:
            name: Column display name
            key: Key for accessing row data
            width: Fixed column width (auto-calculated if None)
            alignment: Text alignment
            formatter: Optional value formatter function
            sortable: Whether column is sortable
        """
        column = Column(
            name=name,
            key=key,
            width=width,
            alignment=alignment,
            formatter=formatter,
            sortable=sortable
        )
        self.columns.append(column)
    
    def add_row(self, row_data: Dict[str, Any]) -> None:
        """
        Add a data row.
        
        Args:
            row_data: Dictionary with row data
        """
        self.rows.append(row_data)
    
    def add_rows(self, rows_data: List[Dict[str, Any]]) -> None:
        """
        Add multiple data rows.
        
        Args:
            rows_data: List of row data dictionaries
        """
        self.rows.extend(rows_data)
    
    def _calculate_column_widths(self) -> Dict[str, int]:
        """
        Calculate optimal column widths.
        
        Returns:
            Dictionary mapping column keys to widths
        """
        widths: Dict[str, int] = {}
        
        for column in self.columns:
            if not column.visible:
                continue
            
            if column.width:
                widths[column.key] = column.width
                continue
            
            header_width = len(column.name)
            max_data_width = 0
            
            for row in self.rows:
                value = row.get(column.key, "")
                if column.formatter:
                    value = column.formatter(value)
                str_value = str(value)
                max_data_width = max(max_data_width, len(str_value))
            
            widths[column.key] = max(header_width, max_data_width) + (self.config.padding * 2)
        
        terminal_width = self._get_terminal_width()
        max_table_width = min(terminal_width - 2, self.config.max_width)
        
        total_width = sum(widths.values())
        if total_width > max_table_width:
            scale_factor = max_table_width / total_width
            for key in widths:
                widths[key] = max(5, int(widths[key] * scale_factor))
        
        return widths
    
    def _get_terminal_width(self) -> int:
        """
        Get terminal width.
        
        Returns:
            Terminal width in characters
        """
        try:
            import shutil
            return shutil.get_terminal_size().columns
        except Exception:
            return 120
    
    def _format_value(self, value: Any, width: int, alignment: Alignment) -> str:
        """
        Format a single value for display.
        
        Args:
            value: Value to format
            width: Column width
            alignment: Text alignment
            
        Returns:
            Formatted string
        """
        str_value = str(value) if value is not None else ""
        
        if len(str_value) > width:
            if self.config.truncate:
                marker = self.config.truncate_marker
                str_value = str_value[:width - len(marker)] + marker
            else:
                str_value = str_value[:width]
        
        if alignment == Alignment.RIGHT:
            return str_value.rjust(width)
        elif alignment == Alignment.CENTER:
            return str_value.center(width)
        else:
            return str_value.ljust(width)
    
    def _build_separator(self, widths: Dict[str, int], char: str) -> str:
        """
        Build a separator line.
        
        Args:
            widths: Column widths
            char: Separator character
            
        Returns:
            Separator string
        """
        if self.config.style == TableStyle.GRID:
            parts = []
            for column in self.columns:
                if not column.visible:
                    continue
                parts.append(char * (widths[column.key] + 2))
            return "+" + "+".join(parts) + "+"
        
        elif self.config.style == TableStyle.SIMPLE:
            parts = []
            for column in self.columns:
                if not column.visible:
                    continue
                parts.append(char * (widths[column.key] + 2))
            return "-".join(parts)
        
        return ""
    
    def _build_row(
        self,
        values: Dict[str, Any],
        widths: Dict[str, int],
        is_header: bool = False
    ) -> str:
        """
        Build a table row.
        
        Args:
            values: Row values
            widths: Column widths
            is_header: Whether this is a header row
            
        Returns:
            Formatted row string
        """
        separator = " | " if self.config.style in [TableStyle.GRID, TableStyle.SIMPLE] else " "
        
        parts = []
        for column in self.columns:
            if not column.visible:
                continue
            
            if is_header:
                value = column.name
            else:
                value = values.get(column.key, "")
                if column.formatter:
                    value = column.formatter(value)
            
            formatted = self._format_value(value, widths[column.key], column.alignment)
            parts.append(formatted)
        
        row_str = separator.join(parts)
        
        if self.config.style == TableStyle.GRID:
            return "| " + row_str + " |"
        
        return row_str
    
    def render(self) -> str:
        """
        Render the complete table.
        
        Returns:
            Formatted table string
        """
        if not self.columns or not self.rows:
            return ""
        
        if self.config.sort_by:
            sort_key = self.config.sort_by
            self.rows.sort(
                key=lambda x: x.get(sort_key, ""),
                reverse=self.config.sort_reverse
            )
        
        widths = self._calculate_column_widths()
        
        lines: List[str] = []
        
        if self.config.title:
            total_width = sum(widths.values()) + (len(widths) * 3) - 1
            lines.append(self.config.title.center(total_width))
            lines.append("")
        
        if self.config.style in [TableStyle.GRID, TableStyle.SIMPLE]:
            separator = self._build_separator(widths, "-")
            lines.append(separator)
        
        header = self._build_row({}, widths, is_header=True)
        lines.append(header)
        
        if self.config.style in [TableStyle.GRID, TableStyle.HEADER_ONLY]:
            separator = self._build_separator(widths, "=")
            lines.append(separator)
        
        for i, row in enumerate(self.rows):
            if self.config.show_row_numbers:
                row = row.copy()
                row['_row_number'] = i + 1
            
            data_row = self._build_row(row, widths)
            lines.append(data_row)
            
            if self.config.style == TableStyle.COMPACT:
                continue
        
        if self.config.style in [TableStyle.GRID, TableStyle.SIMPLE]:
            separator = self._build_separator(widths, "-")
            lines.append(separator)
        
        return "\n".join(lines)
    
    def print_table(self) -> None:
        """Print the formatted table to stdout."""
        print(self.render())
    
    def clear(self) -> None:
        """Clear all columns and rows."""
        self.columns.clear()
        self.rows.clear()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert table data to dictionary.
        
        Returns:
            Dictionary with columns and rows
        """
        return {
            'columns': [
                {
                    'name': col.name,
                    'key': col.key,
                    'alignment': col.alignment.value
                }
                for col in self.columns
            ],
            'rows': self.rows
        }
    
    def to_csv(self, delimiter: str = ",") -> str:
        """
        Convert table to CSV format.
        
        Args:
            delimiter: CSV delimiter character
            
        Returns:
            CSV formatted string
        """
        lines = []
        
        header = delimiter.join(
            f'"{col.name}"' for col in self.columns if col.visible
        )
        lines.append(header)
        
        for row in self.rows:
            values = []
            for col in self.columns:
                if not col.visible:
                    continue
                value = row.get(col.key, "")
                if col.formatter:
                    value = col.formatter(value)
                values.append(f'"{str(value)}"')
            lines.append(delimiter.join(values))
        
        return "\n".join(lines)