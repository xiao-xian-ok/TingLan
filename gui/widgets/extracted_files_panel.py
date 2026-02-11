# 提取文件面板

import os
import shutil
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QHeaderView,
    QPushButton, QFrame, QMenu, QMessageBox, QFileDialog,
    QAbstractItemView
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor, QAction, QCursor

from models.detection_result import ExtractedFile
from gui.styles.colors import (
    PRIMARY, PRIMARY_LIGHT, BG_PRIMARY, BG_SECONDARY,
    BORDER, TEXT_PRIMARY, TEXT_SECONDARY, SUCCESS, WARNING
)


# File type icons (using emoji for simplicity)
FILE_TYPE_ICONS = {
    "image": "picture",
    "code": "document-code",
    "document": "document-text",
    "archive": "archive",
    "text": "document",
    "other": "document",
}


def get_file_icon(file_type: str, file_name: str) -> str:
    """Get appropriate icon/emoji for file type"""
    ext = os.path.splitext(file_name.lower())[1]

    # Script/code files
    if ext in ('.php', '.jsp', '.asp', '.aspx', '.py', '.js', '.sh', '.bat'):
        return "script"
    # Executable
    elif ext in ('.exe', '.dll', '.so', '.elf'):
        return "executable"
    # Archive
    elif ext in ('.zip', '.rar', '.7z', '.tar', '.gz'):
        return "archive"
    # Image
    elif ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico'):
        return "image"
    # Document
    elif ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx'):
        return "document"
    # Data
    elif ext in ('.json', '.xml', '.sql', '.csv'):
        return "data"
    else:
        return FILE_TYPE_ICONS.get(file_type, "other")


def format_file_size(size: int) -> str:
    """Format file size in human-readable format"""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.2f} MB"


class FileListTable(QTableWidget):
    """File list table with custom styling"""

    fileSelected = Signal(object)  # ExtractedFile

    def __init__(self, parent=None):
        super().__init__(parent)
        self._files: List[ExtractedFile] = []
        self._setupUI()

    def _setupUI(self):
        # Set columns: Icon, Name, Type, Size, Source Packet
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["", "File Name", "Type", "Size", "Source"])

        # Header configuration
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)

        self.setColumnWidth(0, 30)   # Icon
        self.setColumnWidth(2, 80)   # Type
        self.setColumnWidth(3, 80)   # Size
        self.setColumnWidth(4, 70)   # Source

        # Table configuration
        self.setShowGrid(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)

        # Connect signals
        self.itemSelectionChanged.connect(self._onSelectionChanged)
        self.customContextMenuRequested.connect(self._showContextMenu)

        # Styling
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {BG_PRIMARY};
                border: 1px solid {BORDER};
                border-radius: 6px;
                gridline-color: {BORDER};
                outline: none;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
                border: none;
            }}
            QTableWidget::item:hover {{
                background-color: {PRIMARY_LIGHT};
            }}
            QTableWidget::item:selected {{
                background-color: {PRIMARY};
                color: white;
            }}
            QHeaderView::section {{
                background-color: {BG_SECONDARY};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {BORDER};
                font-weight: bold;
                color: {TEXT_PRIMARY};
            }}
        """)

    def setFiles(self, files: List[ExtractedFile]):
        """Set the list of extracted files"""
        self._files = files
        self.setRowCount(len(files))

        for row, ef in enumerate(files):
            # Icon column
            icon_type = get_file_icon(ef.file_type, ef.file_name)
            icon_item = QTableWidgetItem(self._getIconText(icon_type))
            icon_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 0, icon_item)

            # File name
            name_item = QTableWidgetItem(ef.file_name)
            name_item.setToolTip(ef.file_path)
            self.setItem(row, 1, name_item)

            # File type
            type_item = QTableWidgetItem(ef.file_type)
            type_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 2, type_item)

            # File size
            size_item = QTableWidgetItem(format_file_size(ef.file_size))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.setItem(row, 3, size_item)

            # Source packet
            source_text = f"#{ef.source_packet}" if ef.source_packet > 0 else "-"
            source_item = QTableWidgetItem(source_text)
            source_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 4, source_item)

            # Color coding for potentially dangerous files
            ext = os.path.splitext(ef.file_name.lower())[1]
            if ext in ('.php', '.jsp', '.asp', '.aspx', '.exe', '.dll'):
                for col in range(5):
                    item = self.item(row, col)
                    if item:
                        item.setForeground(QColor(WARNING))

    def _getIconText(self, icon_type: str) -> str:
        """Get icon text/emoji based on type"""
        icons = {
            "script": "S",
            "executable": "E",
            "archive": "Z",
            "image": "I",
            "document": "D",
            "data": "J",
            "other": "F",
        }
        return icons.get(icon_type, "F")

    def _onSelectionChanged(self):
        """Handle selection change"""
        selected = self.selectedItems()
        if selected:
            row = selected[0].row()
            if 0 <= row < len(self._files):
                self.fileSelected.emit(self._files[row])

    def _showContextMenu(self, pos):
        """Show context menu for file operations"""
        row = self.rowAt(pos.y())
        if row < 0 or row >= len(self._files):
            return

        ef = self._files[row]

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: white;
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 5px;
            }}
            QMenu::item {{
                padding: 8px 20px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {PRIMARY_LIGHT};
            }}
        """)

        # Open in folder action
        open_folder_action = QAction("Open in Folder", self)
        open_folder_action.triggered.connect(lambda: self._openInFolder(ef))
        menu.addAction(open_folder_action)

        # Copy path action
        copy_path_action = QAction("Copy Path", self)
        copy_path_action.triggered.connect(lambda: self._copyPath(ef))
        menu.addAction(copy_path_action)

        menu.addSeparator()

        # Export file action
        export_action = QAction("Export File...", self)
        export_action.triggered.connect(lambda: self._exportFile(ef))
        menu.addAction(export_action)

        menu.exec(QCursor.pos())

    def _openInFolder(self, ef: ExtractedFile):
        """Open the containing folder"""
        if not os.path.exists(ef.file_path):
            QMessageBox.warning(self, "Error", f"File not found:\n{ef.file_path}")
            return

        folder = os.path.dirname(ef.file_path)

        import platform
        import subprocess

        if platform.system() == "Windows":
            os.startfile(folder)
        elif platform.system() == "Darwin":
            subprocess.call(["open", folder])
        else:
            subprocess.call(["xdg-open", folder])

    def _copyPath(self, ef: ExtractedFile):
        """Copy file path to clipboard"""
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(ef.file_path)

    def _exportFile(self, ef: ExtractedFile):
        """Export file to a chosen location"""
        if not os.path.exists(ef.file_path):
            QMessageBox.warning(self, "Export Failed", f"File not found:\n{ef.file_path}")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export File", ef.file_name, "All Files (*)"
        )

        if save_path:
            try:
                shutil.copy(ef.file_path, save_path)
                QMessageBox.information(self, "Export Successful", f"File saved to:\n{save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error saving file:\n{str(e)}")

    def getSelectedFile(self) -> Optional[ExtractedFile]:
        """Get the currently selected file"""
        selected = self.selectedItems()
        if selected:
            row = selected[0].row()
            if 0 <= row < len(self._files):
                return self._files[row]
        return None

    def clear(self):
        """Clear the file list"""
        self._files = []
        self.setRowCount(0)


class HexDumpViewer(QFrame):
    """Hex dump viewer with Wireshark-style formatting"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_file: Optional[ExtractedFile] = None
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet(f"""
            HexDumpViewer {{
                background-color: {BG_PRIMARY};
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Title bar with file info
        title_bar = QWidget()
        title_bar.setStyleSheet(f"""
            background-color: #263238;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            border-bottom: 1px solid #37474F;
        """)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(12, 8, 12, 8)

        self.title_label = QLabel("Hex Dump")
        self.title_label.setStyleSheet("color: #ECEFF1; font-weight: bold; font-size: 12px;")
        title_layout.addWidget(self.title_label)

        title_layout.addStretch()

        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color: #90A4AE; font-size: 11px;")
        title_layout.addWidget(self.info_label)

        layout.addWidget(title_bar)

        # Hex content area
        self.hex_edit = QTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setFont(QFont("Consolas", 10))
        self.hex_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: none;
                padding: 10px;
                selection-background-color: #264F78;
            }
        """)
        layout.addWidget(self.hex_edit)

    def showFile(self, ef: ExtractedFile):
        """Display the hex dump for a file"""
        self._current_file = ef

        # Update title
        self.title_label.setText(f"Hex Dump - {ef.file_name}")
        self.info_label.setText(f"{format_file_size(ef.file_size)} | {ef.content_type}")

        # Load hex content if not already loaded
        if not ef.hex_dump:
            ef.hex_dump = self._loadHexContent(ef.file_path)

        self.hex_edit.setPlainText(ef.hex_dump)

    def _loadHexContent(self, file_path: str, max_bytes: int = 4096) -> str:
        """Load and format file content as hex dump"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(max_bytes)

            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                offset = f"{i:08x}"

                # Hex part
                hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
                hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
                hex_part = f"{hex_left:<23}  {hex_right:<23}"

                # ASCII part
                ascii_part = "".join(
                    chr(b) if 32 <= b < 127 else '.'
                    for b in chunk
                )

                lines.append(f"{offset}   {hex_part}  |{ascii_part}|")

            if len(data) == max_bytes:
                lines.append(f"\n... (showing first {max_bytes} bytes)")

            return '\n'.join(lines)

        except Exception as e:
            return f"Error reading file: {str(e)}"

    def clear(self):
        """Clear the viewer"""
        self._current_file = None
        self.title_label.setText("Hex Dump")
        self.info_label.setText("Select a file to view")
        self.hex_edit.clear()


class ExtractedFilesPanel(QWidget):
    """
    Panel for displaying extracted files from traffic analysis.

    Features:
    - File list table on the left
    - Hex dump viewer on the right
    - Context menu for file operations
    - File type icons and color coding
    """

    fileSelected = Signal(object)  # ExtractedFile

    def __init__(self, parent=None):
        super().__init__(parent)
        self._files: List[ExtractedFile] = []
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header
        header_layout = QHBoxLayout()

        title = QLabel("Extracted Files")
        title.setStyleSheet(f"""
            font-size: 14px;
            font-weight: bold;
            color: {TEXT_PRIMARY};
        """)
        header_layout.addWidget(title)

        header_layout.addStretch()

        # File count label
        self.count_label = QLabel("0 files")
        self.count_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        header_layout.addWidget(self.count_label)

        layout.addLayout(header_layout)

        # Splitter for file list and hex viewer
        splitter = QSplitter(Qt.Horizontal)

        # File list table
        self.file_table = FileListTable()
        self.file_table.fileSelected.connect(self._onFileSelected)
        splitter.addWidget(self.file_table)

        # Hex dump viewer
        self.hex_viewer = HexDumpViewer()
        splitter.addWidget(self.hex_viewer)

        # Set splitter sizes (40:60)
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Select a file to view hex dump")
        self.status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; padding: 4px;")
        layout.addWidget(self.status_label)

    def setFiles(self, files: List[ExtractedFile]):
        """Set the list of extracted files"""
        self._files = files
        self.file_table.setFiles(files)
        self.count_label.setText(f"{len(files)} files")

        # Clear hex viewer
        self.hex_viewer.clear()

        # Update status
        if not files:
            self.status_label.setText("No files extracted")
        else:
            self.status_label.setText("Select a file to view hex dump")

    def addFile(self, ef: ExtractedFile):
        """Add a single file to the list"""
        self._files.append(ef)
        self.file_table.setFiles(self._files)
        self.count_label.setText(f"{len(self._files)} files")

    def _onFileSelected(self, ef: ExtractedFile):
        """Handle file selection"""
        self.hex_viewer.showFile(ef)
        self.fileSelected.emit(ef)
        self.status_label.setText(f"Viewing: {ef.file_name}")

    def clear(self):
        """Clear all files"""
        self._files = []
        self.file_table.clear()
        self.hex_viewer.clear()
        self.count_label.setText("0 files")
        self.status_label.setText("No files extracted")

    def getFiles(self) -> List[ExtractedFile]:
        """Get the list of extracted files"""
        return self._files
