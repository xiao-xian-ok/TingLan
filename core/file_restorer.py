# file_restorer.py
# 从pcap里还原文件，用magic number识别类型

import os
import struct
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class FileSignature:
    magic: bytes                # 魔数字节
    offset: int = 0
    extension: str = ""
    description: str = ""
    mime_type: str = ""
    category: str = ""


FILE_SIGNATURES: List[FileSignature] = [
    # 压缩文件
    FileSignature(
        magic=b'\x50\x4B\x03\x04',
        extension='zip',
        description='ZIP Archive',
        mime_type='application/zip',
        category='archive'
    ),
    FileSignature(
        magic=b'\x50\x4B\x05\x06',
        extension='zip',
        description='ZIP Archive (empty)',
        mime_type='application/zip',
        category='archive'
    ),
    FileSignature(
        magic=b'\x50\x4B\x07\x08',
        extension='zip',
        description='ZIP Archive (spanned)',
        mime_type='application/zip',
        category='archive'
    ),
    FileSignature(
        magic=b'\x1F\x8B\x08',
        extension='gz',
        description='GZIP Archive',
        mime_type='application/gzip',
        category='archive'
    ),
    FileSignature(
        magic=b'\x42\x5A\x68',
        extension='bz2',
        description='BZIP2 Archive',
        mime_type='application/x-bzip2',
        category='archive'
    ),
    FileSignature(
        magic=b'\xFD\x37\x7A\x58\x5A\x00',
        extension='xz',
        description='XZ Archive',
        mime_type='application/x-xz',
        category='archive'
    ),
    FileSignature(
        magic=b'\x52\x61\x72\x21\x1A\x07\x00',
        extension='rar',
        description='RAR Archive v1.5+',
        mime_type='application/vnd.rar',
        category='archive'
    ),
    FileSignature(
        magic=b'\x52\x61\x72\x21\x1A\x07\x01\x00',
        extension='rar',
        description='RAR Archive v5.0+',
        mime_type='application/vnd.rar',
        category='archive'
    ),
    FileSignature(
        magic=b'\x37\x7A\xBC\xAF\x27\x1C',
        extension='7z',
        description='7-Zip Archive',
        mime_type='application/x-7z-compressed',
        category='archive'
    ),
    FileSignature(
        magic=b'\x75\x73\x74\x61\x72',
        offset=257,
        extension='tar',
        description='TAR Archive',
        mime_type='application/x-tar',
        category='archive'
    ),

    # 图像文件
    FileSignature(
        magic=b'\xFF\xD8\xFF',
        extension='jpg',
        description='JPEG Image',
        mime_type='image/jpeg',
        category='image'
    ),
    FileSignature(
        magic=b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        extension='png',
        description='PNG Image',
        mime_type='image/png',
        category='image'
    ),
    FileSignature(
        magic=b'\x47\x49\x46\x38\x37\x61',
        extension='gif',
        description='GIF Image (87a)',
        mime_type='image/gif',
        category='image'
    ),
    FileSignature(
        magic=b'\x47\x49\x46\x38\x39\x61',
        extension='gif',
        description='GIF Image (89a)',
        mime_type='image/gif',
        category='image'
    ),
    FileSignature(
        magic=b'\x42\x4D',
        extension='bmp',
        description='BMP Image',
        mime_type='image/bmp',
        category='image'
    ),
    FileSignature(
        magic=b'\x00\x00\x01\x00',
        extension='ico',
        description='ICO Icon',
        mime_type='image/x-icon',
        category='image'
    ),
    FileSignature(
        magic=b'\x52\x49\x46\x46',
        extension='webp',
        description='WebP Image',
        mime_type='image/webp',
        category='image'
    ),
    FileSignature(
        magic=b'\x49\x49\x2A\x00',
        extension='tif',
        description='TIFF Image (Little Endian)',
        mime_type='image/tiff',
        category='image'
    ),
    FileSignature(
        magic=b'\x4D\x4D\x00\x2A',
        extension='tif',
        description='TIFF Image (Big Endian)',
        mime_type='image/tiff',
        category='image'
    ),

    # 音频文件
    FileSignature(
        magic=b'\x49\x44\x33',
        extension='mp3',
        description='MP3 Audio (ID3v2)',
        mime_type='audio/mpeg',
        category='audio'
    ),
    FileSignature(
        magic=b'\xFF\xFB',
        extension='mp3',
        description='MP3 Audio',
        mime_type='audio/mpeg',
        category='audio'
    ),
    FileSignature(
        magic=b'\xFF\xFA',
        extension='mp3',
        description='MP3 Audio',
        mime_type='audio/mpeg',
        category='audio'
    ),
    FileSignature(
        magic=b'\x52\x49\x46\x46',
        extension='wav',
        description='WAV Audio',
        mime_type='audio/wav',
        category='audio'
    ),
    FileSignature(
        magic=b'\x4F\x67\x67\x53',
        extension='ogg',
        description='OGG Audio',
        mime_type='audio/ogg',
        category='audio'
    ),
    FileSignature(
        magic=b'\x66\x4C\x61\x43',
        extension='flac',
        description='FLAC Audio',
        mime_type='audio/flac',
        category='audio'
    ),
    FileSignature(
        magic=b'\x00\x00\x00',
        extension='m4a',
        description='M4A/AAC Audio',
        mime_type='audio/mp4',
        category='audio'
    ),

    # 视频文件
    FileSignature(
        magic=b'\x00\x00\x00\x1C\x66\x74\x79\x70',
        extension='mp4',
        description='MP4 Video',
        mime_type='video/mp4',
        category='video'
    ),
    FileSignature(
        magic=b'\x00\x00\x00\x20\x66\x74\x79\x70',
        extension='mp4',
        description='MP4 Video',
        mime_type='video/mp4',
        category='video'
    ),
    FileSignature(
        magic=b'\x1A\x45\xDF\xA3',
        extension='mkv',
        description='Matroska Video',
        mime_type='video/x-matroska',
        category='video'
    ),
    FileSignature(
        magic=b'\x52\x49\x46\x46',
        extension='avi',
        description='AVI Video',
        mime_type='video/x-msvideo',
        category='video'
    ),
    FileSignature(
        magic=b'\x46\x4C\x56\x01',
        extension='flv',
        description='FLV Video',
        mime_type='video/x-flv',
        category='video'
    ),
    FileSignature(
        magic=b'\x00\x00\x01\xBA',
        extension='mpg',
        description='MPEG Video',
        mime_type='video/mpeg',
        category='video'
    ),

    # 文档文件
    FileSignature(
        magic=b'\x25\x50\x44\x46',
        extension='pdf',
        description='PDF Document',
        mime_type='application/pdf',
        category='document'
    ),
    FileSignature(
        magic=b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
        extension='doc',
        description='MS Office Document (OLE)',
        mime_type='application/msword',
        category='document'
    ),
    FileSignature(
        magic=b'\x50\x4B\x03\x04\x14\x00\x06\x00',
        extension='docx',
        description='MS Word Document (OOXML)',
        mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        category='document'
    ),
    FileSignature(
        magic=b'\x7B\x5C\x72\x74\x66',
        extension='rtf',
        description='RTF Document',
        mime_type='application/rtf',
        category='document'
    ),

    # 可执行文件
    FileSignature(
        magic=b'\x4D\x5A',
        extension='exe',
        description='Windows Executable (PE)',
        mime_type='application/x-msdownload',
        category='executable'
    ),
    FileSignature(
        magic=b'\x7F\x45\x4C\x46',
        extension='elf',
        description='Linux Executable (ELF)',
        mime_type='application/x-executable',
        category='executable'
    ),
    FileSignature(
        magic=b'\xCA\xFE\xBA\xBE',
        extension='class',
        description='Java Class File',
        mime_type='application/java-vm',
        category='executable'
    ),
    FileSignature(
        magic=b'\xFE\xED\xFA\xCE',
        extension='macho',
        description='macOS Executable (32-bit)',
        mime_type='application/x-mach-binary',
        category='executable'
    ),
    FileSignature(
        magic=b'\xFE\xED\xFA\xCF',
        extension='macho',
        description='macOS Executable (64-bit)',
        mime_type='application/x-mach-binary',
        category='executable'
    ),
    FileSignature(
        magic=b'\xCF\xFA\xED\xFE',
        extension='macho',
        description='macOS Executable (64-bit, reversed)',
        mime_type='application/x-mach-binary',
        category='executable'
    ),

    # 数据库文件
    FileSignature(
        magic=b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33',
        extension='sqlite',
        description='SQLite Database',
        mime_type='application/x-sqlite3',
        category='database'
    ),

    # 密钥/证书文件
    FileSignature(
        magic=b'\x2D\x2D\x2D\x2D\x2D\x42\x45\x47\x49\x4E',
        extension='pem',
        description='PEM Certificate',
        mime_type='application/x-pem-file',
        category='security'
    ),
    FileSignature(
        magic=b'\x30\x82',
        extension='der',
        description='DER Certificate',
        mime_type='application/x-x509-ca-cert',
        category='security'
    ),

    # 脚本/代码文件
    FileSignature(
        magic=b'\x23\x21',
        extension='sh',
        description='Shell Script (shebang)',
        mime_type='text/x-shellscript',
        category='script'
    ),
    FileSignature(
        magic=b'\x3C\x3F\x70\x68\x70',
        extension='php',
        description='PHP Script',
        mime_type='application/x-php',
        category='script'
    ),
    FileSignature(
        magic=b'\x3C\x3F\x78\x6D\x6C',
        extension='xml',
        description='XML Document',
        mime_type='application/xml',
        category='script'
    ),

    # 其他常见文件
    FileSignature(
        magic=b'\x00\x00\x00\x00\x00\x00\x00\x00',
        extension='pcap',
        description='PCAP Capture (null)',
        mime_type='application/vnd.tcpdump.pcap',
        category='network'
    ),
    FileSignature(
        magic=b'\xD4\xC3\xB2\xA1',
        extension='pcap',
        description='PCAP Capture (Little Endian)',
        mime_type='application/vnd.tcpdump.pcap',
        category='network'
    ),
    FileSignature(
        magic=b'\xA1\xB2\xC3\xD4',
        extension='pcap',
        description='PCAP Capture (Big Endian)',
        mime_type='application/vnd.tcpdump.pcap',
        category='network'
    ),
    FileSignature(
        magic=b'\x0A\x0D\x0D\x0A',
        extension='pcapng',
        description='PCAPNG Capture',
        mime_type='application/vnd.tcpdump.pcap',
        category='network'
    ),
]

# 按magic长度和首字节分组，加速查找
_SIGNATURE_INDEX: Dict[int, Dict[int, List[FileSignature]]] = {}

def _build_signature_index():
    global _SIGNATURE_INDEX
    for sig in FILE_SIGNATURES:
        magic_len = len(sig.magic)
        first_byte = sig.magic[0]

        if magic_len not in _SIGNATURE_INDEX:
            _SIGNATURE_INDEX[magic_len] = {}
        if first_byte not in _SIGNATURE_INDEX[magic_len]:
            _SIGNATURE_INDEX[magic_len][first_byte] = []

        _SIGNATURE_INDEX[magic_len][first_byte].append(sig)

_build_signature_index()


@dataclass
class FileRecovery:
    detected: bool = False
    extension: str = ""
    description: str = ""
    mime_type: str = ""
    category: str = ""
    confidence: float = 0.0
    data: bytes = b""
    offset: int = 0
    size: int = 0
    signature: Optional[FileSignature] = None


class FileRestorer:

    def __init__(self):
        self.signatures = FILE_SIGNATURES

    def detect_file_type(self, data: bytes) -> Optional[FileSignature]:
        """遍历所有签名，从长到短匹配"""
        if not data:
            return None

        best_match = None
        best_length = 0

        for sig in self.signatures:
            offset = sig.offset
            magic = sig.magic
            magic_len = len(magic)

            if len(data) < offset + magic_len:
                continue

            if data[offset:offset + magic_len] == magic:
                if magic_len > best_length:
                    best_match = sig
                    best_length = magic_len

        return best_match

    def detect_file_type_fast(self, data: bytes) -> Optional[FileSignature]:
        """用索引加速的版本，至少要前16字节"""
        if not data:
            return None

        best_match = None
        best_length = 0

        for magic_len in sorted(_SIGNATURE_INDEX.keys(), reverse=True):
            if len(data) < magic_len:
                continue

            first_byte = data[0]
            if first_byte not in _SIGNATURE_INDEX[magic_len]:
                continue

            for sig in _SIGNATURE_INDEX[magic_len][first_byte]:
                offset = sig.offset
                if len(data) < offset + magic_len:
                    continue

                if data[offset:offset + magic_len] == sig.magic:
                    if magic_len > best_length:
                        best_match = sig
                        best_length = magic_len

        return best_match

    def restore_file(self, data: bytes, output_dir: str = None) -> FileRecovery:
        result = FileRecovery(data=data, size=len(data))

        signature = self.detect_file_type(data)
        if not signature:
            return result

        result.detected = True
        result.extension = signature.extension
        result.description = signature.description
        result.mime_type = signature.mime_type
        result.category = signature.category
        result.signature = signature
        result.confidence = 0.9  # magic匹配的置信度

        if output_dir and os.path.isdir(output_dir):
            import uuid
            filename = f"recovered_{uuid.uuid4().hex[:8]}.{signature.extension}"
            filepath = os.path.join(output_dir, filename)
            try:
                with open(filepath, 'wb') as f:
                    f.write(data)
            except IOError:
                pass

        return result

    def scan_for_embedded_files(self, data: bytes) -> List[Tuple[int, FileSignature]]:
        """扫描数据中所有嵌入的文件"""
        found = []

        for sig in self.signatures:
            magic = sig.magic
            offset = sig.offset

            search_start = 0
            while True:
                pos = data.find(magic, search_start)
                if pos == -1:
                    break

                actual_offset = pos - offset
                if actual_offset >= 0:
                    found.append((actual_offset, sig))

                search_start = pos + 1

        found.sort(key=lambda x: x[0])
        return found

    def extract_embedded_files(self, data: bytes, output_dir: str = None) -> List[FileRecovery]:
        results = []
        found_files = self.scan_for_embedded_files(data)

        for i, (offset, sig) in enumerate(found_files):
            # 到下一个文件或数据末尾
            if i + 1 < len(found_files):
                next_offset = found_files[i + 1][0]
                file_data = data[offset:next_offset]
            else:
                file_data = data[offset:]

            recovery = FileRecovery(
                detected=True,
                extension=sig.extension,
                description=sig.description,
                mime_type=sig.mime_type,
                category=sig.category,
                confidence=0.85,
                data=file_data,
                offset=offset,
                size=len(file_data),
                signature=sig
            )
            results.append(recovery)

        return results


def detect_file_type(data: bytes) -> Optional[str]:
    """检测文件类型，返回扩展名"""
    restorer = FileRestorer()
    sig = restorer.detect_file_type(data)
    return sig.extension if sig else None


def get_file_signature(data: bytes) -> Optional[FileSignature]:
    return FileRestorer().detect_file_type(data)


def is_archive(data: bytes) -> bool:
    sig = get_file_signature(data)
    return sig is not None and sig.category == 'archive'


def is_executable(data: bytes) -> bool:
    sig = get_file_signature(data)
    return sig is not None and sig.category == 'executable'
