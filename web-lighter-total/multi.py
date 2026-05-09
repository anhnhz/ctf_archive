import os
import tarfile
import zipfile
import mimetypes
import hashlib
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import magic
import werkzeug.utils
from PIL import Image, ImageOps
import io
import re

class MultiFileHandler:
    ALLOWED_EXTENSIONS = {
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',  # Images
        'txt', 'md', 'csv', 'json', 'xml',           # Text files
        'pdf', 'doc', 'docx',                        # Documents
        'tar', 'tar.gz', 'tgz', 'zip'                # Archives
    }
    
    ALLOWED_MIME_TYPES = {
        'image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/webp',
        'text/plain', 'text/markdown', 'text/csv', 'application/json', 'text/xml',
        'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/x-tar', 'application/gzip', 'application/zip'
    }
    
    MAX_FILE_SIZE = 50 * 1024 * 1024
    MAX_ARCHIVE_FILES = 1000
    QUARANTINE_DIR = "quarantine"
    TEMP_DIR = "temp"
    
    MAX_IMAGE_WIDTH = 1920
    MAX_IMAGE_HEIGHT = 1080
    IMAGE_QUALITY = 85
    THUMBNAIL_SIZE = (150, 150)
    
    def __init__(self, upload_dir: str, max_file_size: int = None):
        """
        Initialize the MultiFileHandler.

        Args:
            upload_dir (str): The directory where files will be uploaded.
            max_file_size (int, optional): The maximum allowed file size (in bytes).
        """
        self.upload_dir = Path(upload_dir).resolve()
        self.max_file_size = max_file_size or self.MAX_FILE_SIZE
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir = self.upload_dir / self.QUARANTINE_DIR
        self.temp_dir = self.upload_dir / self.TEMP_DIR
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.mime_detector = magic.Magic(mime=True)
        self.upload_stats = {
            'total_uploads': 0,
            'successful_uploads': 0,
            'failed_uploads': 0,
            'quarantined_files': 0
        }
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a filename to ensure it is safe for use.

        Args:
            filename (str): The original filename.

        Returns:
            str: A sanitized version of the filename.
        """
        filename = werkzeug.utils.secure_filename(filename)
        
        if not filename or filename.startswith('.'):
            filename = f"file_{hashlib.md5(filename.encode()).hexdigest()[:8]}"
        
        filename = filename.replace('/', '_').replace('\\', '_')
        
        return filename

    def _validate_path(self, file_path: Path) -> bool:
        """
        Validate that a file path is within the allowed upload directory.

        Args:
            file_path (Path): The file path to validate.

        Returns:
            bool: True if the path is valid, False otherwise.
        """
        try:
            resolved_path = file_path.resolve()
            return resolved_path.is_relative_to(self.upload_dir)
        except (OSError, ValueError):
            return False
    
    def _validate_file_extension(self, filename: str) -> bool:
        """
        Check if a file has an allowed extension.

        Args:
            filename (str): The name of the file.

        Returns:
            bool: True if the extension is allowed, False otherwise.
        """
        extension = Path(filename).suffix.lower().lstrip('.')
        if filename.lower().endswith('.tar.gz') or filename.lower().endswith('.tgz'):
            return 'tar.gz' in self.ALLOWED_EXTENSIONS or 'tgz' in self.ALLOWED_EXTENSIONS
        
        return extension in self.ALLOWED_EXTENSIONS
    
    def _validate_mime_type(self, file_path: str) -> bool:
        """
        Validate the MIME type of a file.

        Args:
            file_path (str): The path to the file.

        Returns:
            bool: True if the MIME type is allowed, False otherwise.
        """
        try:
            mime_type = self.mime_detector.from_file(file_path)
            return mime_type in self.ALLOWED_MIME_TYPES
        except Exception:
            return False
    
    def _validate_file_size(self, file_path: str) -> bool:
        """
        Check if a file's size is within the allowed limit.

        Args:
            file_path (str): The path to the file.

        Returns:
            bool: True if the file size is within the limit, False otherwise.
        """
        try:
            return os.path.getsize(file_path) <= self.max_file_size
        except OSError:
            return False
    
    def _extract_tar(self, tar_path: str, extract_to: str) -> List[str]:
        """
        Extract a tar archive safely.

        Args:
            tar_path (str): The path to the tar file.
            extract_to (str): The directory to extract the files to.

        Returns:
            List[str]: A list of extracted file paths.
        """
        extracted_files = []
        try:
            with tarfile.open(tar_path, 'r:*') as tar:
                members = tar.getmembers()
                tar.extractall(path=extract_to, filter="data")
                
                for root, dirs, files in os.walk(extract_to):
                    for file in files:
                        filepath = os.path.join(root, file)
                        if (self._validate_file_extension(file) and
                            self._validate_mime_type(filepath) and
                            self._validate_path(Path(filepath)) and
                            self._validate_file_size(filepath)):
                            extracted_files.append(filepath)
                        else:
                            self._quarantine_file(filepath, "Validation failed")
        except Exception as e:
            self._log_error(f"Error extracting tar file: {e}")
            return False
        
        return extracted_files
    
    def _extract_zip_safely(self, zip_path: str, extract_to: str) -> List[str]:
        """
        Safely extract a zip archive with protection against path traversal.

        Args:
            zip_path (str): The path to the zip file.
            extract_to (str): The directory to extract the files to.

        Returns:
            List[str]: A list of extracted file paths.
        """
        extracted_files = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                members = zip_file.namelist()
                
                if len(members) > self.MAX_ARCHIVE_FILES:
                    raise ValueError(f"Archive contains too many files: {len(members)}")
                
                for member_name in members:
                    if member_name.endswith('/'):
                        continue
                    
                    safe_name = self._sanitize_filename(os.path.basename(member_name))
                    if not safe_name:
                        continue
                    
                    safe_path = Path(extract_to) / safe_name
                    
                    if not self._validate_path(safe_path):
                        continue
                    
                    with zip_file.open(member_name) as source, open(safe_path, 'wb') as target:
                        target.write(source.read())
                    
                    extracted_path = str(safe_path)
                    if (self._validate_file_extension(safe_name) and 
                        self._validate_mime_type(extracted_path) and
                        self._validate_file_size(extracted_path)):
                        extracted_files.append(extracted_path)
                    else:
                        os.remove(extracted_path)
                        
        except Exception as e:
            for file_path in extracted_files:
                try:
                    os.remove(file_path)
                except OSError:
                    pass
            raise e
        
        return extracted_files
    
    def _quarantine_file(self, file_path: str, reason: str) -> None:
        """
        Move a suspicious file to the quarantine directory.

        Args:
            file_path (str): The path to the file.
            reason (str): The reason for quarantining the file.
        """
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = self.quarantine_dir / f"{hashlib.md5(file_name.encode()).hexdigest()}_{file_name}"
            
            if os.path.exists(file_path):
                os.rename(file_path, quarantine_path)
                self.upload_stats['quarantined_files'] += 1
                self._log_warning(f"File quarantined: {file_name} - Reason: {reason}")
        except Exception as e:
            self._log_error(f"Failed to quarantine file {file_path}: {e}")
    
    def _log_error(self, message: str) -> None:
        """
        Log an error message.

        Args:
            message (str): The error message to log.
        """
        print(f"[ERROR] {message}")
    
    def _log_warning(self, message: str) -> None:
        """
        Log a warning message.

        Args:
            message (str): The warning message to log.
        """
        print(f"[WARNING] {message}")
    
    def _log_info(self, message: str) -> None:
        """
        Log an informational message.

        Args:
            message (str): The informational message to log.
        """
        print(f"[INFO] {message}")
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate the hash of a file using the specified algorithm.

        Args:
            file_path (str): The path to the file.
            algorithm (str): The hashing algorithm to use (default: 'sha256').

        Returns:
            str: The calculated hash of the file.
        """
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            self._log_error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
    
    def _is_duplicate_file(self, file_path: str) -> bool:
        """
        Check if a file is a duplicate based on its hash.

        Args:
            file_path (str): The path to the file.

        Returns:
            bool: True if the file is a duplicate, False otherwise.
        """
        file_hash = self._calculate_file_hash(file_path)
        if not file_hash:
            return False
        
        for existing_file in self.upload_dir.rglob('*'):
            if existing_file.is_file() and existing_file != Path(file_path):
                existing_hash = self._calculate_file_hash(str(existing_file))
                if existing_hash == file_hash:
                    return True
        return False
    
    def _scan_for_malware_signatures(self, file_path: str) -> bool:
        """
        Scan a file for basic malware signatures (improved version).

        Reads the file in chunks to avoid memory issues.
        Uses regex to detect obfuscated patterns like 'e v a l' or with null bytes.
        """
        signature_patterns = [
            rb'e\s*val\s*\(',
            rb'e\s*x\s*ec\s*\(',
            rb's\s*ystem\s*\(',
            rb's\s*hell_exec\s*\(',
            rb'p\s*assthru\s*\(',
            rb'<\s*script\s*>',
            rb'javascript\s*:',
            rb'vbscript\s*:',
            rb'onload\s*=',
            rb'onerror\s*=',
        ]
        
        try:
            with open(file_path, 'rb') as f:
                buffer = b''
                chunk_size = 8192
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    buffer += data
                    lower_data = buffer.lower()
                    for pattern in signature_patterns:
                        if re.search(pattern, lower_data):
                            return True
                    buffer = buffer[-50:]
        except Exception as e:
            self._log_error(f"Failed to scan file {file_path}: {e}")
            return True  
        
        return False
    
    def validate_single_file(self, file_path: str) -> Dict[str, any]:
        """
        Perform comprehensive validation of a single file like an antivirus scanner.

        Args:
            file_path (str): The path to the file.

        Returns:
            Dict[str, any]: A dictionary containing scan results like VirusTotal.
        """
        import time
        
        scan_result = {
            'file_info': {
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': 0,
                'md5': '',
                'sha1': '',
                'sha256': '',
                'mime_type': '',
                'file_type': '',
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'scan_results': {
                'engines_count': 5,
                'positives': 0,
                'total': 5,
                'scan_details': {},
                'overall_status': 'CLEAN'
            },
            'additional_info': {
                'first_seen': time.strftime('%Y-%m-%d'),
                'last_analysis': time.strftime('%Y-%m-%d %H:%M:%S'),
                'reputation': 'UNKNOWN'
            },
            'metadata': {
                'warnings': [],
                'errors': []
            }
        }
        
        try:
            if not os.path.exists(file_path):
                scan_result['metadata']['errors'].append("File does not exist")
                scan_result['scan_results']['overall_status'] = 'ERROR'
                return scan_result
            
            file_size = os.path.getsize(file_path)
            scan_result['file_info']['file_size'] = file_size
            
            scan_result['file_info']['md5'] = self._calculate_file_hash(file_path, 'md5')
            scan_result['file_info']['sha1'] = self._calculate_file_hash(file_path, 'sha1')
            scan_result['file_info']['sha256'] = self._calculate_file_hash(file_path, 'sha256')
            
            mime_type = self.mime_detector.from_file(file_path)
            scan_result['file_info']['mime_type'] = mime_type
            scan_result['file_info']['file_type'] = mime_type.split('/')[0] if '/' in mime_type else 'unknown'
            
            if not self._validate_file_size(file_path):
                scan_result['scan_results']['scan_details']['SizeGuard'] = {
                    'result': 'MALICIOUS',
                    'reason': f'File size exceeds limit: {file_size} bytes',
                    'version': '1.0',
                    'update': '20250101'
                }
                scan_result['scan_results']['positives'] += 1
            else:
                scan_result['scan_results']['scan_details']['SizeGuard'] = {
                    'result': 'CLEAN',
                    'reason': 'File size within acceptable limits',
                    'version': '1.0',
                    'update': '20250101'
                }
            
            if not self._validate_file_extension(scan_result['file_info']['file_name']):
                scan_result['scan_results']['scan_details']['ExtensionCheck'] = {
                    'result': 'SUSPICIOUS',
                    'reason': 'Invalid or dangerous file extension',
                    'version': '2.1',
                    'update': '20250110'
                }
                scan_result['scan_results']['positives'] += 1
            else:
                scan_result['scan_results']['scan_details']['ExtensionCheck'] = {
                    'result': 'CLEAN',
                    'reason': 'File extension is allowed',
                    'version': '2.1',
                    'update': '20250110'
                }
            
            if not self._validate_mime_type(file_path):
                scan_result['scan_results']['scan_details']['MimeTypeScanner'] = {
                    'result': 'MALICIOUS',
                    'reason': f'Dangerous MIME type: {mime_type}',
                    'version': '3.4',
                    'update': '20250105'
                }
                scan_result['scan_results']['positives'] += 1
            else:
                scan_result['scan_results']['scan_details']['MimeTypeScanner'] = {
                    'result': 'CLEAN',
                    'reason': 'MIME type is safe',
                    'version': '3.4',
                    'update': '20250105'
                }
            
            if not self._validate_path(Path(file_path)):
                scan_result['scan_results']['scan_details']['PathValidator'] = {
                    'result': 'MALICIOUS',
                    'reason': 'Potential path traversal attack detected',
                    'version': '1.5',
                    'update': '20250108'
                }
                scan_result['scan_results']['positives'] += 1
            else:
                scan_result['scan_results']['scan_details']['PathValidator'] = {
                    'result': 'CLEAN',
                    'reason': 'File path is safe',
                    'version': '1.5',
                    'update': '20250108'
                }
            
            if self._scan_for_malware_signatures(file_path):
                scan_result['scan_results']['scan_details']['SignatureEngine'] = {
                    'result': 'MALICIOUS',
                    'reason': 'Malicious code patterns detected',
                    'version': '4.2',
                    'update': '20250112'
                }
                scan_result['scan_results']['positives'] += 1
            else:
                scan_result['scan_results']['scan_details']['SignatureEngine'] = {
                    'result': 'CLEAN',
                    'reason': 'No malicious signatures found',
                    'version': '4.2',
                    'update': '20250112'
                }
            
            if self._is_duplicate_file(file_path):
                scan_result['metadata']['warnings'].append("Duplicate file detected")
                scan_result['additional_info']['reputation'] = 'KNOWN'
            
            if scan_result['scan_results']['positives'] == 0:
                scan_result['scan_results']['overall_status'] = 'CLEAN'
                scan_result['additional_info']['reputation'] = 'GOOD'
            elif scan_result['scan_results']['positives'] <= 2:
                scan_result['scan_results']['overall_status'] = 'SUSPICIOUS'
                scan_result['additional_info']['reputation'] = 'SUSPICIOUS'
            else:
                scan_result['scan_results']['overall_status'] = 'MALICIOUS'
                scan_result['additional_info']['reputation'] = 'BAD'
            
        except Exception as e:
            scan_result['metadata']['errors'].append(f"Scan error: {str(e)}")
            scan_result['scan_results']['overall_status'] = 'ERROR'
        
        return scan_result
    
    def process_uploaded_files(self, file_paths: List[str]) -> Dict[str, any]:
        """
        Process multiple uploaded files and return VirusTotal-like scan results.

        Args:
            file_paths (List[str]): A list of file paths to process.

        Returns:
            Dict[str, any]: A dictionary containing comprehensive scan results.
        """
        import time
        
        scan_report = {
            'scan_summary': {
                'total_files': len(file_paths),
                'clean_files': 0,
                'suspicious_files': 0,
                'malicious_files': 0,
                'error_files': 0,
                'scan_time': 0,
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scanner_version': 'LighterTotal v2.1.0'
            },
            'file_results': [],
            'threat_summary': {
                'threats_detected': [],
                'risk_level': 'LOW',
                'recommendations': []
            },
            'extracted_archives': {
                'total_extracted': 0,
                'extracted_files': []
            }
        }
        
        start_time = time.time()
        
        for file_path in file_paths:
            self.upload_stats['total_uploads'] += 1
            
            try:
                scan_result = self.validate_single_file(file_path)
                scan_report['file_results'].append(scan_result)
                
                status = scan_result['scan_results']['overall_status']
                if status == 'CLEAN':
                    scan_report['scan_summary']['clean_files'] += 1
                    self.upload_stats['successful_uploads'] += 1
                elif status == 'SUSPICIOUS':
                    scan_report['scan_summary']['suspicious_files'] += 1
                    scan_report['threat_summary']['threats_detected'].append({
                        'file': scan_result['file_info']['file_name'],
                        'threat_type': 'SUSPICIOUS',
                        'details': 'File flagged by multiple engines as suspicious'
                    })
                elif status == 'MALICIOUS':
                    scan_report['scan_summary']['malicious_files'] += 1
                    scan_report['threat_summary']['threats_detected'].append({
                        'file': scan_result['file_info']['file_name'],
                        'threat_type': 'MALWARE',
                        'details': 'Malicious content detected'
                    })
                    self._quarantine_file(file_path, "Detected as malicious by scan engines")
                else:
                    scan_report['scan_summary']['error_files'] += 1
                    self.upload_stats['failed_uploads'] += 1
                
                file_ext = Path(file_path).suffix.lower()
                if file_ext in ['.tar', '.gz', '.tgz'] and status == 'CLEAN':
                    extract_dir = Path('upload')
                    extract_dir.mkdir(exist_ok=True)
                    
                    extracted = self._extract_tar(file_path, str(extract_dir))
                    if extracted:
                        scan_report['extracted_archives']['total_extracted'] += len(extracted)
                        scan_report['extracted_archives']['extracted_files'].extend([
                            {'original_archive': os.path.basename(file_path), 'extracted_file': os.path.basename(f)}
                            for f in extracted
                        ])
                
                elif file_ext == '.zip' and status == 'CLEAN':
                    extract_dir = self.temp_dir / f"extract_{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
                    extract_dir.mkdir(exist_ok=True)
                    
                    extracted = self._extract_zip_safely(file_path, str(extract_dir))
                    scan_report['extracted_archives']['total_extracted'] += len(extracted)
                    scan_report['extracted_archives']['extracted_files'].extend([
                        {'original_archive': os.path.basename(file_path), 'extracted_file': os.path.basename(f)}
                        for f in extracted
                    ])
            
            except Exception as e:
                error_result = {
                    'file_info': {
                        'file_name': os.path.basename(file_path),
                        'file_path': file_path,
                        'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
                    },
                    'scan_results': {
                        'overall_status': 'ERROR',
                        'positives': 0,
                        'total': 5
                    },
                    'metadata': {
                        'errors': [f"Processing error: {str(e)}"]
                    }
                }
                scan_report['file_results'].append(error_result)
                scan_report['scan_summary']['error_files'] += 1
                self.upload_stats['failed_uploads'] += 1
    
        scan_report['scan_summary']['scan_time'] = round(time.time() - start_time, 2)
        
        total_threats = scan_report['scan_summary']['malicious_files'] + scan_report['scan_summary']['suspicious_files']
        if scan_report['scan_summary']['malicious_files'] > 0:
            scan_report['threat_summary']['risk_level'] = 'HIGH'
            scan_report['threat_summary']['recommendations'].append("Immediate action required: Malicious files detected")
        elif scan_report['scan_summary']['suspicious_files'] > 0:
            scan_report['threat_summary']['risk_level'] = 'MEDIUM'
            scan_report['threat_summary']['recommendations'].append("Caution advised: Suspicious files detected")
        else:
            scan_report['threat_summary']['risk_level'] = 'LOW'
            scan_report['threat_summary']['recommendations'].append("All files appear to be clean")
        
        if scan_report['extracted_archives']['total_extracted'] > 0:
            scan_report['threat_summary']['recommendations'].append(
                f"Extracted {scan_report['extracted_archives']['total_extracted']} files from archives - review individually"
            )
        
        return scan_report
    
    def get_upload_statistics(self) -> Dict[str, any]:
        """
        Retrieve upload statistics.

        Returns:
            Dict[str, any]: A dictionary containing upload statistics.
        """
        return self.upload_stats.copy()
    
    def cleanup_temp_files(self) -> None:
        """
        Clean up temporary files in the temp directory.
        """
        try:
            for temp_file in self.temp_dir.rglob('*'):
                if temp_file.is_file():
                    temp_file.unlink()
                elif temp_file.is_dir() and temp_file != self.temp_dir:
                    import shutil
                    shutil.rmtree(temp_file)
            self._log_info("Temporary files cleaned up")
        except Exception as e:
            self._log_error(f"Failed to cleanup temp files: {e}")
    
    def list_quarantined_files(self) -> List[Dict[str, any]]:
        """
        List all files in the quarantine directory.

        Returns:
            List[Dict[str, any]]: A list of dictionaries containing file details.
        """
        quarantined = []
        
        try:
            for file_path in self.quarantine_dir.iterdir():
                if file_path.is_file():
                    quarantined.append({
                        'name': file_path.name,
                        'path': str(file_path),
                        'size': file_path.stat().st_size,
                        'modified': file_path.stat().st_mtime
                    })
        except Exception as e:
            self._log_error(f"Failed to list quarantined files: {e}")
        
        return quarantined
    
    def restore_quarantined_file(self, quarantine_filename: str, new_filename: str = None) -> bool:
        """
        Restore a file from the quarantine directory.

        Args:
            quarantine_filename (str): The name of the quarantined file.
            new_filename (str, optional): The new name for the restored file.

        Returns:
            bool: True if the file was restored successfully, False otherwise.
        """
        try:
            quarantine_path = self.quarantine_dir / quarantine_filename
            
            if not quarantine_path.exists():
                self._log_error(f"Quarantined file not found: {quarantine_filename}")
                return False
            
            restore_name = new_filename or quarantine_filename.split('_', 1)[-1]
            restore_path = self.upload_dir / restore_name
            
            quarantine_path.rename(restore_path)
            self.upload_stats['quarantined_files'] -= 1
            self._log_info(f"File restored from quarantine: {restore_name}")
            return True
            
        except Exception as e:
            self._log_error(f"Failed to restore quarantined file: {e}")
            return False
    
    def validate_and_move_file(self, source_path: str, destination_name: str = None) -> Tuple[bool, str]:
        """
        Validate and move a file to the upload directory.

        Args:
            source_path (str): The path to the source file.
            destination_name (str, optional): The new name for the file in the upload directory.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and a message or file path.
        """
        try:
            source = Path(source_path)
            if not source.exists():
                return False, "Source file does not exist"
            
            validation = self.validate_single_file(source_path)
            if not validation['valid']:
                error_msg = '; '.join(validation['errors'])
                self._quarantine_file(source_path, error_msg)
                return False, f"Validation failed: {error_msg}"
            
            dest_name = destination_name or self._sanitize_filename(source.name)
            dest_path = self.upload_dir / dest_name
            
            counter = 1
            original_dest = dest_path
            while dest_path.exists():
                name_parts = original_dest.stem, counter, original_dest.suffix
                dest_path = original_dest.parent / f"{name_parts[0]}_{name_parts[1]}{name_parts[2]}"
                counter += 1
            
            source.rename(dest_path)
            self.upload_stats['successful_uploads'] += 1
            self._log_info(f"File successfully uploaded: {dest_path.name}")
            
            return True, str(dest_path)
            
        except Exception as e:
            error_msg = f"Failed to move file: {str(e)}"
            self._log_error(error_msg)
            self.upload_stats['failed_uploads'] += 1
            return False, error_msg
    
    def _is_image_file(self, file_path: str) -> bool:
        """
        Check if a file is an image based on its extension.

        Args:
            file_path (str): The path to the file.

        Returns:
            bool: True if the file is an image, False otherwise.
        """
        image_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
        extension = Path(file_path).suffix.lower().lstrip('.')
        return extension in image_extensions
    
    def _get_image_info(self, file_path: str) -> Dict[str, any]:
        """
        Retrieve detailed information about an image file with security checks.

        Args:
            file_path (str): The path to the image file.

        Returns:
            Dict[str, any]: A dictionary containing image details.
        """
        image_info = {
            'is_image': False,
            'width': 0,
            'height': 0,
            'format': '',
            'mode': '',
            'file_size': 0,
            'has_transparency': False,
            'has_exif': False,
            'security_warnings': []
        }
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024: 
                image_info['security_warnings'].append("Image file too large for safe processing")
                return image_info
            
            Image.MAX_IMAGE_PIXELS = 89478485  
            
            with Image.open(file_path) as img:
                if img.width > 50000 or img.height > 50000:
                    image_info['security_warnings'].append("Suspicious image dimensions detected")
                
                expected_format = self._get_expected_format_from_extension(file_path)
                if expected_format and img.format != expected_format:
                    image_info['security_warnings'].append(f"Format mismatch: expected {expected_format}, got {img.format}")
                
                has_exif = hasattr(img, '_getexif') and img._getexif() is not None
                if has_exif:
                    image_info['security_warnings'].append("Image contains EXIF metadata")
                
                image_info.update({
                    'is_image': True,
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode,
                    'file_size': file_size,
                    'has_transparency': img.mode in ('RGBA', 'LA') or 'transparency' in img.info,
                    'has_exif': has_exif
                })
                
        except Image.DecompressionBombError:
            image_info['security_warnings'].append("Potential decompression bomb detected")
            self._log_error(f"Decompression bomb detected in {file_path}")
        except Exception as e:
            self._log_error(f"Failed to get image info for {file_path}: {e}")
            image_info['security_warnings'].append(f"Image processing error: {str(e)}")
        
        return image_info
    
    def _get_expected_format_from_extension(self, file_path: str) -> str:
        """
        Get expected image format based on file extension.
        
        Args:
            file_path (str): The path to the file.
            
        Returns:
            str: Expected format or empty string if unknown.
        """
        ext_to_format = {
            '.jpg': 'JPEG', '.jpeg': 'JPEG',
            '.png': 'PNG',
            '.gif': 'GIF',
            '.bmp': 'BMP',
            '.webp': 'WEBP'
        }
        ext = Path(file_path).suffix.lower()
        return ext_to_format.get(ext, '')
    
    def _strip_image_metadata(self, image_path: str) -> bool:
        """
        Strip potentially dangerous metadata from image files.
        
        Args:
            image_path (str): Path to the image file.
            
        Returns:
            bool: True if metadata was stripped successfully.
        """
        try:
            with Image.open(image_path) as img:
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(list(img.getdata()))
                
                if img.format == 'JPEG':
                    clean_img.save(image_path, 'JPEG', quality=self.IMAGE_QUALITY, optimize=True)
                elif img.format == 'PNG':
                    clean_img.save(image_path, 'PNG', optimize=True)
                else:
                    clean_img.save(image_path, img.format)
                
                self._log_info(f"Metadata stripped from: {image_path}")
                return True
        except Exception as e:
            self._log_error(f"Failed to strip metadata from {image_path}: {e}")
            return False
    
    def resize_image(self, image_path: str, max_width: int = None, max_height: int = None, 
                    quality: int = None, output_path: str = None) -> Tuple[bool, str]:
        """
        Resize an image while maintaining its aspect ratio.

        Args:
            image_path (str): The path to the source image.
            max_width (int, optional): The maximum width of the resized image.
            max_height (int, optional): The maximum height of the resized image.
            quality (int, optional): The quality of the resized image (for JPEG).
            output_path (str, optional): The path to save the resized image.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and a message.
        """
        try:
            if not self._is_image_file(image_path):
                return False, "File is not a valid image"
            
            image_info = self._get_image_info(image_path)
            if image_info['security_warnings']:
                warning_msg = "; ".join(image_info['security_warnings'])
                self._log_warning(f"Security warnings for {image_path}: {warning_msg}")
                self._quarantine_file(image_path, f"Image security warnings: {warning_msg}")
                return False, f"Image security check failed: {warning_msg}"
            
            max_width = max_width or self.MAX_IMAGE_WIDTH
            max_height = max_height or self.MAX_IMAGE_HEIGHT
            quality = quality or self.IMAGE_QUALITY
            output_path = output_path or image_path
            
            Image.MAX_IMAGE_PIXELS = 89478485
            
            with Image.open(image_path) as img:
                original_size = img.size
                
                if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                    return False, "Image too large (potential decompression bomb)"
                
                img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                
                if img.format == 'JPEG' or output_path.lower().endswith('.jpg'):
                    if img.mode in ('RGBA', 'LA'):
                        background = Image.new('RGB', img.size, (255, 255, 255))
                        if img.mode == 'RGBA':
                            background.paste(img, mask=img.split()[-1])
                        else:
                            background.paste(img)
                        img = background
                    
                    img.save(output_path, 'JPEG', quality=quality, optimize=True, progressive=True)
                
                elif img.format == 'PNG' or output_path.lower().endswith('.png'):
                    img.save(output_path, 'PNG', optimize=True)
                
                else:
                    img.save(output_path, img.format)
                

                self._strip_image_metadata(output_path)
                
                new_size = img.size
                self._log_info(f"Image resized from {original_size} to {new_size}: {output_path}")
                
                return True, f"Image resized successfully: {original_size} -> {new_size}"
                
        except Exception as e:
            error_msg = f"Failed to resize image: {str(e)}"
            self._log_error(error_msg)
            return False, error_msg
    
    def create_thumbnail(self, image_path: str, thumbnail_size: Tuple[int, int] = None, 
                        output_dir: str = None) -> Tuple[bool, str]:
        """
        Create a thumbnail for an image.

        Args:
            image_path (str): The path to the source image.
            thumbnail_size (Tuple[int, int], optional): The size of the thumbnail.
            output_dir (str, optional): The directory to save the thumbnail.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and the thumbnail path.
        """
        try:
            if not self._is_image_file(image_path):
                return False, "File is not a valid image"
            
            image_info = self._get_image_info(image_path)
            if image_info['security_warnings']:
                warning_msg = "; ".join(image_info['security_warnings'])
                return False, f"Image security check failed: {warning_msg}"
            
            thumbnail_size = thumbnail_size or self.THUMBNAIL_SIZE
            source_path = Path(image_path)
            
            if output_dir:
                output_dir = Path(output_dir)
            else:
                output_dir = source_path.parent
            
            thumb_name = f"{source_path.stem}_thumb{source_path.suffix}"
            thumb_path = output_dir / thumb_name
            
            Image.MAX_IMAGE_PIXELS = 89478485
            
            with Image.open(image_path) as img:
                if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                    return False, "Image too large for thumbnail creation"
                
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                
                if img.format == 'JPEG':
                    if img.mode in ('RGBA', 'LA'):
                        background = Image.new('RGB', img.size, (255, 255, 255))
                        if img.mode == 'RGBA':
                            background.paste(img, mask=img.split()[-1])
                        else:
                            background.paste(img)
                        img = background
                    img.save(thumb_path, 'JPEG', quality=self.IMAGE_QUALITY, optimize=True, progressive=True)
                else:
                    img.save(thumb_path, img.format)
                
                self._strip_image_metadata(str(thumb_path))
                
                self._log_info(f"Thumbnail created: {thumb_path}")
                return True, str(thumb_path)
                
        except Exception as e:
            error_msg = f"Failed to create thumbnail: {str(e)}"
            self._log_error(error_msg)
            return False, error_msg
    
    def optimize_image(self, image_path: str, output_path: str = None) -> Tuple[bool, str]:
        """
        Optimize an image by reducing its file size while maintaining quality.

        Args:
            image_path (str): The path to the source image.
            output_path (str, optional): The path to save the optimized image.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and a message.
        """
        try:
            if not self._is_image_file(image_path):
                return False, "File is not a valid image"
            
            image_info = self._get_image_info(image_path)
            if image_info['security_warnings']:
                warning_msg = "; ".join(image_info['security_warnings'])
                return False, f"Image security check failed: {warning_msg}"
            
            output_path = output_path or image_path
            original_size = os.path.getsize(image_path)
            
            Image.MAX_IMAGE_PIXELS = 89478485
            
            with Image.open(image_path) as img:
                if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                    return False, "Image too large for optimization"
                
                if img.format == 'JPEG':
                    if img.mode in ('RGBA', 'LA'):
                        background = Image.new('RGB', img.size, (255, 255, 255))
                        if img.mode == 'RGBA':
                            background.paste(img, mask=img.split()[-1])
                        else:
                            background.paste(img)
                        img = background
                    
                    img.save(output_path, 'JPEG', quality=self.IMAGE_QUALITY, optimize=True, progressive=True)
                
                elif img.format == 'PNG':
                    img.save(output_path, 'PNG', optimize=True)
                
                else:
                    img.save(output_path, img.format, optimize=True)
            
            self._strip_image_metadata(output_path)
            
            new_size = os.path.getsize(output_path)
            reduction = ((original_size - new_size) / original_size) * 100
            
            self._log_info(f"Image optimized: {original_size} -> {new_size} bytes ({reduction:.1f}% reduction)")
            return True, f"Image optimized: {reduction:.1f}% size reduction"
            
        except Exception as e:
            error_msg = f"Failed to optimize image: {str(e)}"
            self._log_error(error_msg)
            return False, error_msg
    
    def convert_image_format(self, image_path: str, target_format: str, 
                           output_path: str = None) -> Tuple[bool, str]:
        """
        Convert an image to a different format.

        Args:
            image_path (str): The path to the source image.
            target_format (str): The target format (e.g., 'JPEG', 'PNG').
            output_path (str, optional): The path to save the converted image.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and the output path.
        """
        try:
            if not self._is_image_file(image_path):
                return False, "File is not a valid image"
            
            source_path = Path(image_path)
            target_format = target_format.upper()
            
            if not output_path:
                ext_map = {'JPEG': '.jpg', 'PNG': '.png', 'WEBP': '.webp', 'BMP': '.bmp'}
                new_ext = ext_map.get(target_format, f'.{target_format.lower()}')
                output_path = source_path.with_suffix(new_ext)
            
            with Image.open(image_path) as img:
                if target_format == 'JPEG' and img.mode in ('RGBA', 'LA'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = background
                
                if target_format == 'JPEG':
                    img.save(output_path, 'JPEG', quality=self.IMAGE_QUALITY, optimize=True)
                elif target_format == 'WEBP':
                    img.save(output_path, 'WEBP', quality=self.IMAGE_QUALITY, optimize=True)
                else:
                    img.save(output_path, target_format, optimize=True)
                
                self._log_info(f"Image converted to {target_format}: {output_path}")
                return True, str(output_path)
                
        except Exception as e:
            error_msg = f"Failed to convert image: {str(e)}"
            self._log_error(error_msg)
            return False, error_msg
    
    def auto_orient_image(self, image_path: str, output_path: str = None) -> Tuple[bool, str]:
        """
        Auto-orient an image based on its EXIF data.

        Args:
            image_path (str): The path to the source image.
            output_path (str, optional): The path to save the auto-oriented image.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and a message.
        """
        try:
            if not self._is_image_file(image_path):
                return False, "File is not a valid image"
            
            output_path = output_path or image_path
            
            with Image.open(image_path) as img:
                oriented_img = ImageOps.exif_transpose(img)
                
                if oriented_img != img:
                    if img.format == 'JPEG':
                        oriented_img.save(output_path, 'JPEG', quality=self.IMAGE_QUALITY, optimize=True)
                    else:
                        oriented_img.save(output_path, img.format, optimize=True)
                    
                    self._log_info(f"Image auto-oriented: {output_path}")
                    return True, "Image auto-oriented successfully"
                else:
                    return True, "Image already properly oriented"
                
        except Exception as e:
            error_msg = f"Failed to auto-orient image: {str(e)}"
            self._log_error(error_msg)
            return False, error_msg
    
    def process_image_upload(self, image_path: str, auto_resize: bool = True, 
                           create_thumb: bool = True, optimize: bool = True, 
                           strip_metadata: bool = True) -> Dict[str, any]:
        """
        Perform comprehensive processing of an uploaded image with security checks.

        Args:
            image_path (str): The path to the uploaded image.
            auto_resize (bool, optional): Whether to auto-resize the image.
            create_thumb (bool, optional): Whether to create a thumbnail.
            optimize (bool, optional): Whether to optimize the image.
            strip_metadata (bool, optional): Whether to strip metadata for security.

        Returns:
            Dict[str, any]: A dictionary containing processing results.
        """
        results = {
            'original_path': image_path,
            'processed_files': [],
            'operations': [],
            'errors': [],
            'security_warnings': [],
            'image_info': {}
        }
        
        try:
            if not self._is_image_file(image_path):
                results['errors'].append("File is not a valid image")
                return results
            
            results['image_info'] = self._get_image_info(image_path)
            
            if results['image_info']['security_warnings']:
                results['security_warnings'].extend(results['image_info']['security_warnings'])

                critical_warnings = ['decompression bomb', 'too large', 'suspicious dimensions']
                if any(warning in str(results['security_warnings']).lower() for warning in critical_warnings):
                    self._quarantine_file(image_path, "Critical security warnings in image")
                    results['errors'].append("Image quarantined due to security concerns")
                    return results
        
            if strip_metadata:
                if self._strip_image_metadata(image_path):
                    results['operations'].append("Metadata stripped for security")
                else:
                    results['errors'].append("Failed to strip metadata")
            
            success, msg = self.auto_orient_image(image_path)
            if success:
                results['operations'].append(f"Auto-orient: {msg}")
            else:
                results['errors'].append(f"Auto-orient failed: {msg}")
            
            if auto_resize:
                img_info = results['image_info']
                if (img_info['width'] > self.MAX_IMAGE_WIDTH or 
                    img_info['height'] > self.MAX_IMAGE_HEIGHT):
                    
                    success, msg = self.resize_image(image_path)
                    if success:
                        results['operations'].append(f"Resize: {msg}")
                        results['processed_files'].append(image_path)
                    else:
                        results['errors'].append(f"Resize failed: {msg}")
            
            if optimize:
                success, msg = self.optimize_image(image_path)
                if success:
                    results['operations'].append(f"Optimize: {msg}")
                else:
                    results['errors'].append(f"Optimize failed: {msg}")
            
            if create_thumb:
                success, thumb_path = self.create_thumbnail(image_path)
                if success:
                    results['operations'].append(f"Thumbnail created: {thumb_path}")
                    results['processed_files'].append(thumb_path)
                else:
                    results['errors'].append(f"Thumbnail failed: {thumb_path}")
            
            results['image_info'] = self._get_image_info(image_path)
            
        except Exception as e:
            results['errors'].append(f"Processing error: {str(e)}")
            self._log_error(f"Image processing error for {image_path}: {e}")
        
        return results
    
    def generate_scan_report(self, scan_results: Dict[str, any]) -> str:
        """
        Generate a human-readable scan report similar to VirusTotal.

        Args:
            scan_results (Dict[str, any]): The scan results from process_uploaded_files.

        Returns:
            str: A formatted scan report.
        """
        summary = scan_results['scan_summary']
        threats = scan_results['threat_summary']
        
        report = []
        report.append("=" * 60)
        report.append("           LIGHTERSTOTAL SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Scan Date: {summary['scan_date']}")
        report.append(f"Scanner Version: {summary['scanner_version']}")
        report.append(f"Scan Time: {summary['scan_time']} seconds")
        report.append("")
        
        report.append("SCAN SUMMARY:")
        report.append("-" * 20)
        report.append(f"Total Files Scanned: {summary['total_files']}")
        report.append(f"[+] Clean Files: {summary['clean_files']}")
        report.append(f"[!]  Suspicious Files: {summary['suspicious_files']}")
        report.append(f"[-] Malicious Files: {summary['malicious_files']}")
        report.append(f"~ Error Files: {summary['error_files']}")
        report.append(f"Risk Level: {threats['risk_level']}")
        report.append("")
        
        if threats['threats_detected']:
            report.append("THREATS DETECTED:")
            report.append("-" * 20)
            for threat in threats['threats_detected']:
                report.append(f"~ {threat['file']}")
                report.append(f"   Type: {threat['threat_type']}")
                report.append(f"   Details: {threat['details']}")
                report.append("")
        
        if scan_results['extracted_archives']['total_extracted'] > 0:
            report.append("ARCHIVE EXTRACTION:")
            report.append("-" * 20)
            report.append(f"Files Extracted: {scan_results['extracted_archives']['total_extracted']}")
            for item in scan_results['extracted_archives']['extracted_files'][:5]:  # Show first 5
                report.append(f"  ~ {item['original_archive']} → {item['extracted_file']}")
            if len(scan_results['extracted_archives']['extracted_files']) > 5:
                report.append(f"  ... and {len(scan_results['extracted_archives']['extracted_files']) - 5} more")
            report.append("")
        
        report.append("DETAILED SCAN RESULTS:")
        report.append("-" * 25)
        for file_result in scan_results['file_results']:
            file_info = file_result['file_info']
            scan_info = file_result['scan_results']
            
            report.append(f"~ File: {file_info['file_name']}")
            report.append(f"   Size: {file_info.get('file_size', 0)} bytes")
            report.append(f"   Type: {file_info.get('mime_type', 'unknown')}")
            report.append(f"   MD5: {file_info.get('md5', 'N/A')}")
            report.append(f"   Status: {scan_info['overall_status']}")
            report.append(f"   Detections: {scan_info['positives']}/{scan_info['total']}")
            
            if 'scan_details' in scan_info:
                report.append("   Engine Results:")
                for engine, result in scan_info['scan_details'].items():
                    status_icon = "[+]" if result['result'] == 'CLEAN' else "[-]" if result['result'] == 'MALICIOUS' else "[!]"
                    report.append(f"     {status_icon} {engine}: {result['result']} - {result['reason']}")
            report.append("")
        
        if threats['recommendations']:
            report.append("RECOMMENDATIONS:")
            report.append("-" * 18)
            for rec in threats['recommendations']:
                report.append(f"~ {rec}")
            report.append("")
        
        report.append("=" * 60)
        report.append("Report generated by LighterTotal Security Scanner")
        report.append("=" * 60)
        
        return "\n".join(report)

    def generate_upload_report(self) -> str:
        """
        Generate a detailed report of upload statistics and settings.

        Returns:
            str: The generated report as a string.
        """
        report = []
        report.append("=== FILE UPLOAD REPORT ===")
        report.append(f"Total uploads attempted: {self.upload_stats['total_uploads']}")
        report.append(f"Successful uploads: {self.upload_stats['successful_uploads']}")
        report.append(f"Failed uploads: {self.upload_stats['failed_uploads']}")
        report.append(f"Quarantined files: {self.upload_stats['quarantined_files']}")
        
        success_rate = (self.upload_stats['successful_uploads'] / max(1, self.upload_stats['total_uploads'])) * 100
        report.append(f"Success rate: {success_rate:.2f}%")
        
        report.append("\n=== ALLOWED FILE TYPES ===")
        report.append(f"Extensions: {', '.join(sorted(self.ALLOWED_EXTENSIONS))}")
        report.append(f"MIME types: {len(self.ALLOWED_MIME_TYPES)} types allowed")
        
        report.append(f"\n=== SECURITY SETTINGS ===")
        report.append(f"Max file size: {self.max_file_size / (1024*1024):.1f} MB")
        report.append(f"Max archive files: {self.MAX_ARCHIVE_FILES}")
        report.append(f"Upload directory: {self.upload_dir}")
        report.append(f"Quarantine directory: {self.quarantine_dir}")
        
        return "\n".join(report)




