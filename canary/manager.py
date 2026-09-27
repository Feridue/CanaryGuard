"""
Canary Manager — Phase 1
Responsible for planting, hashing, and verifying decoy files.
"""

import hashlib
import os
from pathlib import Path
from typing import Dict, Any, Optional

from evidence.logger import EvidenceLogger


class CanaryManager:
    def __init__(self, logger: EvidenceLogger):
        self.logger = logger
        self.protected_dir = Path(self.logger.protected_dir)
        self.canary_filenames = self.logger.canary_files
        self.canary_file_types = self.logger.canary_file_types
        
        # Maps original filename -> dict of baseline info (path, size, hash, mtime)
        self.baselines: Dict[str, Dict[str, Any]] = {}
        
    def plant_canaries(self) -> None:
        """
        Create the protected directory if it doesn't exist, generate the 
        synthetic canary files, and record their baseline state.
        """
        self.protected_dir.mkdir(parents=True, exist_ok=True)
        
        for filename in self.canary_filenames:
            filepath = self.protected_dir / filename
            
            # Generate synthetic content
            ext = filepath.suffix.lower()
            content = self._generate_synthetic_content(ext)
            
            # Write file (overwrite if exists to ensure pristine state)
            with open(filepath, "wb") as f:
                f.write(content)
                
            self.logger._console.info(f"Planted canary: {filename}")
            
        self._record_baseline()
        self.logger.log_system_event("Canaries planted and baselined", extra={"count": len(self.baselines)})

    def _generate_synthetic_content(self, ext: str) -> bytes:
        """
        Generate harmless synthetic byte content tailored to the file extension.
        """
        if ext == ".txt":
            return b"This is a confidential backup file. Do not distribute.\n" * 10
        elif ext == ".pdf":
            # Very basic PDF header to look slightly legitimate to magic-byte checkers
            return b"%PDF-1.4\n%...\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + (b"mock_data " * 20)
        elif ext in [".docx", ".xlsx"]:
            # Fake zip header for Office Open XML formats (PK\x03\x04)
            return b"PK\x03\x04\n" + (b"mock_data " * 20)
        else:
            return b"generic canary content " * 10

    def _hash_file(self, filepath: Path) -> str:
        """
        Compute the SHA-256 hash of a file.
        Returns empty string if file cannot be read.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except OSError:
            return ""

    def _record_baseline(self) -> None:
        """
        Record the baseline metadata (path, size, hash, modification time)
        for all configured canary files in the protected directory.
        """
        self.baselines.clear()
        for filename in self.canary_filenames:
            filepath = self.protected_dir / filename
            if filepath.exists():
                stat = filepath.stat()
                self.baselines[filename] = {
                    "path": filepath,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "hash": self._hash_file(filepath)
                }

    def verify_canary(self, original_name: str, current_path: Optional[Path] = None) -> str:
        """
        Verify the current state of a canary file against its baseline.
        
        Args:
            original_name: The expected baseline filename (e.g., 'passwords.txt').
            current_path: The file's current path (useful if it was renamed). 
                          If None, we check the baseline path.
                          
        Returns:
            A string classification: 'unchanged', 'modified', 'renamed', 
            'extension-changed', or 'deleted'.
        """
        if original_name not in self.baselines:
            return "unknown"
            
        baseline = self.baselines[original_name]
        baseline_path = baseline["path"]
        
        # If no current path is given, assume we're checking the original path
        check_path = current_path if current_path else baseline_path
        
        if not check_path.exists():
            return "deleted"
            
        # Check for rename / extension change
        if check_path.name != baseline_path.name:
            if check_path.suffix != baseline_path.suffix:
                return "extension-changed"
            return "renamed"
            
        # Check for modification
        try:
            current_stat = check_path.stat()
            if current_stat.st_size != baseline["size"]:
                return "modified"
            
            # If size matches, do a full hash comparison
            current_hash = self._hash_file(check_path)
            if current_hash != baseline["hash"]:
                return "modified"
                
        except OSError:
            # If we can't stat/read it, it might be locked or deleted during check
            return "deleted"
            
        return "unchanged"
