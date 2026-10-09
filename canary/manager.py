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
        self.monitored_folders: list = list(self.logger.config.get("monitored_folders", []))
        
        # Maps original filename/path -> dict of baseline info (path, size, hash, mtime)
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
        for all configured canary files in the protected directory as well as
        any files inside monitored folders.
        """
        self.baselines.clear()
        
        # 1. Base protected directory canaries
        for filename in self.canary_filenames:
            filepath = self.protected_dir / filename
            if filepath.exists() and filepath.is_file():
                try:
                    stat = filepath.stat()
                    self.baselines[filename] = {
                        "path": filepath,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "hash": self._hash_file(filepath)
                    }
                except OSError:
                    pass

        # 2. Files inside monitored folders (recursive)
        for folder_str in self.monitored_folders:
            folder_p = Path(folder_str)
            if folder_p.exists() and folder_p.is_dir():
                try:
                    for f in folder_p.rglob("*"):
                        if f.is_file():
                            key = str(f.resolve())
                            try:
                                stat = f.stat()
                                self.baselines[key] = {
                                    "path": f,
                                    "size": stat.st_size,
                                    "mtime": stat.st_mtime,
                                    "hash": self._hash_file(f)
                                }
                            except OSError:
                                pass
                except OSError:
                    pass

    def add_folder(self, folderpath: str) -> bool:
        """Add a directory to monitor recursively."""
        p = Path(folderpath).resolve()
        if not p.exists() or not p.is_dir():
            return False
        p_str = str(p)
        if p_str in self.monitored_folders:
            return False

        self.monitored_folders.append(p_str)
        self.logger.config["monitored_folders"] = list(self.monitored_folders)
        self._record_baseline()
        self.logger.log_system_event(f"Monitored folder added: {p_str}", extra={"total_folders": len(self.monitored_folders)})
        return True

    def remove_folder(self, folderpath: str) -> bool:
        """Remove a directory from monitoring."""
        p_resolved = Path(folderpath).resolve()
        matched = None
        for f in self.monitored_folders:
            if Path(f).resolve() == p_resolved:
                matched = f
                break
        if not matched:
            return False

        self.monitored_folders.remove(matched)
        self.logger.config["monitored_folders"] = list(self.monitored_folders)
        p_str = str(p_resolved)
        to_del = [k for k, v in self.baselines.items() if str(Path(v["path"]).resolve()).startswith(p_str)]
        for k in to_del:
            self.baselines.pop(k, None)
        self.logger.log_system_event(f"Monitored folder removed: {matched}")
        return True

    def is_path_monitored(self, path: Path) -> Optional[str]:
        """Check if a file path is a canary file or inside a monitored folder."""
        # Exact name in canary_filenames inside protected_dir
        if path.name in self.canary_filenames:
            return path.name

        resolved = path.resolve()
        # Inside protected_dir
        try:
            if resolved.is_relative_to(self.protected_dir.resolve()):
                return path.name
        except (ValueError, AttributeError):
            if str(resolved).startswith(str(self.protected_dir.resolve())):
                return path.name

        # Inside any monitored folder
        for folder_str in self.monitored_folders:
            folder_p = Path(folder_str).resolve()
            try:
                if resolved.is_relative_to(folder_p):
                    return str(path)
            except (ValueError, AttributeError):
                if str(resolved).startswith(str(folder_p)):
                    return str(path)

        return None

    def verify_canary(self, original_name: str, current_path: Optional[Path] = None) -> str:
        """
        Verify the current state of a canary file or folder file against its baseline.
        """
        baseline = None
        if original_name in self.baselines:
            baseline = self.baselines[original_name]
        else:
            # Check by matching resolved path or filename
            for k, b in self.baselines.items():
                if k == original_name or Path(k).name == original_name or str(b["path"]) == original_name:
                    baseline = b
                    break

        if not baseline:
            # Check if newly created file inside a monitored folder
            check_p = current_path if current_path else Path(original_name)
            if check_p.exists():
                return "created"
            return "unknown"

        baseline_path = baseline["path"]
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

            current_hash = self._hash_file(check_path)
            if current_hash != baseline["hash"]:
                return "modified"
        except OSError:
            return "deleted"

        return "unchanged"

