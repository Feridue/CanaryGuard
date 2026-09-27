"""
Test Simulator — Phase 2
Safe, reversible, self-built ransomware-behavior test harness.
"""

import sys
from pathlib import Path

# Ensure imports resolve if run independently
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from evidence.logger import load_config


class RansomwareSimulator:
    def __init__(self):
        self.config = load_config()
        self.target_dir = Path(self.config["protected_dir"]).resolve()
        
    def _safety_check(self) -> None:
        """
        Ensure we are only running against the designated test sandbox directory.
        This prevents accidental runs against real folders.
        """
        # The expected suffix in the config is "test_sandbox"
        # We explicitly check for 'test_sandbox' in the path as a hard-coded safety guard
        if "test_sandbox" not in str(self.target_dir).lower():
            raise RuntimeError(
                f"SAFETY ABORT: Target directory {self.target_dir} does not appear "
                "to be the safe test sandbox. Simulator halted."
            )
            
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            raise RuntimeError(
                f"SAFETY ABORT: Target directory {self.target_dir} does not exist."
            )

    def run(self) -> int:
        """
        Iterates over files in the target directory, overwrites them with 
        garbage data, and renames them to append .locked. Finally, drops a ransom note.
        
        Returns the number of files affected.
        """
        print(f"[SIMULATOR] Starting safe run against: {self.target_dir}")
        self._safety_check()
        
        files_affected = 0
        
        for filepath in self.target_dir.iterdir():
            if not filepath.is_file():
                continue
                
            # Skip files that are already locked or the ransom note
            if filepath.name.endswith(".locked") or filepath.name == "RANSOM_NOTE.txt":
                continue
                
            try:
                # 1. Overwrite file content with garbage
                with open(filepath, "wb") as f:
                    f.write(b"ENCRYPTED_BY_SIMULATOR\x00\x01\x02" * 50)
                    
                # 2. Rename file to append .locked
                locked_path = filepath.with_name(filepath.name + ".locked")
                filepath.rename(locked_path)
                
                print(f"[SIMULATOR] Locked: {filepath.name}")
                files_affected += 1
            except Exception as e:
                print(f"[SIMULATOR] Error processing {filepath.name}: {e}")
                
        # 3. Drop ransom note
        note_path = self.target_dir / "RANSOM_NOTE.txt"
        try:
            with open(note_path, "w", encoding="utf-8") as f:
                f.write(
                    "YOUR FILES HAVE BEEN 'ENCRYPTED' BY THE CANARYGUARD SIMULATOR.\n\n"
                    "This is a safe test. No real damage has occurred. "
                    "Run CanaryManager.plant_canaries() to restore the original files.\n"
                )
            print(f"[SIMULATOR] Dropped ransom note: {note_path.name}")
        except Exception as e:
            print(f"[SIMULATOR] Error dropping note: {e}")
            
        print(f"[SIMULATOR] Finished. Total files affected: {files_affected}")
        return files_affected


if __name__ == "__main__":
    sim = RansomwareSimulator()
    sim.run()
