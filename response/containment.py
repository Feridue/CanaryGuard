"""
Responder / Containment — Phase 7
Handles the containment logic (Observe, Approval, Automatic modes).
Uses PowerShell WinRT toasts for desktop notifications (reliable on Windows 10/11).
"""

import subprocess
import sys
import psutil
from typing import Dict, List, Any
from evidence.logger import EvidenceLogger


def _send_desktop_notification(title: str, message: str) -> None:
    """
    Fires a native Windows 10/11 toast notification via PowerShell.
    Uses PowerShell's own registered App ID so Windows always delivers it.
    Raises RuntimeError on failure.
    """
    title_safe   = title.replace("'", "''").replace('"', '')
    message_safe = message.replace("'", "''").replace('"', '')

    ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$AppID = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe'

$template = @'
<toast duration="long">
    <visual>
        <binding template="ToastGeneric">
            <text>{title_safe}</text>
            <text>{message_safe}</text>
        </binding>
    </visual>
</toast>
'@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppID).Show($toast)
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

class Responder:
    def __init__(self, logger: EvidenceLogger):
        self.logger = logger
        # Default allowlist for OS-critical processes if not in config
        self.allowlist = self.logger.config.get("allowlist", [
            "svchost.exe", "explorer.exe", "csrss.exe", "smss.exe", 
            "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", 
            "taskmgr.exe", "system", "system idle process"
        ])
        
    def _is_allowed(self, name: str) -> bool:
        if not name:
            return False
        name_lower = name.lower()
        return any(allowed.lower() == name_lower for allowed in self.allowlist)
        
    def suspend_process(self, pid: int) -> bool:
        """Suspends a running process by its PID."""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            self.logger.log_system_event(f"Suspended process PID {pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.log_system_event(f"Failed to suspend PID {pid}: {e}")
            return False
            
    def resume_process(self, pid: int) -> bool:
        """Resumes a suspended process by its PID."""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            self.logger.log_system_event(f"Resumed process PID {pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.log_system_event(f"Failed to resume PID {pid}: {e}")
            return False

    def handle_incident(self, incident: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Determines and executes the appropriate response based on the active mode.
        Fires a desktop notification first.
        """
        # Package candidates into the incident
        incident["candidates"] = candidates
        
        # Fire desktop notification (best-effort; never crashes the containment loop)
        try:
            canary_name = "Unknown Canary"
            if incident.get("affected_canaries"):
                canary_name = incident["affected_canaries"][0].get("canary_name", "Unknown Canary")

            suspect_name = "Unknown"
            confidence   = "None"
            if candidates:
                suspect_name = candidates[0].get("name", "Unknown")
                confidence   = candidates[0].get("confidence", "Unknown")

            _send_desktop_notification(
                title   = "CanaryGuard Incident Detected",
                message = f"Canary Tampered: {canary_name} | Suspect: {suspect_name} ({confidence})"
            )
        except Exception as e:
            self.logger._console.error(f"[RESPONDER] Desktop notification failed: {e}")
        
        mode = self.logger.mode
        
        if mode == "Observe":
            incident["decision"] = "observe"
            incident["action_taken"] = "none"
            
            # Identify the top candidate for logging context, if any
            top_suspect = candidates[0] if candidates else None
            
            if top_suspect:
                self.logger._console.warning(
                    f"[OBSERVE MODE] Incident detected. Top suspect: {top_suspect.get('name')} "
                    f"(PID {top_suspect.get('pid')}) with {top_suspect.get('confidence', 'Unknown')} confidence."
                )
            else:
                self.logger._console.warning("[OBSERVE MODE] Incident detected. No candidates found.")
                
            self.logger._console.info("[OBSERVE MODE] No action taken.")
            
        elif mode == "Approval":
            if not candidates:
                self.logger._console.info("[APPROVAL MODE] Incident detected, but no candidates found. No action taken.")
                incident["decision"] = "denied"
                incident["action_taken"] = "none"
                return incident
                
            top_suspect = candidates[0]
            pid = top_suspect.get("pid")
            name = top_suspect.get("name")
            conf = top_suspect.get("confidence")
            expl = top_suspect.get("explanation")
            
            print("\n" + "="*60)
            print("  🚨 [APPROVAL REQUIRED] 🚨")
            print("="*60)
            print(f"  Incident  : {incident.get('files_affected_count')} canary files tampered")
            print(f"  Suspect   : {name} (PID: {pid})")
            print(f"  Confidence: {conf}")
            print(f"  Evidence  : {expl}")
            print("="*60)
            
            choice = "n"
            try:
                if sys.stdin is not None:
                    choice = input(f"\nSuspend process {name} (PID {pid})? (y/n): ").strip().lower()
                else:
                    raise EOFError("No stdin")
            except (EOFError, OSError):
                # Running as a background or GUI app without terminal stdin
                try:
                    import tkinter as tk
                    from tkinter import messagebox
                    root = tk.Tk()
                    root.withdraw()
                    root.attributes("-topmost", True)
                    dialog_msg = (
                        f"🚨 CanaryGuard Ransomware Alert!\n\n"
                        f"Incident: {incident.get('files_affected_count', 0)} canary file(s) tampered.\n"
                        f"Suspect: {name} (PID {pid})\n"
                        f"Confidence: {conf}\n\n"
                        f"Evidence:\n{expl}\n\n"
                        f"Do you want to suspend this process immediately?"
                    )
                    approved = messagebox.askyesno(
                        "CanaryGuard — Approval Required",
                        dialog_msg,
                        icon="warning"
                    )
                    root.destroy()
                    choice = "y" if approved else "n"
                except Exception as exc:
                    self.logger._console.warning(f"[APPROVAL MODE] GUI prompt failed: {exc}, defaulting to deny.")
                    choice = "n"

                
            if choice == 'y':
                success = self.suspend_process(pid)
                if success:
                    incident["decision"] = "approved"
                    incident["action_taken"] = "suspended"
                else:
                    incident["decision"] = "approved"
                    incident["action_taken"] = "failed"
            else:
                self.logger._console.info("[APPROVAL MODE] Operator denied suspension.")
                incident["decision"] = "denied"
                incident["action_taken"] = "none"
            
        elif mode == "Automatic":
            if not candidates:
                self.logger._console.info("[AUTOMATIC MODE] Incident detected, but no candidates found. No action taken.")
                incident["decision"] = "denied"
                incident["action_taken"] = "none"
                return incident
                
            top_suspect = candidates[0]
            pid = top_suspect.get("pid")
            name = top_suspect.get("name")
            conf = top_suspect.get("confidence")
            
            # Check 1: Must be High confidence
            if conf != "High":
                self.logger._console.warning(f"[AUTOMATIC MODE] Top suspect {name} confidence is '{conf}' (too low). Aborting suspension.")
                incident["decision"] = "denied"
                incident["action_taken"] = "none"
                return incident
                
            # Check 2: Must not be on allowlist
            if self._is_allowed(name):
                self.logger._console.warning(f"[AUTOMATIC MODE] Top suspect {name} is on the OS allowlist! Aborting suspension.")
                incident["decision"] = "allowlisted"
                incident["action_taken"] = "none"
                return incident
                
            # Both checks passed, execute automatic suspension
            self.logger._console.warning(f"[AUTOMATIC MODE] Threat criteria met. Automatically suspending {name} (PID {pid})...")
            success = self.suspend_process(pid)
            
            if success:
                incident["decision"] = "auto_suspended"
                incident["action_taken"] = "suspended"
            else:
                incident["decision"] = "auto_suspended"
                incident["action_taken"] = "failed"
            
        return incident
