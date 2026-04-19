#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Worker - Windows Service Wrapper
======================================
Runs the SNMP Worker as a native Windows Service using pywin32.

Benefits vs. running from cmd.exe:
  - Starts automatically at Windows boot (no user login required)
  - Runs in the background without a visible CMD window
  - Uses less CPU: the Windows SCM (Service Control Manager) manages the
    process at a lower scheduling priority than an interactive console window
  - Restarts automatically on failure
  - Proper logging via the Windows Event Log in addition to file logs

Installation (run as Administrator in the snmp_worker directory):
  python windows_service.py install
  python windows_service.py start
  python windows_service.py stop
  python windows_service.py remove

Or use the helper script:
  install_service.bat

Requires: pip install pywin32
"""

import sys
import os
import time
import threading

# ── Windows-only guard ────────────────────────────────────────────────────────
if sys.platform != 'win32':
    print("This script is only for Windows.  Use the systemd service on Linux.")
    sys.exit(1)

try:
    import win32serviceutil
    import win32service
    import win32event
    import win32process
    import win32api
    import servicemanager
    import socket
except ImportError:
    print("=" * 60)
    print("ERROR: pywin32 is required to run as a Windows Service.")
    print("=" * 60)
    print("\nInstall it with:")
    print("  pip install pywin32")
    print("  python -m pywin32_postinstall -install")
    print("\nOr run the helper script:")
    print("  install_service.bat")
    sys.exit(1)


# ── Service metadata ─────────────────────────────────────────────────────────
_SERVICE_NAME    = "SNMPWorker"
_SERVICE_DISPLAY = "SNMP Worker - Network Monitoring"
_SERVICE_DESC    = (
    "Monitors network switches via SNMP and writes port/alarm data "
    "to the database for the Switchp web dashboard."
)


class SNMPWorkerService(win32serviceutil.ServiceFramework):
    """
    Windows Service that wraps the SNMPWorker main loop.

    The service starts the worker in a background thread so that the SCM's
    SvcDoRun() can respond to stop/pause requests promptly.
    """

    _svc_name_         = _SERVICE_NAME
    _svc_display_name_ = _SERVICE_DISPLAY
    _svc_description_  = _SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        # Win32 event: set by SvcStop() to wake SvcDoRun's WaitForSingleObject
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        # SNMPWorker instance (set by the worker thread)
        self._worker = None
        # Background thread that runs _run_worker()
        self._worker_thread = None

    def GetAcceptedControls(self):
        """Only accept STOP and SHUTDOWN — no PAUSE/CONTINUE."""
        return win32service.SERVICE_ACCEPT_STOP | win32service.SERVICE_ACCEPT_SHUTDOWN

    # ── SCM entry points ──────────────────────────────────────────────────────

    def SvcStop(self):
        """Called by the SCM when the service is stopped."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        servicemanager.LogInfoMsg(f"{_SERVICE_NAME}: Stop requested")

        # Ask the SNMPWorker main loop to exit (thread-safe via stop())
        if self._worker is not None:
            self._worker.stop()

        # Wake SvcDoRun so it can join the worker thread and return
        win32event.SetEvent(self._stop_event)

    def SvcShutdown(self):
        """Called by the SCM on system shutdown (SERVICE_ACCEPT_SHUTDOWN)."""
        servicemanager.LogInfoMsg(f"{_SERVICE_NAME}: System shutdown received")
        self.SvcStop()

    def SvcDoRun(self):
        """
        Main service body — called by the SCM after start.

        IMPORTANT: The SCM calls SvcDoRun from a non-main Python thread.
        Therefore we must NOT call signal.signal() here (or in anything we
        call from here).  SNMPWorker handles this by wrapping signal
        registration in try/except so it is silently skipped in service mode.

        We run the worker in a separate daemon thread and block this SCM
        thread on a Win32 event.  That way:
          - SvcStop() can unblock us at any time via SetEvent()
          - The worker thread can run independently without holding the SCM thread
        """
        servicemanager.LogInfoMsg(f"{_SERVICE_NAME}: Starting")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        # Launch the worker in a daemon thread so the SCM thread is free
        self._worker_thread = threading.Thread(
            target=self._run_worker,
            name="SNMPWorkerThread",
            daemon=True,
        )
        self._worker_thread.start()

        # Block until SvcStop() fires the stop event
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

        # Give the worker thread up to 30 s to finish cleanly
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=30)

        servicemanager.LogInfoMsg(f"{_SERVICE_NAME}: Stopped")

    # ── Worker management ─────────────────────────────────────────────────────

    def _run_worker(self):
        """Initialise and run the SNMPWorker in this thread."""
        # Ensure we run from the directory that contains worker.py
        service_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(service_dir)
        if service_dir not in sys.path:
            sys.path.insert(0, service_dir)

        # Lower the process priority to BELOW_NORMAL so that MySQL (XAMPP)
        # and the web server always get CPU before this monitoring service.
        # This is the single biggest win from running as a service: we can
        # yield nicely without affecting alarm latency (network I/O dominates,
        # not CPU).
        try:
            handle = win32api.OpenProcess(
                win32process.PROCESS_SET_INFORMATION,
                False,
                os.getpid(),
            )
            try:
                win32process.SetPriorityClass(
                    handle,
                    win32process.BELOW_NORMAL_PRIORITY_CLASS,
                )
            finally:
                win32api.CloseHandle(handle)
        except Exception as exc:
            servicemanager.LogInfoMsg(
                f"{_SERVICE_NAME}: Could not set process priority: {exc}"
            )

        # Windows Services have no console — sys.stdout/sys.stderr are None.
        # worker.py has module-level print() calls (diagnostic import output)
        # that would raise AttributeError on a None stream.  Redirect None
        # streams to NUL so those calls are silently discarded.
        # _devnull is closed in the finally block below once the worker exits.
        _devnull = open(os.devnull, 'w', encoding='utf-8', errors='replace')
        if sys.stdout is None:
            sys.stdout = _devnull
        if sys.stderr is None:
            sys.stderr = _devnull

        try:
            # Lazy-import so pywin32 isn't required just to import this module
            try:
                from worker import SNMPWorker
            except BaseException as exc:
                import traceback
                servicemanager.LogErrorMsg(
                    f"{_SERVICE_NAME}: Failed to import SNMPWorker: {exc}\n"
                    f"{traceback.format_exc()}"
                )
                return

            config_path = os.path.join(service_dir, 'config', 'config.yml')
            if not os.path.exists(config_path):
                config_path = None

            try:
                self._worker = SNMPWorker(config_file=config_path)
            except BaseException as exc:
                import traceback
                servicemanager.LogErrorMsg(
                    f"{_SERVICE_NAME}: Failed to initialise SNMPWorker: {exc}\n"
                    f"{traceback.format_exc()}"
                )
                return

            # Run the worker.  SNMPWorker.run() blocks until self._worker.running
            # is set to False (which SvcStop() does).
            try:
                exit_code = self._worker.run()
                if exit_code:
                    servicemanager.LogWarningMsg(
                        f"{_SERVICE_NAME}: Worker exited with code {exit_code}"
                    )
            except BaseException as exc:
                import traceback
                servicemanager.LogErrorMsg(
                    f"{_SERVICE_NAME}: Worker loop error: {exc}\n"
                    f"{traceback.format_exc()}"
                )

        finally:
            # Close the NUL redirect handle now that the worker has exited.
            # Restore streams to None so any post-exit caller also gets None
            # rather than a closed file handle.
            if sys.stdout is _devnull:
                sys.stdout = None
            if sys.stderr is _devnull:
                sys.stderr = None
            _devnull.close()
            # Wake SvcDoRun in case the worker exited on its own (e.g. fatal error)
            # so SvcDoRun does not block on WaitForSingleObject forever.
            win32event.SetEvent(self._stop_event)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    """
    Handle command-line verbs:
      install / update / remove / start / stop / restart / status / debug
    When called by the SCM with no arguments, hand off to HandleCommandLine.
    """
    if len(sys.argv) == 1:
        # Launched by SCM
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SNMPWorkerService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as exc:
            print(f"Service dispatcher error: {exc}")
            sys.exit(1)
    else:
        win32serviceutil.HandleCommandLine(SNMPWorkerService)


if __name__ == '__main__':
    main()
