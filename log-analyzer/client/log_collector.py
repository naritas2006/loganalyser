import time
import os
import threading
import platform
from datetime import datetime

if platform.system() == "Windows":
    import win32evtlog

class LogCollector:
    def __init__(self, log_paths):
        self.log_paths = log_paths
        self.log_queue = []
        self.file_pointers = {}
        self.lock = threading.Lock()
        self.last_event_check = datetime.utcnow()
        
        # Initialize file pointers to the end of the file
        for source, path in self.log_paths.items():
            if os.path.exists(path):
                self.file_pointers[source] = os.path.getsize(path)
            else:
                self.file_pointers[source] = 0

    def start_collecting(self, interval=1.0):
        """Starts a background thread to collect logs continuously."""
        threading.Thread(target=self._collect_logs_loop, args=(interval,), daemon=True).start()

    def _collect_logs_loop(self, interval):
        while True:
            if platform.system() == "Windows":
                self._collect_windows_events()

            for source, path in self.log_paths.items():
                if not os.path.exists(path):
                    continue
                    
                try:
                    current_size = os.path.getsize(path)
                except FileNotFoundError:
                    continue

                last_size = self.file_pointers.get(source, 0)
                
                if current_size < last_size:
                    # Log rotation detected
                    self.file_pointers[source] = 0
                    last_size = 0
                    
                if current_size > last_size:
                    try:
                        # Open with ignore to avoid decoding errors for special character logs
                        with open(path, 'r', errors='ignore') as f:
                            f.seek(last_size)
                            new_lines = f.readlines()
                            self.file_pointers[source] = f.tell()
                            
                            with self.lock:
                                for line in new_lines:
                                    if line.strip(): # Ignore empty lines
                                        self.log_queue.append({
                                            "raw_logs": line.strip(),
                                            "log_source": source
                                        })
                    except Exception as e:
                        print(f"Error reading {path}: {e}")
            time.sleep(interval)

    def get_batch(self):
        """Returns the current log queue and clears it."""
        with self.lock:
            batch = list(self.log_queue)
            self.log_queue.clear()
            return batch

    def _collect_windows_events(self):
        if platform.system() != "Windows":
            return

        for log_name in ["Application", "System"]:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    if event.TimeGenerated > self.last_event_check:
                        with self.lock:
                            self.log_queue.append({
                                "raw_logs": str(event.StringInserts),
                                "log_source": f"windows_{log_name.lower()}"
                            })
                
                self.last_event_check = datetime.now()
                win32evtlog.CloseEventLog(hand)

            except Exception as e:
                print(f"Error querying Windows Event Log for {log_name}: {e}")
