"""
Real-time monitoring agent for ransomware detection.

This script:
- Monitors file system activity using watchdog.
- Monitors CPU/RAM/process information using psutil.
- Samples basic network statistics.
- Aggregates metrics into a single feature vector per interval.
- Sends features to the backend Flask API for classification and response.

For safety and portability, this agent focuses on behavioral telemetry and
does NOT execute any real ransomware. It is safe to run on a normal system.
"""

import json
import os
import queue
import socket
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any

import psutil
import requests
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer


BACKEND_API_URL = "http://127.0.0.1:5000/api/ingest_features"


@dataclass
class FeatureSnapshot:
    timestamp: float
    hostname: str
    file_modification_rate: float
    entropy_rate: float
    avg_file_size_kb: float
    num_files_touched: int
    cpu_usage: float
    memory_usage: float
    num_api_calls: int
    network_bytes_sent: float
    network_bytes_recv: float
    suspicious_extension_ratio: float
    registry_modifications: int
    failed_file_accesses: int


class FileActivityHandler(FileSystemEventHandler):
    """
    Collect basic file activity statistics.
    This is a simplified approximation suitable for demonstration.
    """

    def __init__(self, state: Dict[str, Any]) -> None:
        super().__init__()
        self.state = state

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        self.state["num_files_touched"] += 1

        # Track approximate file modification count
        if event.event_type in ("modified", "created", "moved"):
            self.state["file_modifications"] += 1

        # Suspicious extensions (simplified)
        suspicious_exts = {".encrypted", ".locked", ".enc", ".crypto"}
        _, ext = os.path.splitext(event.src_path)
        if ext.lower() in suspicious_exts:
            self.state["suspicious_files"] += 1


class MonitoringAgent:
    def __init__(self, watch_path: str, interval_seconds: int = 5) -> None:
        self.watch_path = watch_path
        self.interval_seconds = interval_seconds
        self.hostname = socket.gethostname()

        # Shared state for file activity
        self.file_state: Dict[str, Any] = {
            "file_modifications": 0,
            "num_files_touched": 0,
            "suspicious_files": 0,
        }

        self.stop_event = threading.Event()
        self.event_queue: "queue.Queue[FeatureSnapshot]" = queue.Queue()

    def start(self) -> None:
        print(f"[AGENT] Starting monitoring on: {self.watch_path}")

        # Start watchdog observer
        event_handler = FileActivityHandler(self.file_state)
        observer = Observer()
        observer.schedule(event_handler, self.watch_path, recursive=True)
        observer.start()

        try:
            producer_thread = threading.Thread(
                target=self._collect_loop, name="FeatureCollector", daemon=True
            )
            consumer_thread = threading.Thread(
                target=self._send_loop, name="FeatureSender", daemon=True
            )
            producer_thread.start()
            consumer_thread.start()

            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            print("[AGENT] Shutting down (KeyboardInterrupt)...")
            self.stop_event.set()
        finally:
            observer.stop()
            observer.join()

    def _collect_loop(self) -> None:
        while not self.stop_event.is_set():
            start = time.time()
            snapshot = self._collect_features()
            self.event_queue.put(snapshot)
            elapsed = time.time() - start
            remaining = self.interval_seconds - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def _send_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                snapshot = self.event_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            payload = asdict(snapshot)
            try:
                resp = requests.post(BACKEND_API_URL, json=payload, timeout=3)
                if resp.status_code != 200:
                    print(
                        f"[AGENT] Backend responded with status {resp.status_code}: {resp.text}"
                    )
                else:
                    data = resp.json()
                    status = data.get("prediction_label", "unknown")
                    score = data.get("prediction_score", 0.0)
                    print(
                        f"[AGENT] Classification: {status} (score={score:.3f}) at {time.ctime(snapshot.timestamp)}"
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"[AGENT] Error sending data to backend: {exc}")

    def _collect_features(self) -> FeatureSnapshot:
        """
        Convert current system state into a feature vector.
        This can be extended with richer telemetry (API hooks, registry, etc.).
        """
        timestamp = time.time()

        # CPU and memory
        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        memory_usage = mem.percent

        # Network
        net_io = psutil.net_io_counters()
        network_bytes_sent = float(net_io.bytes_sent)
        network_bytes_recv = float(net_io.bytes_recv)

        # Process-level approximations
        num_api_calls = 0
        failed_file_accesses = 0
        registry_modifications = 0  # Placeholder; Windows-specific APIs needed

        for proc in psutil.process_iter(attrs=["pid", "name", "io_counters"]):
            try:
                io = proc.info.get("io_counters")
                if io:
                    # Approximate "API calls" by number of read/write ops
                    num_api_calls += int(io.read_count + io.write_count)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                failed_file_accesses += 1
                continue

        # File stats from watchdog state
        file_modifications = self.file_state.get("file_modifications", 0)
        num_files_touched = self.file_state.get("num_files_touched", 0)
        suspicious_files = self.file_state.get("suspicious_files", 0)

        # Reset counters for next interval
        self.file_state["file_modifications"] = 0
        self.file_state["num_files_touched"] = 0
        self.file_state["suspicious_files"] = 0

        # Approximate "entropy_rate" and "avg_file_size_kb" in a cheap, safe way:
        # we just sample a handful of files from the watched directory.
        sampled_sizes = []
        for root, _, files in os.walk(self.watch_path):
            for f in files[:50]:
                try:
                    path = os.path.join(root, f)
                    size_kb = os.path.getsize(path) / 1024.0
                    sampled_sizes.append(size_kb)
                except (FileNotFoundError, PermissionError):
                    continue
            break

        if sampled_sizes:
            avg_file_size_kb = float(sum(sampled_sizes) / len(sampled_sizes))
            # Use variance as a cheap "entropy-like" indicator
            entropy_rate = float(
                (sum((s - avg_file_size_kb) ** 2 for s in sampled_sizes) / len(sampled_sizes))
                ** 0.5
            )
        else:
            avg_file_size_kb = 0.0
            entropy_rate = 0.0

        # Derived metrics
        file_modification_rate = float(file_modifications) / max(
            1, self.interval_seconds
        )
        suspicious_extension_ratio = (
            float(suspicious_files) / max(1, num_files_touched)
        )

        snapshot = FeatureSnapshot(
            timestamp=timestamp,
            hostname=self.hostname,
            file_modification_rate=file_modification_rate,
            entropy_rate=entropy_rate,
            avg_file_size_kb=avg_file_size_kb,
            num_files_touched=num_files_touched,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            num_api_calls=num_api_calls,
            network_bytes_sent=network_bytes_sent,
            network_bytes_recv=network_bytes_recv,
            suspicious_extension_ratio=suspicious_extension_ratio,
            registry_modifications=registry_modifications,
            failed_file_accesses=failed_file_accesses,
        )
        return snapshot


def main() -> None:
    watch_path = os.path.abspath(".")
    agent = MonitoringAgent(watch_path=watch_path, interval_seconds=5)
    agent.start()


if __name__ == "__main__":
    main()

