import socket
import subprocess
import time
from contextlib import closing
from queue import Empty, Queue
from threading import Thread
from typing import IO, override

from boofuzz.monitors import BaseMonitor
from boofuzz.sessions import Session

START_TIMEOUT = 60.0
START_INTERVAL = 1.0


class MinecraftServer(BaseMonitor):
    start_command: list[str]
    full_log: Queue[str]
    current_log: str
    return_code: int
    process: subprocess.Popen | None
    address: str
    port: int

    def __init__(self, start_command: list[str], address: str, port: int):
        self.start_command = start_command
        self.address = address
        self.port = port
        self.full_log = Queue()
        self.current_log = ""
        self.return_code = 0
        self.process = None

    @override
    def alive(self) -> bool:
        return True

    @override
    def get_crash_synopsis(self) -> str:
        self.post_send()
        return f"process returned exit code {self.return_code}:\n{self.current_log}"

    def _post_send(self) -> bool:
        lines = 0
        try:
            while True:
                self.current_log += self.full_log.get_nowait()
                lines += 1
        except Empty:
            print(f"read {lines} output lines")
        if self.process is None:
            return False
        code = self.process.poll()
        if code:
            self.return_code = code
            self.process = None
            return False
        return True

    @override
    def post_send(
        self, target=None, fuzz_data_logger=None, session: Session | None = None
    ) -> bool:
        index = "unknown"
        if session:
            index = session.total_mutant_index
        print(f"post_send test {index}")
        res = self._post_send()
        print("finished post_send")
        return res

    @override
    def retrieve_data(self) -> str:
        return f"Server Log:\n{self.current_log}"

    @override
    def pre_send(
        self, target=None, fuzz_data_logger=None, session: Session | None = None
    ):
        self.current_log = ""
        index = "unknown"
        if session:
            index = session.total_mutant_index
        print(f"pre_send test {index}")
        if not self.process:
            self.start_target()

    @staticmethod
    def _enqueue_output(out: IO, queue: Queue):
        for line in iter(out.readline, b""):
            queue.put(line if isinstance(line, str) else line.decode("utf-8"))
        out.close()

    def _wait_started(self) -> bool:
        start_time = time.time()
        while True:
            print("waiting for target to start...")
            try:
                while True:
                    print("server log:", self.full_log.get_nowait())
            except Empty:
                pass
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.settimeout(START_INTERVAL)
                    result = s.connect_ex((self.address, self.port))
                    if result == 0:
                        s.close()
                        print("waiting 3 seconds for the target to settle...")
                        time.sleep(3)
                        print("target started")
                        return True
            except socket.error as e:
                print(f"socket error: {e}")

            if time.time() - start_time >= START_TIMEOUT:
                print("timed out waiting for target")
                return False

            time.sleep(START_INTERVAL)

    @override
    def start_target(self) -> bool:
        self.current_log = ""
        print("starting target...")
        if self.process:
            self._post_send()
            if self.process:
                print("target already running")
                return True
        self.process = subprocess.Popen(
            self.start_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        t = Thread(
            target=self._enqueue_output, args=(self.process.stdout, self.full_log)
        )
        t.daemon = True
        t.start()
        print("target starting up...")
        return self._wait_started()

    @override
    def stop_target(self):
        print("stopping target...")
        if not self.process:
            print("no target to stop")
            return
        self.process.kill()
        self.process.wait()
        print("stopped target")

    @override
    def restart_target(self, target=None, fuzz_data_logger=None, session=None) -> bool:
        self.stop_target()
        return self.start_target()
