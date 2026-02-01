import tftpy
import threading
import os

class AgentTFTPServer:
    def __init__(self, tftp_root, port=1069):
        self.tftp_root = tftp_root
        self.port = port
        self._thread = None
        self._server = tftpy.TftpServer(self.tftp_root)

    def start(self):
        def run():
            print(f"[TFTP] Starting TFTP server on 0.0.0.0:{self.port}, root={self.tftp_root}")
            self._server.listen('0.0.0.0', self.port)
        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

if __name__ == "__main__":
    tftp_root = os.environ.get("TFTP_ROOT", "/tmp/tftpboot")
    port = int(os.environ.get("TFTP_PORT", "1069"))
    server = AgentTFTPServer(tftp_root, port)
    server.start()
    print("[TFTP] Server thread started. Press Ctrl+C to exit.")
    while True:
        try:
            import time
            time.sleep(10)
        except KeyboardInterrupt:
            print("[TFTP] Exiting.")
            break
