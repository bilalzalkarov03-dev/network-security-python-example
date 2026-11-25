import socket
import time
from collections import defaultdict


PORT_WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 8


class NetworkGuard:
    """Учебный детектор частых обращений к разным портам (Port Scan)."""

    def __init__(self, window_seconds: int = PORT_WINDOW_SECONDS, threshold: int = PORT_SCAN_THRESHOLD):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.port_hits = defaultdict(list)
        self.blocked_ips = set()

    def register_connection(self, source_ip: str, target_port: int) -> bool:
        """Фиксирует обращение к порту и возвращает True при превышении порога."""
        if source_ip in self.blocked_ips:
            return True

        now = time.time()
        recent_hits = [
            (ts, port)
            for ts, port in self.port_hits[source_ip]
            if now - ts <= self.window_seconds
        ]
        recent_hits.append((now, target_port))
        self.port_hits[source_ip] = recent_hits

        unique_ports = {port for _, port in recent_hits}
        if len(unique_ports) >= self.threshold:
            self.blocked_ips.add(source_ip)
            print(
                f"[ALERT] Подозрительная активность с {source_ip}: "
                f"{len(unique_ports)} разных портов за {self.window_seconds} сек."
            )
            return True

        return False

    @staticmethod
    def check_local_port(host: str, port: int, timeout: float = 0.5) -> bool:
        """Проверяет, отвечает ли TCP-порт на указанном хосте."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0


if __name__ == "__main__":
    guard = NetworkGuard()
    simulated_events = [
        ("192.168.1.50", 22),
        ("192.168.1.50", 80),
        ("192.168.1.50", 443),
        ("192.168.1.50", 8080),
        ("192.168.1.50", 3306),
        ("192.168.1.50", 5432),
        ("192.168.1.50", 21),
        ("192.168.1.50", 25),
    ]

    for ip, port in simulated_events:
        guard.register_connection(ip, port)

    print("Проверка локального порта 80:", guard.check_local_port("127.0.0.1", 80))
