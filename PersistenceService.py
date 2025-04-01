suspicious_ports: list[int] = [53, 443, 8080, 9001, 4444, 6666]

def check_persistence(time_interval: list[int], analysis: dict, ip: str, port: str) -> dict:
        if len(time_interval) > 5:
            intervals = [time_interval[i] - time_interval[i-1] for i in range(1, len(time_interval))]
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 60:
                analysis[ip] = {
                    "port": port,
                    "connections": len(time_interval),
                    "avg_interval_seconds": round(avg_interval, 2)
                }
        return analysis