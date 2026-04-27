import argparse
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from influxdb_client import InfluxDBClient


def send_syn_packets(host, port, count, packets_per_second):
    # Requires elevated privileges because raw SYN packets are crafted directly.
    from scapy.all import IP, TCP, RandIP, RandShort, send

    interval = 1.0 / max(packets_per_second, 1)
    packets = []
    for _ in range(count):
        packet = IP(dst=host, src=RandIP()) / TCP(
            sport=RandShort(),
            dport=port,
            flags='S',
            seq=random.randint(1, 2**32 - 1)
        )
        packets.append(packet)

    print(f'Sending {count} SYN packets to {host}:{port} at ~{packets_per_second} pps')
    send(packets, inter=interval, verbose=False)


def _open_connection(host, port, hold_seconds, timeout_seconds):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        sock.connect((host, port))
        time.sleep(hold_seconds)
        return True
    except Exception:
        return False
    finally:
        sock.close()


def open_many_connections(host, port, count, workers, hold_seconds, timeout_seconds):
    success = 0
    print(f'Opening {count} TCP connections to {host}:{port} with {workers} workers')
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_open_connection, host, port, hold_seconds, timeout_seconds)
            for _ in range(count)
        ]
        for future in as_completed(futures):
            if future.result():
                success += 1
    print(f'Connection burst completed: {success}/{count} successful')


def check_dos_alert(influx_url, influx_token, influx_org, influx_bucket, lookback_minutes):
    client = InfluxDBClient(url=influx_url, token=influx_token, org=influx_org)
    query_api = client.query_api()

    ratio_query = f'''
from(bucket: "{influx_bucket}")
  |> range(start: -{lookback_minutes}m)
  |> filter(fn: (r) => r._measurement == "network_anomaly")
  |> filter(fn: (r) => r._field == "syn_ack_ratio")
  |> last()
'''

    alert_query = f'''
from(bucket: "{influx_bucket}")
  |> range(start: -{lookback_minutes}m)
  |> filter(fn: (r) => r._measurement == "network_anomaly")
  |> filter(fn: (r) => r._field == "dos_suspected")
  |> last()
'''

    ratio_tables = query_api.query(org=influx_org, query=ratio_query)
    alert_tables = query_api.query(org=influx_org, query=alert_query)

    ratio_value = None
    alert_value = None

    for table in ratio_tables:
        for record in table.records:
            ratio_value = record.get_value()

    for table in alert_tables:
        for record in table.records:
            alert_value = record.get_value()

    print(f'Latest syn_ack_ratio: {ratio_value}')
    print(f'Latest dos_suspected: {alert_value}')

    if alert_value == 1:
        print('ALERT VALIDATED: dos_suspected is active.')
        return 0

    print('ALERT NOT TRIGGERED in queried window.')
    return 1


def main():
    parser = argparse.ArgumentParser(description='DoS simulation utility for secure-comm observability validation')
    parser.add_argument('--host', default='127.0.0.1', help='Target host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Target TCP port (default: 5000)')
    parser.add_argument('--mode', choices=['syn', 'connect'], default='syn', help='Attack mode')
    parser.add_argument('--count', type=int, default=800, help='Number of packets/connections to attempt')
    parser.add_argument('--pps', type=int, default=250, help='Packets per second for SYN mode')
    parser.add_argument('--workers', type=int, default=120, help='Parallel workers for connect mode')
    parser.add_argument('--hold-seconds', type=float, default=0.3, help='Connection hold time for connect mode')
    parser.add_argument('--timeout-seconds', type=float, default=1.0, help='Connection timeout for connect mode')
    parser.add_argument('--check-alert', action='store_true', help='Query InfluxDB after simulation')
    parser.add_argument('--lookback-minutes', type=int, default=5, help='Influx query lookback window')

    parser.add_argument('--influx-url', default='http://localhost:8086')
    parser.add_argument('--influx-token', default='my-super-secret-auth-token')
    parser.add_argument('--influx-org', default='securechat')
    parser.add_argument('--influx-bucket', default='network_metrics')

    args = parser.parse_args()

    if args.mode == 'syn':
        send_syn_packets(args.host, args.port, args.count, args.pps)
    else:
        open_many_connections(
            args.host,
            args.port,
            args.count,
            args.workers,
            args.hold_seconds,
            args.timeout_seconds,
        )

    if args.check_alert:
        time.sleep(2)
        exit_code = check_dos_alert(
            args.influx_url,
            args.influx_token,
            args.influx_org,
            args.influx_bucket,
            args.lookback_minutes,
        )
        raise SystemExit(exit_code)


if __name__ == '__main__':
    main()
