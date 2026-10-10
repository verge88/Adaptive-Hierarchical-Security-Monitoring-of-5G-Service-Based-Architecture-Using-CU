"""Verify real Open5GS Nnrf discovery using a genuine HTTP/2 h2c request."""
import argparse
import asyncio
import json
from .live_experiment import nrf_discovery


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', default='http://127.0.0.1:7777')
    p.add_argument('--retries', type=int, default=45)
    args = p.parse_args()
    print(json.dumps(asyncio.run(nrf_discovery(args.url, retries=args.retries)), indent=2))

if __name__ == '__main__':
    main()
