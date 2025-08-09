#!/usr/bin/env python3
import asyncio, json, sys, time
import httpx

async def worker(url, payload, n):
    async with httpx.AsyncClient() as client:
        tasks = [client.post(url, json=payload) for _ in range(n)]
        return await asyncio.gather(*tasks)

async def main():
    if len(sys.argv) < 4:
        print("usage: load_test.py URL JSON_PAYLOAD CONCURRENCY")
        return
    url = sys.argv[1]
    payload = json.loads(open(sys.argv[2]).read())
    concurrency = int(sys.argv[3])
    start = time.time()
    await worker(url, payload, concurrency)
    print(f"{concurrency} requests in {time.time()-start:.3f}s")

if __name__ == "__main__":
    asyncio.run(main())
