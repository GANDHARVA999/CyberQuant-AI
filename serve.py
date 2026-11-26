"""Start CyberQuant AI so every device on the same Wi-Fi can open it.

    python serve.py            # port 8000
    python serve.py --port 9000
"""
import argparse, socket
import uvicorn


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; this only picks the Wi-Fi interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    ip = lan_ip()
    bar = "=" * 62
    print(f"\n{bar}\n  CyberQuant AI is starting\n"
          f"  On this laptop:           http://localhost:{a.port}\n"
          f"  On phones/other laptops:  http://{ip}:{a.port}   (same Wi-Fi)\n"
          f"  Sign in: admin / Gandharva (or create your own account)\n{bar}\n")
    uvicorn.run("src.api:app", host="0.0.0.0", port=a.port)
