import socket

def rdns(ip: str) -> str | None:
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None
