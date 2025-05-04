import socket
import threading

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        src.close()
        dst.close()

def start_proxy(listen_host, listen_port, remote_host, remote_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_host, listen_port))
    server.listen(5)
    print(f"[*] Listening on {listen_host}:{listen_port}, forwarding to {remote_host}:{remote_port}")
    while True:
        client_sock, client_addr = server.accept()
        print(f"[>] Connection from {client_addr}")
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((remote_host, remote_port))
        # Thread: client → server
        threading.Thread(target=forward, args=(client_sock, server_sock), daemon=True).start()
        # Thread: server → client
        threading.Thread(target=forward, args=(server_sock, client_sock), daemon=True).start()

if __name__ == "__main__":
    # Example usage: python mitm_proxy.py 127.0.0.1 8888 example.com 80
    import sys
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <listen_host> <listen_port> <remote_host> <remote_port>")
        sys.exit(1)
    lh, lp, rh, rp = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    start_proxy(lh, lp, rh, rp)
