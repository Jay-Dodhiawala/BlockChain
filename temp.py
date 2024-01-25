import socket
import json

HOST = socket.gethostbyname(socket.gethostname())
port = 9000

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, port))

print(f"UDP Server listening on {HOST}:{port}")

with server as s:
    while True:
        try:
            data, addr = s.recvfrom(1024)
            decoded_data = data.decode("utf-8")
            print(f"Received data: {decoded_data} from {addr}")

            # Send a response back to the client
            response_data = {"reply":"Response from server"}
            response_data = json.dumps(response_data)
            s.sendto(response_data.encode("utf-8"), addr)
            print(f"Sent response to {addr}")

        except Exception as e:
            print(f"Error: {e}")

