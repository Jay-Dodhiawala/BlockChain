import socket

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

msg = "hiii"

print(type(msg) == dict)

client.sendto(msg.encode('utf-8'), ("130.179.28.111",9000))