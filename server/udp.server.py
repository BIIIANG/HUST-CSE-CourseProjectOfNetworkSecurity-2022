import socket

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

udp.bind(('0.0.0.0', 9001))

while True:
    rec_msg, addr = udp.recvfrom(1024)
    client_ip, client_port = addr
    print(f'{client_ip},{client_port}: {rec_msg.decode("utf8").strip()}')
    ack_msg = 'Hello, udp client.'
    udp.sendto(ack_msg.encode('utf8'), addr)
