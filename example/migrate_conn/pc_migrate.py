import json
import socket
import base64
from scapy.all import *
import signal

wfile = open("migrate1.log",'w')
def handler(signum, frame):
    wfile.close()
    exit(1)

# 监听地址和端口
host = '0.0.0.0'
port = 14443

# 创建 UDP 套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))

signal.signal(signal.SIGINT, handler)
while True:
    # 接收数据
    data, addr = sock.recvfrom(4096)
    
    #print("Received data:", data.decode())

    # 反序列化 JSON 数据
    try:
        message = json.loads(data)
        #print(message)

        ConnAddr = message["ConnAddr"]
        PcMessage = base64.b64decode(message["PcMessage"])
        #print(ConnAddr)
        #print(PcMessage)
        src_ip = "202.112.47.63"
        src_port = 10443
        dst = ConnAddr.rsplit(":", 1)
        dst_ip ,dst_port =dst[0],dst[1]
        dst_port = int(dst_port)
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=PcMessage)
        # 发送数据包
        send(udp_packet)
        #print(udp_packet)
        wdata = ConnAddr + "#" + str(len(PcMessage)) + '\n'
        wfile.write(wdata)
        wfile.flush()  # 强制刷新缓冲区，将数据写入磁盘
        os.fsync(wfile.fileno())  # 确保数据被写入硬盘

        #print(ConnAddr + "#" + str(len(ConnAddr)))

    except Exception as e:
        #print("Error decoding JSON:", e)
        pass
