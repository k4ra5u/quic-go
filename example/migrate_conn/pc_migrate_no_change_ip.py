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
        print(ConnAddr)
        print(PcMessage)
        
        src_port = 10443

        dst = ConnAddr.rsplit(":", 1)
        dst_ip ,dst_port =dst[0],dst[1]
        dst_port = int(dst_port)
        # 发送数据包
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 将消息编码为字节并发送
        client.sendto(PcMessage, (dst_ip, dst_port))
        #recv_message = client.recvfrom(4096)
        #print(udp_packet)
        wdata = ConnAddr + "#" + str(len(PcMessage)) + '\n'
        #wfile.write(wdata)
        #wdata = ConnAddr + "#recv#" + str(len(recv_message)) + '\n'
        wfile.write(wdata)

        wfile.flush()  # 强制刷新缓冲区，将数据写入磁盘
        os.fsync(wfile.fileno())  # 确保数据被写入硬盘
        client.close()

        #print(ConnAddr + "#" + str(len(ConnAddr)))

    except Exception as e:
        #print("Error decoding JSON:", e)
        pass
