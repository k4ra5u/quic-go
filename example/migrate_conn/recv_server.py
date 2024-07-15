import socket
import os
def udp_server(host, port):
    wfile = open("migrate1.log",'w')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"UDP server listening on {host}:{port}...")

        while True:
            data, client_address = server_socket.recvfrom(4096)
            output = f"{client_address[0]}:{client_address[1]}#{len(data)}"
            wfile.write(output)
            wfile.flush()  # 强制刷新缓冲区，将数据写入磁盘
            os.fsync(wfile.fileno())  # 确保数据被写入硬盘
            print(output)
        

if __name__ == "__main__":

    HOST = '0.0.0.0'
    PORT = 10443
    udp_server(HOST, PORT)