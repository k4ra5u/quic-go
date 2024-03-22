import ipaddress

# 打开输入文件和输出文件
with open('fastly_ips.txt', 'r') as input_file, open('fastly_ips_out.txt', 'w') as output_file:
    for line in input_file:
        print(line)
        # 移除每行的换行符并解析IP网络
        network = ipaddress.ip_network(line.strip(), strict=False)
        # 遍历网络中的所有IP并写入输出文件
        for ip in network.hosts():
            output_file.write(str(ip) + '\n')
