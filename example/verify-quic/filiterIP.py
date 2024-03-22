from ipaddress import ip_address, ip_network

# 假设我们有两个文件：ips.txt（包含IP段）和addresses.txt（包含单独的IP地址）
# 我们需要读取这些文件，然后找出哪些IP地址属于给定的IP段

def filter_ips(ip_ranges_file, ip_addresses_file, output_file):
    # 读取IP段并存储到一个列表中
    with open(ip_ranges_file, 'r') as file:
        ip_ranges = [line.strip() for line in file.readlines()]
    
    # 读取IP地址并存储到另一个列表中
    ip_addresses = []
    ports = dict()
    alpns = dict()
    with open(ip_addresses_file, 'r') as file:
        lines = [line.strip() for line in file.readlines()]
        for line in lines:
            prelist = line.split(' ')
            ip_addresses.append(prelist[0])
            if prelist[1] not in ports:
                ports[prelist[1]] = 1
            else:
                ports[prelist[1]] +=1
            if prelist[2] not in alpns:
                alpns[prelist[2]] = 1
            else:
                alpns[prelist[2]]+=1
    print("ports:")
    for port in ports.keys():
        print(port,ports[port])
    print("alpns:")
    for alpn in alpns.keys():
        print(alpn,alpns[alpn])

    
    # 筛选出属于给定IP段的IP地址
    filtered_ips = []
    for ip in ip_addresses:
        filtered_ips.append(ip)
        continue
        for ip_range in ip_ranges:
            if ip_address(ip) in ip_network(ip_range):
                filtered_ips.append(ip)
                break  # 如果找到匹配的IP段，就不需要检查剩余的IP段
    
    # 将筛选出的IP地址写入到输出文件中
    with open(output_file, 'w') as file:
        for ip in filtered_ips:
            file.write(ip + '\n')

# 这里提供文件路径的例子，实际使用时需要根据文件的实际存储路径来修改
ip_ranges_file = 'input_ips.txt'
ip_addresses_file = 'unique_data2args.json'
output_file = 'unique_ips.txt'
filter_ips(ip_ranges_file,ip_addresses_file,output_file)