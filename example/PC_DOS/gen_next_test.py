import json
import os
import sys
from multiprocessing import Pool
from functools import partial
from itertools import repeat
from threading import Thread
from tqdm import tqdm
import time
import concurrent.futures
import logging
prs = dict()
pds = dict()
ports = dict()
mutli = dict()
alpns = dict()
total = 0
with open('/home/john/Desktop/cjj_related/shodan/shodan-python/unique_data2args.json','r') as rfile:
    lines2 = rfile.readlines()
for line2 in lines2:
    buf = line2.split(' ')
    alpns[buf[0]]=buf[2][:-1]
with open('3.log','r') as rfile:
    lines = rfile.readlines()
for line in lines:
    if line[0]== '[':
        #ipv6
        ip_end_pos = line.index(']')
        ip = line[1:ip_end_pos]
        line_args = line[ip_end_pos+1:].split(':')
    else:
        line_args = line.split(':')
        ip = line_args[0]
    port = line_args[1]
    ports[ip] = port
    if 'Received PADDING frame' in line_args[2]:
        #calc padding
        pd_bytes = int(line_args[3])
        if pd_bytes < 10:
            continue
        if ip not in pds:
            pds[ip]=(1,pd_bytes)
        else:
            pre_num,pre_bytes = pds[ip]
            pds[ip]=(pre_num+1,pre_bytes+pd_bytes)

    elif 'received path_response' in line_args[2]:
        if ip not in prs:
            total +=1
            prs[ip]=1
        else:
            prs[ip]+=1
        #clac pr
# clac with pr = 80bytes
for ip in prs.keys():
    send_bytes = prs[ip] * 80
    if ip not in pds:
        recv_num,recv_bytes = (0,0)
    else:
        recv_num,recv_bytes = pds[ip]
    recv_bytes += prs[ip] * 80
    mutli[ip] = [recv_bytes , send_bytes, recv_bytes / send_bytes]

for ip in mutli.keys():
    if mutli[ip][2]>1:
        print(ip + ' ' + ports[ip] + ' ' + alpns[ip])
        #print(ip + ':' + ports[ip] + ": " +str(mutli[ip][0]) +":" +str(mutli[ip][1])+':' + str(mutli[ip][2]))
#print("total: "+ str(total))
'''
34.110.136.239:443:received path_response: 650a9bfd65190621
34.110.136.239:443:Received PADDING frame:1234
34.110.136.239:443:received path_response: 29aa32966490ab8d
141.98.114.98:443:Received PADDING frame:1123
91.238.163.15:443:Received PADDING frame:2
91.238.163.15:443:received path_response: 15145d59d06f9043
91.238.163.15:443:Received PADDING frame:1220
91.238.163.15:443:received path_response: 3e34950e0ea2a1e5
91.238.163.15:443:Received PADDING frame:1220
91.238.163.15:443:received path_response: 9cbe40b773d71d8c
91.238.163.15:443:Received PADDING frame:1220
91.238.163.15:443:received path_response: ce7bda7a546f55dd
91.238.163.15:443:Received PADDING frame:1220
[2a00:c20:4009:2::172]:443:Received PADDING frame:2
[2a00:c20:4009:2::172]:443:received path_response: 13bd5ccb7e195558
[2a00:c20:4009:2::172]:443:Received PADDING frame:1200
[2a00:c20:4009:2::172]:443:received path_response: 62b8041bad6a6905
[2a00:c20:4009:2::172]:443:Received PADDING frame:1200

'''
