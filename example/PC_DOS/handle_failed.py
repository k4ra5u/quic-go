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
total = 0
with open('4.log','r') as rfile:
    lines = rfile.readlines()
with open('error.log','w') as wfile:
    for line in lines:
        start_pos = line.index('failed:')
        target = line[start_pos+7:]
        wfile.write(target)


'''
2024/03/11 23:49:14 failed:142.250.189.225 443 h3
2024/03/11 23:49:14 failed:2606:4700:3108::ac42:2b7f 443 h3
2024/03/11 23:49:14 failed:104.16.101.75 443 h3
2024/03/11 23:49:14 failed:104.21.83.167 443 h3
2024/03/11 23:49:14 failed:99.86.102.21 443 h3
2024/03/11 23:49:14 failed:104.21.81.227 443 h3
'''
