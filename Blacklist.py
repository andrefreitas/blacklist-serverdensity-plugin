"""
Blacklist Plugin for Server Density to monitor Email BlackList Listing
Author: Andre Freitas
Email: p.andrefreitas@gmail.com / andrefreitas@ptwebtech.pt
Twitter: http://twitter.com/cantodoandre
"""

import os
import re
import copy
import socket

class Blacklist (object):
    def __init__(self, agentConfig, checksLogger, rawConfig):
        self.agentConfig = agentConfig
        self.checksLogger = checksLogger
        self.rawConfig = rawConfig
 
    def get_system_public_ips(self):
        ips_text = os.popen("ifconfig | grep -E \'inet (addr|end)\'").read().strip()
        ips_lines_list = ips_text.split("\n")
        ips_set = set([])
        for ip_line in ips_lines_list:
            ip = ip_line.split(":")[1].split(" ")[1]
            if(not self.ip_is_private(ip)):
                ips_set.add(ip)
        return ips_set

    def ip_is_private(self, ip):
        regex = "127\.0\.0\.1"
        regex += "|10\."
        regex += "|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]"
        regex += "|192\.168\."
        return bool(re.match(regex, ip))

    def ip_is_listed(self, ip, dnsbl):
        ip = reverse_ip(ip)
        try:
            socket.gethostbyname(ip + dnsbl)
            return True
        except:
            return False

    def run(self):
        data = {'blacklists': 0}
        return data

"""
A function to reverse an IP to prepare it to test in the DNSBL
"""
def reverse_ip(ip):
    # Add a . in the final if necessary
    if(ip[len(ip)-1]!='.'):
        ip+='.'
        
    # Fetch all the octects
    aux=[]
    auxSt=''
    for i in range(len(ip)):
        if(ip[i]!='.'):
            auxSt+=ip[i]
        elif(ip[i]=='.'):
            aux.append(copy.deepcopy(auxSt))
            auxSt=''
            
    # Reverse the octects
    aux.reverse()
    ip=''
    for i in range(len(aux)):
        ip+=aux[i]+'.'
        
    return ip