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
        self.blacklists_file = "Blacklists.csv"
        self.blacklists = self.get_blacklists()
        self.ips = self.get_system_public_ips()


    def get_blacklists(self):
        f = open(self.blacklists_file, "r")
        lists = f.read().strip().split("\n")
        f.close()
        return lists
 
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

    def check_all(self):
        total = 0
        for ip in self.ips:
            for blacklist in self.blacklists:
                if(self.ip_is_listed(ip, blacklist)):
                    total += 1
        return total
    

    def run(self):
        data = {'blacklists': self.check_all()}
        return data

"""
A function to reverse an IP to prepare it to test in the DNSBL
"""
def reverse_ip(ip):
    octects = ip.split(".")
    octects = list(reversed(octects))
    reversed_ip = ".".join(octects)
    return reversed_ip

b = Blacklist(1,2,3)
print b.run()