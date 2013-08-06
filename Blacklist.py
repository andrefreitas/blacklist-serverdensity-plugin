import os
import re

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

 
    def run(self):
        data = {'blacklists': 0}
        return data
 
b = Blacklist(1,2,3)
print b.get_system_ips()
print b.ip_is_private("172.31.0.2")