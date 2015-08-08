#!/usr/bin/python

import nmap






#print result['nmap']['192.168.1.10'].keys()

def walk_dict(d):
    for k,v in d.items():
        if isinstance(v, dict):
            walk_dict(v)
        else:
            print "%s %s" % (k, v) 

def _finditem(obj, key):
    if key in obj: return obj[key]
    for k, v in obj.items():
        if isinstance(v,dict):
            item = _finditem(v, key)
            if item is not None:
                return item
				
	


	
nm = nmap.PortScanner()

result = nm.scan('192.168.1.10/32',arguments='-sV -p2222')
walk_dict(result)
