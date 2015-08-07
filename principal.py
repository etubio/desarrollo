#!/usr/bin/python
# coding 

# This program scan a net by using nmap to get information of
# each host active in the net.
# Requires superuser.
# Designed only for local networks

import nmap, sys
import chapter
from Host import Host, Port

def print_usage():
	print 'Usage: ./principal.py <red>\n\
	Example 1: ./principal.py 192.168.1.0/24\n\
	Example 2: python principal.py 192.168.1.10/32'
	

# print dictionary recursively
def walk_dict(d):
    for k,v in d.items():
        if isinstance(v, dict):
            walk_dict(v)
        else:
            print "%s %s" % (k, v) 


# search the value of the given key in a dictionary recursively
# check if key exists in the dictionary	
# PRECONDITION: the key must be unique
def _finditem(obj, key):
    if key in obj: return obj[key]
    for k, v in obj.items():
        if isinstance(v,dict):
            item = _finditem(v, key)
            if item is not None:
                return item

	
def host_discovery(nm,red):
	print 'Barrido ping (ARP en red local)'
	hosts_up_list = nm.scan(red,arguments='-sP')['scan'].keys()
	print str(len(hosts_up_list))+' host(s) activo(s) encontrado(s)'
	return hosts_up_list
	

# The objetive of this function was get the hostname,
# but this library return always empty (bug?)
def dns_fingerprinting(nm,ip,h):
	print 'Escaneo de lista (DNS) para el host '+ip
	result = nm.scan(ip,arguments='-sL')['scan']
	if (ip in result.keys()) & ('hostname' in result[ip].keys()):
		h.dns = result[ip]['hostname']

	
def port_scanning(nm,ip,h):
	print 'Port scanning para el host '+ip
	result = nm.scan(ip,arguments='-PN')
	# check keys
	if (ip in result['scan'].keys()) & ('tcp' in result['scan'][ip].keys()):
		found_ports = result['scan'][ip]['tcp'].keys()
		for e in found_ports:
			port = result['scan'][ip]['tcp'][e]	
			p = Port('tcp',str(e),port['state'],port['name'])
			h.ports.append(p)
	
	
def os_fingerprinting(nm,ip,h):
	print 'OS fingerprinting para el host '+ip
	result = nm.scan(ip,arguments='-O')['scan']
	if ip in result.keys():
		result = result[ip]
		if 'hostname' in result.keys():	
			h.hostname = result['hostname']
		if ('addresses' in result.keys()) & ('mac' in result['addresses'].keys()):
			h.mac = result['addresses']['mac']
			if ('vendor' in result.keys()) & ('mac' in result['vendor'].keys()):		
				h.vendor = result['vendor'][h.mac]
		if ('osclass' in result.keys()) & ('vendor' in result['osclass'].keys()):
			h.os = result['osclass']['vendor'] + ' ' + result['osclass']['osfamily']


def port_fingerprinting(nm,ip,h):
	print 'Port fingerprinting para el host '+ip
	for p in h.ports:
		result = nm.scan(ip,arguments='-sV -p'+p.num)['scan']
		if ip in result.keys():
			result = result[ip]
			p.descr = _finditem(result,'product')+' '+_finditem(result,'version')+' '+_finditem(result,'extrainfo')

			
			
def to_pdf(diccionario,title):
	chapter.title = title
	pdf = chapter.PDF()
	i=1
	for ip in diccionario:
		texto = str(diccionario[ip])
		pdf.print_chapter(i,'Host '+ip,texto)	
		i+=1
	pdf.output('informe.pdf','F')
	
	
def main():
	# check parameters
	if (len(sys.argv) != 2):
		print_usage()
		exit()	

	red = sys.argv[1]
	print 'Analizando la red '+red
	nm = nmap.PortScanner()

	# Host Discovery
	hosts_up_list = host_discovery(nm,red)

	diccionario = {}
	for ip in hosts_up_list:
		h = Host(ip)
		
		# DNS Fingerprinting
		# dns_fingerprinting(nm,ip,h) Problem, see the def function's comment
		
		# Port Scanning
		port_scanning(nm,ip,h)
		
		# OS Fingerprinting
		os_fingerprinting(nm,ip,h)	
		
		# Port fingerprinting
		port_fingerprinting(nm,ip,h)
		
		print h
		diccionario[ip] = h

	# to PDF
	to_pdf(diccionario,red)
	
	print ("\nTerminado, ver informe generado (informe.pdf)")


main()



