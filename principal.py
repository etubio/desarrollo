#!/usr/bin/python
# coding 

import nmap, sys
import chapter
from Host import Host, Port

def print_usage():
	print 'Usage: ./principal.py <red>\n\
	Example 1: ./principal.py 192.168.1.0/24\n\
	Example 2: python principal.py 192.168.1.10/32'
	
	
def check_key(k,l):
	for e in l:
		if e == k:
			return True
	return False

	
def host_discovery(nm,red):
	print 'Barrido ping (ARP en red local)'
	hosts_up_list = nm.scan(red,arguments='-sP')['scan'].keys()
	print 'Terminado, '+str(len(hosts_up_list))+' host(s) activo(s) encontrado(s)'
	return hosts_up_list
	
	
def dns_fingerprinting(nm,ip,h):
	print 'Escaneo de lista (DNS) para el host '+ip
	result_dns = nm.scan(ip,arguments='-sL')['scan']
	print 'Terminado'
	h.dns = result_dns[ip]

	
def port_scanning(nm,ip,h):
	print 'Port scanning para el host '+ip
	result = nm.scan(ip,arguments='-PN')
	print 'Terminado'
	# check keys
	if check_key(ip,result['scan'].keys()):
		if check_key('tcp',result['scan'][ip].keys()):
			found_ports = result['scan'][ip]['tcp'].keys()
			for e in found_ports:
				port = result['scan'][ip]['tcp'][e]	
				p = Port('tcp',str(e),port['state'],port['name'])
				h.ports.append(p)
	
	
def os_fingerprinting(nm,ip,h):
	print 'OS fingerprinting para el host '+ip
	result = nm.scan(ip,arguments='-O')['scan'][ip]
	print 'Terminado'
	h.hostname = result['hostname']
	# mac = result['addresses']['mac']
	#texto += 'vendor: '+ str(mac) + ' (' + result['vendor'][mac] + ')\n'
	if check_key('osclass',result):
		if check_key('vendor',result['osclass']):
			h.os = result['osclass']['vendor'] + ' ' + result['osclass']['osfamily']

			
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
		dns_fingerprinting(nm,ip,h)
		
		# Port Scanning
		port_scanning(nm,ip,h)
		
		# OS Fingerprinting
		os_fingerprinting(nm,ip,h)	
		
		# Port fingerprinting
		
		
		print h
		diccionario[ip] = h

	# to PDF
	to_pdf(diccionario,red)


main()



