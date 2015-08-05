#!/usr/bin/python
# coding utf-8

class Port:
	def  __init__(self,proto,num,state,descr):
		self.proto = proto
		self.num = num
		self.state = state
		self.descr = descr
		
	def __repr__(self):
		return '\n'+self.num+' '+self.proto+': '+self.state+' ('+self.descr+')'

class Host:
	def __init__(self,ipv4):
		self.ipv4 = ipv4
		self.mac = ''
		self.vendor = ''
		self.hostname = ''
		self.dns = ''
		self.os = ''
		self.ports = []
		
	def __repr__(self):
		output = ''
		for e in self.ports:
			output += str(e)
		return '\n'+self.ipv4+'\n'+self.os+'\n'+output
