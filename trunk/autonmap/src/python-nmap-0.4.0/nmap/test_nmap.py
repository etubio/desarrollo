#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nmap
import datetime
import os

from nose.tools import assert_equals
from nose.tools import raises
from nose import with_setup


"""
test_nmap.py - tests cases for python-nmap

Source code : https://bitbucket.org/xael/python-nmap

Author :

* Alexandre Norman - norman at xael.org

Contributors:

* Steve 'Ashcrow' Milner - steve at gnulinux.net
* Brian Bustin - brian at bustin.us
* old.schepperhand
* Johan Lundberg
* Thomas D. maaaaz
* Robert Bost
 
Licence : GPL v3 or any later version


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""



def setup_module():
    global nm
    nm = nmap.PortScanner()
    

@raises(nmap.PortScannerError)
def test_wrong_args():
    nm.scan(arguments='-wrongargs')
    

def test_host_scan_error():
    assert('error' in nm.scan('noserver.example.com', arguments='-sP')['nmap']['scaninfo'])


def xmlfile_read_setup():
    nm.analyse_nmap_xml_scan(open('scanme_output.xml').read())

@with_setup(xmlfile_read_setup)
def test_command_line():
    assert_equals(nm.command_line(), './nmap-6.40/nmap -sV -oX scanme_output.xml scanme.nmap.org')

@with_setup(xmlfile_read_setup)
def test_scan_info():
    assert('tcp' in nm.scaninfo())
    assert('method' in nm.scaninfo()['tcp'])
    assert_equals('connect', nm.scaninfo()['tcp']['method'])
    assert('services' in nm.scaninfo()['tcp'])

@with_setup(xmlfile_read_setup)
def test_all_hosts():
    assert_equals(['74.207.244.221'], nm.all_hosts())


@with_setup(xmlfile_read_setup)
def test_host():
    assert_equals('scanme.nmap.org', nm['74.207.244.221'].hostname())
    assert_equals('up', nm['74.207.244.221'].state())
    assert_equals(['tcp'], nm['74.207.244.221'].all_protocols())


@with_setup(xmlfile_read_setup)
def test_port():
    assert_equals([80, 9929, 22], list(nm['74.207.244.221']['tcp'].keys()))
    assert(nm['74.207.244.221'].has_tcp(22))
    assert(nm['74.207.244.221'].has_tcp(23) == False)
    assert('conf' in list(nm['74.207.244.221']['tcp'][22]))
    assert('cpe' in list(nm['74.207.244.221']['tcp'][22]))
    assert('name' in list(nm['74.207.244.221']['tcp'][22]))
    assert('product' in list(nm['74.207.244.221']['tcp'][22]))
    assert('reason' in list(nm['74.207.244.221']['tcp'][22]))
    assert('state' in list(nm['74.207.244.221']['tcp'][22]))
    assert('version' in list(nm['74.207.244.221']['tcp'][22]))
                  
    assert('10' in nm['74.207.244.221']['tcp'][22]['conf'])
    assert('cpe:/o:linux:linux_kernel' in nm['74.207.244.221']['tcp'][22]['cpe'])
    assert('ssh' in nm['74.207.244.221']['tcp'][22]['name'])
    assert('OpenSSH' in nm['74.207.244.221']['tcp'][22]['product'])
    assert('syn-ack' in nm['74.207.244.221']['tcp'][22]['reason'])
    assert('open' in nm['74.207.244.221']['tcp'][22]['state'])
    assert('5.3p1 Debian 3ubuntu7' in nm['74.207.244.221']['tcp'][22]['version'])

    assert_equals(nm['74.207.244.221']['tcp'][22], nm['74.207.244.221'].tcp(22))


@with_setup(xmlfile_read_setup)
def test_listscan():
    assert_equals('1', nm.scanstats()['uphosts'])
    assert_equals('0', nm.scanstats()['downhosts'])
    assert_equals('1', nm.scanstats()['totalhosts'])
    assert('timestr' in nm.scanstats().keys())
    assert('elapsed' in nm.scanstats().keys())

    
@with_setup(xmlfile_read_setup)
def test_csv_output():
    assert_equals('host;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe',
                  nm.csv().split('\n')[0].strip())
    assert_equals('74.207.244.221;tcp;22;ssh;open;OpenSSH;"Ubuntu Linux; protocol 2.0";syn-ack;5.3p1 Debian 3ubuntu7;10;cpe:/o:linux:linux_kernel',
                  nm.csv().split('\n')[1].strip())

    
def test_listscan():
    assert(0 < len(nm.listscan('192.168.1.0/30')))
    assert_equals(['127.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3'], 
                  nm.listscan('localhost/30'))


def test_sudo():
    if os.getuid() == 0:
        r=nm.scan('127.0.0.1', arguments='-O')
    else :
        r=nm.scan('127.0.0.1', arguments='-O', sudo=True)
        
    assert(len(nm['127.0.0.1']['osclass']) > 0)
    assert_equals('Linux', nm['127.0.0.1']['osclass']['vendor'])



    
