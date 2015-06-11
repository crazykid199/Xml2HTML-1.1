#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import re
import string
import os
from xml.dom.minidom import parse


if sys.platform == 'linux-i386' or sys.platform == 'linux2' or sys.platform == 'darwin':
  SysCls = 'clear'
elif sys.platform == 'win32' or sys.platform == 'dos' or sys.platform[0:5] == 'ms-dos':
  SysCls = 'cls'
else:
  SysCls = 'unknown'

log = "xmltohtml2.log"
face = '''

                            ) (   (      
   (                     ( /( )\ ))\ )   
   )\  (      )    (     )\()|()/(()/(   
 (((_) )(  ( /( (  )\ )|((_)\ /(_))(_))  
 )\___(()\ )(_)))\(()/(|_ ((_|_))(_))_   
((/ __|((_|(_)_((_))(_)) |/ /|_ _||   \  
 | (__| '_/ _` |_ / || | ' <  | | | |) | 
  \___|_| \__,_/__|\_, |_|\_\|___||___/  
                   |__/                  
                   			http://ceh.vn
                   			by: CrazyKID
    XMLtoHTML2 version 1.1
    Convert XML GFI LanGuard report to HTML report
 
'''

option = '''
  Usage ./xmltohtml2.py [xml file path] [html file path to save]

  Example: ./xmltohtml2.py report.xml report.html
  '''

file = open(log, "a")

def Myface():
	os.system(SysCls)
	print face
	file.write(face)

def Myoption():
	print option
	file.write(option)


if len(sys.argv) == 3 :
	f = open(sys.argv[2], 'w')
	xmlContent = parse(sys.argv[1])
	hostList = xmlContent.getElementsByTagName('host')
	f.write('''<html>
			<head>
			<title>Host assessment report</title>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
			<style>
			table, td, th {
			border:1px solid black;
			border-collapse:collapse;
			padding: 3px;
			}
			</style>
			</head>
			<body>
			''')
	for host in hostList:

		hostname = host.getElementsByTagName('ip')[0].childNodes[0].data if len(host.getElementsByTagName('hostname')[0].childNodes) == 0 else host.getElementsByTagName('hostname')[0].childNodes[0].data
		f.write(('''<hr /><h2>May %s</h2>
				'''.decode('utf-8') % (hostname)).encode('utf-8'))
	
		f.write('''<h2>Danh sách mã hiệu lỗ hổng và nội dung chi tiết</h2>
				<table>
				<tr>
				<th>Mã hiệu lỗ hổng</th><th>Nội dung chi tiết</th>
				</tr>
				''')
		vulList = host.getElementsByTagName('alerts')[0].getElementsByTagName('alert')
		for vul in vulList:
			vulName = vul.getElementsByTagName('name')[0].childNodes[0].data
			matchObj = re.match(r'(OVAL:\d+):.*',vulName)
			if matchObj: vulName = matchObj.group(1)
			vulDescription = '' if len(vul.getElementsByTagName('descr')[0].childNodes) ==0 else vul.getElementsByTagName('descr')[0].childNodes[0].data
			if vulDescription != "":
				f.write(('''<tr>
						<td align="justify">%s</td><td align="justify">%s</td>
						</tr>
						''' % (vulName, vulDescription)).encode('utf-8'))
		f.write('''</table>
				''')
		if len(host.getElementsByTagName('alerts')[0].getElementsByTagName('missing_hotfixes')) == 0: continue
		f.write('''<h2>Danh sách mã hiệu các bản vá và nội dung chi tiết</h2>
				<table>
				<tr>
				<th>Mã hiệu bản vá</th><th>Nội dung chi tiết</th>
				</tr>
				''')
		hotfixes = host.getElementsByTagName('alerts')[0].getElementsByTagName('missing_hotfixes')[0].getElementsByTagName('hotfix')
		for hotfix in hotfixes:
			KB2 = ""
			hotfixBID = hotfix.getElementsByTagName('bulletinid')[0].childNodes[0].data
			hotfixTitle = hotfix.getElementsByTagName('title')[0].childNodes[0].data
			for KB in re.finditer(r'(.KB[0-9]+).',hotfixTitle):
				KB2 = KB.group(0)
			hotfixTitle2 = hotfixTitle.replace(KB2,'')
			hotfixBID2 = hotfixBID + ' ' + KB2

			f.write(('''<tr>
					<td align="center">%s</td><td align="justify">%s</td>
					</tr>
					''' % (hotfixBID2, hotfixTitle2)).encode('utf-8'))
		f.write('</table><hr />')
	f.write('</body></html>')
	Myface()
	print "Convert Completed !!!"

	f.close()
else:
	Myface()
	Myoption()
	print "Error !!! Missing parameters"
	sys.exit()
file.close()