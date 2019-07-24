# Payday
Payload generator that uses Metasploit and Veil. Takes IP address input and then builds payloads automatically.
Calls Veil framework with supplied IP address and creates binaries and handlers.
Uses msfvenom to create payloads and writes resource handler files in the same way that Veil does.

The --php option creates a pshell.txt that automatically removes the comments at the start of the file so you can use this without the need to edit.


-->
Update the path to the Veil Evasion Script
>> The tool now has error checking that show the directory structure and parses the veil config file.
-->


Examples:

# Generate Metasploit Payloads
payday.py --msf --ip 1.1.1.1

=======
# Generate Metasploit Payloads with custom port
payday.py --msf --ip 1.1.1.1 --port 7777

# Generate Veil Payloads
payday.py --veil --ip 1.1.1.1

# Generate Veil Payloads with custom port
=======
payday.py --veil --ip 1.1.1.1 --port 7777

# Generate Multiple
payday.py --veil --msf --php --ip 1.1.1.1

# Generate PHP Payload
payday.py --php --ip 1.1.1.1

# Clean Out Directories
payday.py --clean

# Specify custom output directory
payday --veil --msf --output /path/to/custom --ip 1.1.1.1

# Clean custom output directory
payday --output /path/to/custom --clean

