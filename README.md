# Payday
Payload generator that uses Metasploit and Veil. Takes IP address input and then builds payloads automatically.
Calls Veil framework with supplied IP address and creates binaries and handlers.
Uses msfvenom to create payloads and writes resource handler files in the same way that Veil does.

-->
Update the path to the Veil Evasion Script
-->


Examples:

# Generate Metasploit Payloads
payday.py --msf --ip 1.1.1.1

# Generate Veil Payloads
payday.py --veil --ip 1.1.1.1

# Generate Both
payday.py --veil --msf --ip 1.1.1.1

# Clean Out Directories

payday.py --clean
