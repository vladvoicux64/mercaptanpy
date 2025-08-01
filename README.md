# DISCLAIMER
This project is provided for educational and research purposes only. It demonstrates how data can be tunneled through DNS for academic, security research, or penetration testing in controlled environments.

Misuse Warning:
The use of this software to bypass network restrictions, access unauthorized systems, or perform any kind of illegal activity is strictly prohibited. The author(s) assume no responsibility or liability for any misuse, damage, or legal consequences arising from the use of this tool.

By using this project, you agree to comply with all applicable laws, regulations, and terms of service of the networks you interact with.

# Description
Mercaptan is a multi-connection, multi-threaded SOCKS5 DNS tunnel. It allows piping your network traffic through DNS requests, in mediums where it would be restricted. It also doubles as a privacy oriented DNS server, blocking known ad and tracking domains and forwarding DNS requests to [Quad9](https://quad9.net/).

# Installation and setup
## Virtual environment
As always, a virtual environment is recommended to run this. Note that the project is meant to be run with elevated privileges, so you will either have to manually provide the environment's `python` executable path to `sudo` (or the utility of your choice), or to pass the correct flags to maintain the `PATH` that the venv's `activate` script sets (instructions not provided as it is out of the scope of this README).

## Requirements
The sole requirement to be installed is `scapy`. To install `scapy`, use `pip install scapy`, after activating your venv, if you use one.

## Setup
The tool is split up into a server and client script. The server script is meant to be ran on the external machine that will act as the DNS server, and the client to be ran on the machine that is in a restricted medium. Please note that because this tool was made for educational purposes, it directly sends requests to a fixed DNS server IP you provide. You may modify it to work by querying a domain that redirects requests to a certain DNS tunnel, removing the need to specify a DNS server IP, on your own responsibility.

### Server setup
In the appropriately named server python script, at the top you'll have to setup:
- the TUNNEL_DOMAIN variable, with a phony domain used to mask your traffic*;
- the LISTEN_IP variable, with the IP of the interface that shall receive DNS requests, default value listening on all interfaces;
- the DNS_PORT variable, if you use a DNS port other than the standard;

### Client setup
As in the case of the server, setup:
- the TUNNEL_DOMAIN variable, to the same value as used in the server*;
- the SERVER_IP variable, to the IP of your server, example is a local IP I used in development;
- optionally, the SOCKS_PORT variable to the port you wish to use for the SOCKS5 server;
- if encountering desync issues, or failed connections, try lowering the speed of the tunnel by increasing the values of the *_WAIT variables;
- the DNS_PORT variable, if you use a DNS port other than the standard;

(*) - failure to match the two variables' values will result in the tunnel not working.

# Usage
On your server machine, run the server script with elevated privileges. A message informing that the server awaits connections will pop up. 
On your client machine, run the client script with elevated privileges. A message informing you that the SOCKS5 server is ready will pop up.
Point your browser/system to use a SOCKS5 proxy, at `localhost:<SOCKS_PORT>` (default: 1080). You should start seeing debug messages of sessions being started.
