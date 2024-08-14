# TAKE GOOD NOTES 
# Stack
6
Jump:
10.50.40.153
# Windows OP:
xfreerdp /v:10.50.28.142 /u:student /p:ZgoxLDNLHlzqU1a /size:1920x1000 +clipboard
# Linux OP:
```
ssh student@10.50.27.207 -X
```
# CTFD server
Username:
DODU-005-M
ZgoxLDNLHlzqU1a	
## Set up control socket (to jump box. exchange the ip and /tmp/* to where your going)
 ssh -MS          /tmp/jump             student@10.50.40.153
      ^               ^                           ^
Master socket   Directory + name         Normal login with ssh

ssh -MS /tmp/jump student@10.50.40.153
## Ping sweep
Linux
```
for i in {97..130}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
```
Windows
```
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
```
## Dynamic port forward 
ssh -S /tmp/jump jump            -O forward -D9050 
     ^             ^                ^
  No loggin   Device name      Dynamic forward
## proxychains nmap scan for open ports
```
nmap -sS -Pn 8.8.8.8 -p 135-139,22,80,443,21,8080
proxychains nmap 192.168.28.100
```
Using netcat
```
nc -z -v -w 1 8.8.8.8 440-443
```
## Banner grabbing (exchange ip and last number to what your looking for)
proxychains nc 192.168.28.100 2222
## Port forwarding to found ports
ssh -S /tmp/jump jump -O forward -L 1111:192.168.28.100:80 -L3333:192.168.28.100:2222
(Creates a local tunnel to both port 80 and port 2222, use any high port, use firefox for port 80)

## Cancel port forwards
ssh -S /tmp/jump jump -O cancel -L 1111:192.168.28.100:80
(can do one port or the entire previous ssh command. could also kill the pid)
ssh -S /tmp/jump jump -O cancel -D9050

## going to the next box (t1 is target 1)
ssh -MS /tmp/t1 credentials@127.0.0.1 -p 3333
(same as initial tunnel)

# Phases of Pentesting
Phase 1: Mission Definition
  Goals and targets, scope, RoE
Phase 2: Recon
  Info gathering
Phase 3: Footprinting
  get data through scan/interaction
Phase 4: Exploitation & Initial Access
  Gain an initial foothold
Phase 5: Post-Exploitation
  persistence, Escalate privileges, cover tracks, Exfiltrate target data
Phase 6: Document Mission

# Data to collect
```
Web Data
  Cached Content, Analytics, Proxy Web Application, Command Line Interrogation
Sensitive Data
  Business Data, Profiles, Non-Profits/Charities, Business Filings, Historical and Public Listings
Publicly Accessible
  Physical Addresses, Phone Numbers, Email Addresses, User Names, Search Engine Data, Web and Traffic Cameras, Wireless Access Point Data
Social Media
  Twitter, Facebook, Instagram, People Searches, Registry and Wish Lists
Domain and IP Data
  DNS Registration, IP Address Assignments, Geolocation Data, Whois
```
# Hyper-Text Markup Language (HTML)
```
Standardized markup language for browser interpretation of webpages
  Client-side interpretation (web browser)
  Utilizes elements (identified by tags)
  Typically redirects to another page for server-side interaction
  Cascading Stylesheets (CSS) for page themeing
```
# Scraping Data
Prep
```
pip install lxml requests
```
# Script
#!/usr/bin/python
import lxml.html
import requests

page = requests.get('http://quotes.toscrape.com')
tree = lxml.html.fromstring(page.content)

authors = tree.xpath('//small[@class="author"]/text()')

print ('Authors: ',authors)

# Advanced Scanning Techniques
1) Host Discovery
  Find hosts that are online
2) Port Enumeration
  Find ports for each host that is online
3) Port Interrogation
  Find what service is running on each open/available port

# NMAP USAGE AND EXAMPLES (file path /usr/share/nmap/scripts)
```
nmap --script <filename>|<category>|<directory>|<expression>[,…​]

Runs all scripts that match defined criteria.

nmap --script-help "<filename>|<category>|<directory>|<expression>[,…​]"

Shows help content for specific scripts, categories, etc.

nmap --script-args <args>

Allows options definied within the script to be ran in conjunction with the script.

nmap --script-args-file <filename>

Allows options definied within the script to be pre listed in a file and then ran in conjunction with the script.

nmap --script-help <filename>|<category>|<directory>|<expression>|all[,…​]

Shows help about scripts. For each script matching the given specification, Nmap prints the script name, its categories, and its description.

nmap --script-trace

Similar to --packet-trace as it will output traffic data to include protocol, source, destination, and transmitted data.


dns-brute.nse

Find valid DNS (A) records by trying a list of common sub-domains and finding those that successfully resolve.

nmap -p 80 --script dns-brute.nse <domain name>
hostmap-bfk.nse

Find virtual hosts on an IP address that you are attempting to compromise (or assess).

nmap -p 80 --script hostmap-bfk.nse <domain name>
traceroute-geolocation.nse

Perform a traceroute to your target IP address and have geolocation data plotted for each hop along the way.

nmap --traceroute --script traceroute-geolocation.nse -p 80 <domain name>
http-enum.nse

Attempts will be made to find valid paths on the web server that match a list of known paths for common web applications.

nmap --script http-enum <IP Address>

  --script-args http-enum.basepath='<Web Server Dir/>' <IP Address>
This entry shows an example of utilizing the --script-args option, identifying a valid value from within the script in order to narrow the scan.

smb-os-discovery.nse

Determines the operating system, computer name, netbios name and domain of a system.

nmap -p 445 --script smb-os-discovery <IP Address / Subnet>
firewalk.nse

Discovers firewall rules using an IP Protocol Time To Live (TTL) expiration technique

nmap -p 80 --script=firewalk.nse <IP Address>

  --script-args=firewalk.max-retries=1 <IP Address>
  --script-args=firewalk.probe-timeout=400ms <IP Address>
  --script-args=firewalk.firewalk.max-probed-ports=7 <IP Address>
This entry shows examples of utilizing the --script-args option, identifying a valid value from within the script in order to narrow the scan.
```
