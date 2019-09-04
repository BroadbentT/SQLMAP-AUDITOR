#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#          PYTHON SCRIPT FILE IMPLEMENTING OSWASPS AUTOMATIC SQLMAP AUDITOR
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import subprocess
import os.path
import fileinput
import shutil
import linecache
from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print "Please run this python script as root..."
   exit(True)

if len(sys.argv) < 2:
   print "Use the command python sqlmap-auditor.py website.com..."
   exit(True)

fileName = sys.argv[1]

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display my universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")
print " ____   ___  _     __  __    _    ____       _   _   _ ____ ___ _____ ___  ____   "
print "/ ___| / _ \| |   |  \/  |  / \  |  _ \     / \ | | | |  _ \_ _|_   _/ _ \|  _ \  "
print "\___ \| | | | |   | |\/| | / _ \ | |_) |   / _ \| | | | | | | |  | || | | | |_) | "
print " ___) | |_| | |___| |  | |/ ___ \|  __/   / ___ \ |_| | |_| | |  | || |_| |  _ <  "
print "|____/ \__\_\_____|_|  |_/_/   \_\_|     /_/   \_\___/|____/___| |_| \___/|_| \_\ "
print "                                                                                  "
print "              BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)              \n"


# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

command = "sqlmap -v 2 -u http://" + fileName + " --data='username=admin&password=admin' --user-agent=SQLMAP --delay=1 --timeout=15 --retries=2 --keep-alive --threads=5 --batch --dbms=MySQL --os=Linux --level=5 --risk=3  --tamper=space2comment --cookie='PHPSESSIONID=so6nbe8a6injaapdllrqfc2t7t; security=low' --banner --is-dba --dbs --tables --technique=BEUST -s scan_report.txt --flush-session -t scan_trace.txt --fresh-queries > scan_out.txt"

print "SQL COMMAND STRUCTURE:-"
print "-"*134
print colored(command,'blue')
print "-"*134

print "\nStarting scan, please wait this can take some time!!..."
os.system(command)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : March 2012                   
# Details : Script to generate a HTML report from a SQLMap stdout output.
# Modified: 4/9/2019
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

injectable = False # Flag to know if global audit is OK
fileName1  = "scan_out.txt"
fileName2  = "scan_out.html"
inputFile  = open(fileName1,"r")
outputFile = open(fileName2,"w")

# -------------------------------------------------------------------------------------
# Details : Initialize HTML report stream.
# -------------------------------------------------------------------------------------
outputFile.write("<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">")
outputFile.write("<head><link rel=\"StyleSheet\" href=\"style.css\" type=\"text/css\" media=\"screen\" /><title>SQLMap HTML Report</title></head>")
outputFile.write("<body><table id=\"myStyle\">")
outputFile.write("<thead><tr><th scope=\"col\">Test datetime</th><th scope=\"col\">Test description</th></tr></thead>")
outputFile.write("<tbody>")

# -------------------------------------------------------------------------------------
# Details : Read STDOUT file line by line.
# -------------------------------------------------------------------------------------
for line in inputFile:
   if (line.strip().startswith("[")) and (line.find("[*]") == -1):
      if(line.lower().find("all parameters are not injectable") > -1):
         injectable = True
      line_part = line.strip().split(" ")
      catchdata = line_part[2] if len(line_part) > 2 else 'null'
      if catchdata == "testing":
         execution_datatime = line_part[0]
         execution_trace = ""
         count = 2
         while(count < len(line_part)):
            execution_trace = execution_trace + " " + line_part[count]
            count = count + 1 
         outputFile.write("<tr><td>" + line_part[0] + "</td><td>" + execution_trace + "</td></tr>")                
outputFile.write("</tbody></table>")  
      
# -------------------------------------------------------------------------------------
# Details : Write global audit stauts line.
# -------------------------------------------------------------------------------------
if(injectable):
   outputFile.write("<h1 class=\"success\">SQLMap cannot find injectable parameters !</h1>")
else:
   outputFile.write("<h1 class=\"fail\">SQLMap can find injectable parameters !</h1>")
# -------------------------------------------------------------------------------------

outputFile.write("</body></html>")
outputFile.close()
inputFile.close()

print "\nReport generated to " + fileName2 + "\n"
#End
