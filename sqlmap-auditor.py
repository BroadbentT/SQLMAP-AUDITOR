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
import os.path
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

webName = sys.argv[1]

if os.path.exists("logs") == 0:
   os.system("mkdir logs")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display my universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")
print "\t\t\t ____   ___  _     __  __    _    ____       _   _   _ ____ ___ _____ ___  ____   "
print "\t\t\t/ ___| / _ \| |   |  \/  |  / \  |  _ \     / \ | | | |  _ \_ _|_   _/ _ \|  _ \  "
print "\t\t\t\___ \| | | | |   | |\/| | / _ \ | |_) |   / _ \| | | | | | | |  | || | | | |_) | "
print "\t\t\t ___) | |_| | |___| |  | |/ ___ \|  __/   / ___ \ |_| | |_| | |  | || |_| |  _ <  "
print "\t\t\t|____/ \__\_\_____|_|  |_/_/   \_\_|     /_/   \_\___/|____/___| |_| \___/|_| \_\ "
print "\t\t\t                                                                                  "
print "\t\t\t              BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)             \n"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

command = "sqlmap -v 2 -u http://" + webName + " --data='username=admin&password=admin' --user-agent=SQLMAP --delay=1 --timeout=15 --retries=2 --keep-alive --threads=5 --batch --dbms=MySQL --os=Linux --level=5 --risk=3  --tamper=space2comment --cookie='PHPSESSIONID=sirkdou58nuhqmbtu29bmib58v; security=low' --banner --is-dba --dbs --tables --technique=BEUST -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

print "SCAN COMMAND:"
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

injectable = False
webName1  = "logs/scan_out.txt"
webName2  = "scan_out.html"

inputFile  = open(webName1,"r")
outputFile = open(webName2,"w")

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
# Details : Write global audit stats line.
# -------------------------------------------------------------------------------------

if(injectable):
   outputFile.write("<h1 class=\"success\">SQLMap cannot find injectable parameters !</h1>")
else:
   outputFile.write("<h1 class=\"fail\">SQLMap can find injectable parameters !</h1>")

# -------------------------------------------------------------------------------------
# Details : Close open file and tidy up.
# -------------------------------------------------------------------------------------

outputFile.write("</body></html>")
outputFile.close()
inputFile.close()
print "\nReport generated to " + webName2 + "\n"
#End
