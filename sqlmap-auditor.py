#!/usr/bin/python3
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

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("Please run this python script as root...")
   exit(True)

if len(sys.argv) < 2:
   print("Use the command python3 sqlmap-auditor.py https://website.com/index.php?id=1000...")
   exit(True)

WebName = sys.argv[1]

if os.path.exists("logs") == 0:
   os.system("mkdir logs")
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create functional calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def banner():
   os.system("clear")
   print("\t\t\t\t\t ____   ___  _     __  __    _    ____       _   _   _ ____ ___ _____ ___  ____   ")
   print("\t\t\t\t\t/ ___| / _ \| |   |  \/  |  / \  |  _ \     / \ | | | |  _ \_ _|_   _/ _ \|  _ \  ")
   print("\t\t\t\t\t\___ \| | | | |   | |\/| | / _ \ | |_) |   / _ \| | | | | | | |  | || | | | |_) | ")
   print("\t\t\t\t\t ___) | |_| | |___| |  | |/ ___ \|  __/   / ___ \ |_| | |_| | |  | || |_| |  _ <  ")
   print("\t\t\t\t\t|____/ \__\_\_____|_|  |_/_/   \_\_|     /_/   \_\___/|____/___| |_| \___/|_| \_\ ")
   print("\t\t\t\t\t                                                                                  ")
   print("\t\t\t\t\t              BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)             \n")
   
def display():
   print("*"*165)
   print(" [1] THE TARGET URL: " + WebName[:PAD] 	+ " [10] TAMPER LEVEL  : " + Tamper)
   print(" [2] PHP SESSION ID: " + CookieValue[:PAD]	+ " [11] VERBOSE LEVEL : " + str(VerboseLevel)) 
   print(" [3] USERNAME      : " + UserName[:PAD]	+ " [12] TEST LEVEL    : " + str(Level))
   print(" [4] PASSWORD      : " + PassWord[:PAD]	+ " [13] RISK LEVEL    : " + str(Risk))
   print(" [5] TARGET SYSTEM : " + OperatingSys[:PAD]	+ " [14] SET TIME DELAY: " + str(TimeDelay))
   print(" [6] DATABASE TYPE : " + DataBase[:PAD]	+ " [15] SET TIME OUT  : " + str(TimeOut))
   print(" [7] USER AGENT    : " + UserAgent[:PAD]	+ " [16] SET RETRIES   : " + str(Retries))
   print(" [8] ENUM TECHNIQUE: " + Technique[:PAD]	+ " [17] SET THREADS   : " + str(Threads))
   print("*"*165)
   print(" [9] RUN AUDITOR     " + " "*PAD	 	+ " [18] EXIT PROGRAM")
   print("*"*165)


def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

PAD		= 80

UserName	= "Administrator"
PassWord	= "Administrator"
OperatingSys	= "Linux"
DataBase 	= "MySQL"
UserAgent	= "SQLMAP"
Tamper		= "space2comment"
CookieValue	= "l3q63lsm8t3cms26154p56at62"
Technique	= "BEUSTQ"

WebName 	= padding(WebName, PAD)
CookieValue	= padding(CookieValue, PAD)
UserName	= padding(UserName, PAD)
PassWord 	= padding(PassWord, PAD)
OperatingSys	= padding(OperatingSys, PAD)
DataBase	= padding(DataBase, PAD)
UserAgent	= padding(UserAgent, PAD)
Technique	= padding(Technique, PAD)

VerboseLevel	= 6
TimeDelay	= 5
TimeOut		= 10
Retries		= 3
Threads		= 10 
Level 		= 5
Risk		= 3

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Build Display
# Modified: N/A
# -------------------------------------------------------------------------------------



# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

command = "\n\nsqlmap -v " + str(VerboseLevel) + " -u " + WebName.rstrip(" ") + " --data='username=" + UserName.rstrip(" ") + "&password=" + PassWord.rstrip(" ") + "' --user-agent=" + UserAgent.rstrip(" ") + " --delay=" + str(TimeDelay) + " --timeout=" + str(TimeOut) + " --retries=" + str(Retries) + " --keep-alive --threads=" + str(Threads) + " --batch --dbms=" + DataBase.rstrip(" ") + " --os=" + OperatingSys.rstrip(" ") + " --level=" + str(Level) + " --risk=" + str(Risk) + " --tamper=" + Tamper.rstrip(" ") + " --cookie='PHPSESSIONID=" + CookieValue.rstrip(" ") + "; security=low' --banner --is-dba --dbs --tables --technique=" + Technique.rstrip(" ") + " -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"

# print(command)	# Error Checking

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   os.system("clear")
   banner()
   display()
   #options()
   selection=input("\n\n[*] Please Select: ")
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='1':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='2':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='3':
      exit(0)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='4':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='5':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='6':
      exit(0)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='7':
      exit(0)
   
## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='8':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : March 2012                   
# Details : Script to generate a HTML report from a SQLMap stdout output.
# Modified: 4/9/2019
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='9':
      print("\nStarting scan, please wait this can take several hours!!...")
      os.system(command)

      injectable = False
      Filename1  = "logs/scan_out.txt"
      Filename2  = "scan_out.html"

      inputFile  = open(Filename1,"r")
      outputFile = open(Filename2,"w")

# -------------------------------------------------------------------------------------
# Details : Initialize HTML report stream.
# -------------------------------------------------------------------------------------

      outputFile.write("<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">")
      outputFile.write("<head><link rel=\"StyleSheet\" href=\"style.css\" type=\"text/css\" media=\"screen\" /><title>SQLMap HTML Audit Report</title></head>")
      outputFile.write("<body><table id=\"myStyle\">")
      outputFile.write("<thead><tr><th scope=\"col\">Test datetime</th><th scope=\"col\">Test description</th></tr></thead>")
      outputFile.write("<tbody>")

# -------------------------------------------------------------------------------------
# Details : Read STDOUT file line by line.
# -------------------------------------------------------------------------------------

      for line in inputFile:
         if (line.strip().startswith("[")) and (line.find("[*]") == -1):
            if(line.lower().find("all parameters are not injectable") > -1):		# Check for special message indicating audit global status
               injectable = True
            line_part = line.strip().split(" ")					        # Report generation
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
      print("\nReport generated to " + Filename2 + "\n")
      exit(1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='11':
      exit(0)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='12':
      exit(0)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='13':
      exit(0)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='14':
      exit(0)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='15':
      exit(0)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='16':
      exit(0)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : 1.0
# Details : 
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='17':
      exit(0)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : 1.0
# Details : Exit Program
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='18':
      exit(1)
#End
