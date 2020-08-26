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
import datetime

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
   print("-"*165)
   print(" [1] THE TARGET URL: " + WebName[:PAD1] 	+ " [10] WAF BYPASS    : " + Tamper)
   print(" [2] PHP SESSION ID: " + CookieValue[:PAD1]	+ " [11] VERBOSE LEVEL : " + str(VerboseLevel)) 
   print(" [3] USERNAME      : " + UserName[:PAD1]	+ " [12] TEST LEVEL    : " + str(Level))
   print(" [4] PASSWORD      : " + PassWord[:PAD1]	+ " [13] RISK LEVEL    : " + str(Risk))
   print(" [5] TARGET SYSTEM : " + OperatingSys[:PAD1]	+ " [14] SET TIME DELAY: " + str(TimeDelay))
   print(" [6] DATABASE TYPE : " + DataBase[:PAD1]	+ " [15] SET TIME OUT  : " + str(TimeOut))
   print(" [7] USER AGENT    : " + UserAgent[:PAD1]	+ " [16] SET RETRIES   : " + str(Retries))
   print(" [8] ENUM TECHNIQUE: " + Technique[:PAD1]	+ " [17] SET THREADS   : " + str(Threads))
   print("="*165)
   print(" [9] RUN AUDITOR     " + " "*PAD1	 	+ " [18] EXIT PROGRAM")
   print("-"*165)


def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable
   
def pause():
   input("\n[*] Please press ENTER to continue")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

PAD1		= 80
PAD2		= 40
CRIT		= 0

UserName	= "Administrator"
PassWord	= "Administrator"
OperatingSys	= "Linux"
DataBase 	= "MySQL"
UserAgent	= "SQLMAP"
Tamper		= "General"
CookieValue	= "su9q2tmc91dj9vvhsoj2nrapi4"
Technique	= "BEUSTQ"

WebName 	= padding(WebName, PAD1)
CookieValue	= padding(CookieValue, PAD1)
UserName	= padding(UserName, PAD1)
PassWord 	= padding(PassWord, PAD1)
OperatingSys	= padding(OperatingSys, PAD1)
DataBase	= padding(DataBase, PAD1)
UserAgent	= padding(UserAgent, PAD1)
Technique	= padding(Technique, PAD1)

VerboseLevel	= "6"
TimeDelay	= "5"
TimeOut		= "10"
Retries		= "3"
Threads		= "10"
Level 		= "5"
Risk		= "3"

OSList		= "Linux, Windows"
DBList		= "MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase, SAP MaxDB, Informix, MariaDB, Percona, MemSQL, TiDB2, CockroachDB, HSQLDB, H2, MonetDB, Apache Derby, Amazon Redshift, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, Cubrid, InterSystems Cache, IRIS, eXtremeDB, FrontBase"
TAList		= "General, MsSQL, MySQL"
VEList		= "1, 2, 3, 4, 5, 6"
TEList		= "1, 2, 3, 4, 5"
RIList		= "1, 2, 3"
DEList		= "1, 2, 3, 4, 5"
TOList		= "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30"
REList		= "1, 2, 3"
TRList		= "1, 2, 3, 4, 5, 6, 7, 8, 9, 10"

Tamper_GeSQL 	= "'apostrophemask, apostrophenullencode, base64encode, between, chardoubleencode, charencode, charunicodeencode, equaltolike, greatest, ifnull2ifisnull, multiplespaces, percentage, randomcase, space2comment, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
Tamper_MsSQL	= "'between, charencode, charunicodeencode, equaltolike, greatest, multiplespaces, percentage, randomcase, sp_password, space2comment, space2dash, space2mssqlblank, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
Tamper_MySQL	= "'between, bluecoat, charencode, charunicodeencode, concat2concatws, equaltolike, greatest, halfversionedmorekeywords, ifnull2ifisnull, modsecurityversioned, modsecurityzeroversioned, multiplespaces, percentage, randomcase, space2comment, space2hash, space2morehash, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes, versionedkeywords, versionedmorekeywords, xforwardedfor'"

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
   
   if Tamper == "General":
      command = "\n\nsqlmap -v " + VerboseLevel + " -u " + WebName.rstrip(" ") + " --data='username=" + UserName.rstrip(" ") + "&password=" + PassWord.rstrip(" ") + "' --user-agent=" + UserAgent.rstrip(" ") + " --delay=" + TimeDelay + " --timeout=" + TimeOut + " --retries=" + Retries + " --keep-alive --threads=" + Threads + " --batch --dbms=" + DataBase.rstrip(" ") + " --os=" + OperatingSys.rstrip(" ") + " --level=" + Level + " --risk=" + Risk + " --tamper=" + Tamper_GeSQL + " --cookie='PHPSESSIONID=" + CookieValue.rstrip(" ") + "; security=low' --banner --is-dba --dbs --tables --technique=" + Technique.rstrip(" ") + " --dump-all -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"
   if Tamper == "MySQL":
      command = "\n\nsqlmap -v " + VerboseLevel + " -u " + WebName.rstrip(" ") + " --data='username=" + UserName.rstrip(" ") + "&password=" + PassWord.rstrip(" ") + "' --user-agent=" + UserAgent.rstrip(" ") + " --delay=" + TimeDelay + " --timeout=" + TimeOut + " --retries=" + Retries + " --keep-alive --threads=" + Threads + " --batch --dbms=" + DataBase.rstrip(" ") + " --os=" + OperatingSys.rstrip(" ") + " --level=" + Level + " --risk=" + Risk + " --tamper=" + Tamper_MySQL + " --cookie='PHPSESSIONID=" + CookieValue.rstrip(" ") + "; security=low' --banner --is-dba --dbs --tables --technique=" + Technique.rstrip(" ") + " --dump-all -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"
   if Tamper == "MsSQL":
      command = "\n\nsqlmap -v " + VerboseLevel + " -u " + WebName.rstrip(" ") + " --data='username=" + UserName.rstrip(" ") + "&password=" + PassWord.rstrip(" ") + "' --user-agent=" + UserAgent.rstrip(" ") + " --delay=" + TimeDelay + " --timeout=" + TimeOut + " --retries=" + Retries + " --keep-alive --threads=" + Threads + " --batch --dbms=" + DataBase.rstrip(" ") + " --os=" + OperatingSys.rstrip(" ") + " --level=" + Level + " --risk=" + Risk + " --tamper=" + Tamper_MsSQL + " --cookie='PHPSESSIONID=" + CookieValue.rstrip(" ") + "; security=low' --banner --is-dba --dbs --tables --technique=" + Technique.rstrip(" ") + " --dump-all -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"
   # print(command) # DEBUG

   selection=input("\n[*] Please Select: ")
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of WebName
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='1':
      Restore = WebName.rstrip(" ")
      WebName = input("[*] Please enter WebName value: ")
      if WebName == "":
         WebName = Restore
      WebName = padding(WebName, PAD1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of CookieValue
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='2':
      Restore = CookieValue.rstrip(" ")
      CookieValue = input("[*] Please enter PHPSESSID value: ")
      if CookieValue == "":
         CookieValue = Restore
      CookieValue = padding(CookieValue, PAD1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of UserName
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='3':
      Restore = UserName.rstrip(" ")
      UserName = input("[*] Please enter UserName value: ")
      if UserName == "":
         UserName = Restore
      UserName = padding(UserName, PAD1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of PassWord
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='4':
      Restore = PassWord.rstrip(" ")
      PassWord = input("[*] Please enter PassWord value: ")
      if PassWord == "":
         PassWord = Restore
      PassWord = padding(PassWord, PAD1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of OperatingSys
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='5':
      Restore = OperatingSys.rstrip(" ")
      OperatingSys = input("[*] Please enter OperatingSys value: ")
      if OperatingSys == "":
         OperatingSys = Restore         
      if OperatingSys in OSList:
         OperatingSys = padding(OperatingSys, PAD1)
      else:
         OperatingSys = Restore
         print("[-] Available Options:", OSList)
         pause()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change Value of DataBase
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='6':
      Restore = DataBase.rstrip(" ")
      DataBase = input("[*] Please enter DataBase value: ")
      if DataBase == "":
         DataBase = Restore
      if DataBase in DBList:
         DataBase = padding(DataBase, PAD1)
      else:
         DataBase = Restore        
         print("[-] Available Options:", DBList)
         pause()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Technique
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
      injectable = False
      print("[*] Audit start", datetime.datetime.now())
      os.system(command)
      
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
            if(line.lower().find("[critical]") > -1):					# Check for critical error messages
               print(line)
               CRIT = 1
            print(line)
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
      if CRIT != 1:
         print("Report generated to " + Filename2 + "\n")
      exit(1)

## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Tamper
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='10':
      Restore = Tamper.rstrip(" ")
      Tamper = input("[*] Please enter Tamper value: ")
      if Tamper == "":
         Tamper = Restore
      if Tamper in TAList:
         Tamper = padding(Tamper, PAD2)
      else:
         Tamper = Restore        
         print("[-] Available Options:")
         print("\n[+] General which contains -", Tamper_GeSQL.strip("'"))
         print("\n[+] MsSQL which contains -", Tamper_MsSQL.strip("'"))
         print("\n[+] MySQL which contains -", Tamper_MySQL.strip("'"))
         pause()
             
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of VerboseLevel
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='11':
      Restore = VerboseLevel.rstrip(" ")
      VerboseLevel = input("[*] Please enter Verbose value: ")
      if VerboseLevel == "":
         VerboseLevel = Restore         
      if VerboseLevel in VEList:
         VerboseLevel = padding(VerboseLevel, PAD2)
      else:
         VerboseLevel = Restore
         print("[-] Available Options:", VEList)
         pause()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Level
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='12':
      Restore = Level.rstrip(" ")
      Level = input("[*] Please enter Level value: ")
      if Level == "":
         Level = Restore         
      if Level in TEList:
         Level = padding(Level, PAD2)
      else:
         Level = Restore
         print("[-] Available Options:", TEList)
         pause()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Risk
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='13':
      Restore = Risk.rstrip(" ")
      Risk = input("[*] Please enter Risk value: ")
      if Risk == "":
         Risk = Restore         
      if Risk in RIList:
         Risk = padding(Risk, PAD2)
      else:
         Risk = Restore
         print("[-] Available Options:", RIList)
         pause()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeDelay
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='14':
      Restore = TimeDelay.rstrip(" ")
      TimeDelay = input("[*] Please enter TimeDelay value: ")
      if TimeDelay == "":
         TimeDelay = Restore         
      if TimeDelay in DEList:
         TimeDelay = padding(TimeDelay, PAD2)
      else:
         TimeDelay = Restore
         print("[-] Available Options:", DEList)
         pause()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeOut
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='15':
      Restore = TimeOut.rstrip(" ")
      TimeOut = input("[*] Please enter TimeOut value: ")
      if TimeOut == "":
         TimeOut = Restore         
      if TimeOut in TOList:
         TimeOut = padding(TimeOut, PAD2)
      else:
         TimeOut = Restore
         print("[-] Available Options:", TOList)
         pause()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Retries
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='16':
      Restore = Retries.rstrip(" ")
      Retries = input("[*] Please enter Retries value: ")
      if Retries == "":
         Retries = Restore         
      if Retries in REList:
         Retries = padding(Retries, PAD2)
      else:
         Retries = Restore
         print("[-] Available Options:", REList)
         pause()        
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Threads
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='17':
      Restore = Threads.rstrip(" ")
      Threads = input("[*] Please enter Threads value: ")
      if Threads == "":
         Threads = Restore         
      if Threads in TRList:
         Threads = padding(Threads, PAD2)
      else:
         Threads = Restore
         print("[-] Available Options:", TRList)
         pause()  
               
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
