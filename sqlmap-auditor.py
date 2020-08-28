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
   print(" [1] THE TARGET URL: " + WebName[:PAD1] 	+ " [10] TAMPER STRING : " + Tamper[:PAD2]   	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [2] PHP SESSION ID: " + CookieValue[:PAD1]	+ " [11] VERBOSE LEVEL : " + VerboseLevel[:PAD2] + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [3] USERNAME      : " + UserName[:PAD1]	+ " [12] TEST LEVEL    : " + Level[:PAD2]	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [4] PASSWORD      : " + PassWord[:PAD1]	+ " [13] RISK LEVEL    : " + Risk[:PAD2]	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [5] TARGET SYSTEM : " + OperatingSys[:PAD1]	+ " [14] SET TIME OUT  : " + TimeOut[:PAD2]  	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [6] DATABASE TYPE : " + DataBase[:PAD1]	+ " [15] SET TIME OUT  : " + TimeOut[:PAD2] 	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [7] USER AGENT    : " + UserAgent[:PAD1]	+ " [16] SET RETRIES   : " + Retries[:PAD2]	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [8] ENUM TECHNIQUE: " + Technique[:PAD1]	+ " [17] SET THREADS   : " + Threads[:PAD2]	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print(" [9] PARAMETER     : " + Parameter[:PAD1]      + " [xx] UNALLOCATED   : " + Blank[:PAD2]	 + "[xx] UNALLOCATED :" + Blank[:PAD2])
   print("="*165)
   print(" [0] RUN AUDITOR     " + " "*(22+PAD1+PAD2)	+ "[99] EXIT")
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

PAD1		= 70
PAD2		= 10

UserName	= "Administrator"
PassWord	= "Administrator"
OperatingSys	= "Linux"
DataBase 	= "MySQL"
UserAgent	= "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
Tamper		= "General"
CookieValue	= "o63gbsl0leeco50eh8frl72nf2"
Technique	= "BEUSTQ"
Parameter	= "ID"

WebName 	= padding(WebName, PAD1)
CookieValue	= padding(CookieValue, PAD1)
UserName	= padding(UserName, PAD1)
PassWord 	= padding(PassWord, PAD1)
OperatingSys	= padding(OperatingSys, PAD1)
DataBase	= padding(DataBase, PAD1)
UserAgent	= padding(UserAgent, PAD1)
Technique	= padding(Technique, PAD1)
Parameter	= padding(Parameter, PAD1)

VerboseLevel	= "6"
TimeDelay	= "5"
TimeOut		= "10"
Retries		= "3"
Threads		= "10"
Level 		= "5"
Risk		= "3"
Blank		= " "

VerboseLevel	= padding(VerboseLevel, PAD2)
TimeDelay	= padding(TimeDelay, PAD2)
TimeOut		= padding(TimeOut, PAD2)
Retries		= padding(Retries, PAD2)
Threads		= padding(Threads, PAD2)
Level 		= padding(Level, PAD2)
Risk		= padding(Risk, PAD2)
Blank 		= padding(Blank, PAD2)
Tamper		= padding(Tamper, PAD2)

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
THList		= "B: Boolean-based blind, E: Error-based, U: Union query-based, S: Stacked queries, T: Time-based blind, Q: Inline queries"

Tamper_GeSQL 	= "'apostrophemask, apostrophenullencode, base64encode, between, chardoubleencode, charencode, charunicodeencode, equaltolike, greatest, ifnull2ifisnull, multiplespaces, percentage, randomcase, space2comment, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
Tamper_MsSQL	= "'between, charencode, charunicodeencode, equaltolike, greatest, multiplespaces, percentage, randomcase, sp_password, space2comment, space2dash, space2mssqlblank, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
Tamper_MySQL	= "'between, bluecoat, charencode, charunicodeencode, concat2concatws, equaltolike, greatest, halfversionedmorekeywords, ifnull2ifisnull, modsecurityversioned, modsecurityzeroversioned, multiplespaces, percentage, randomcase, space2comment, space2hash, space2morehash, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes, versionedkeywords, versionedmorekeywords, xforwardedfor'"

Tamper_SeLEC	= Tamper_GeSQL

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
   selection=input("\n[*] Please Select: ")
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Dominique Righetto - dominique.righetto@owasp.org                                            
# CONTRACT: GitHub
# Version : March 2012                   
# Details : Script to generate a HTML report from a SQLMap stdout output.
# Modified: 4/9/2019
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='0':
      injectable = True
      print("[*] Audit start", datetime.datetime.now())

      command = "sqlmap -v " + VerboseLevel.rstrip(" ") + " -u " + WebName.rstrip(" ") + "-p " + Parameter.rstrip(" ") +  " --data='username=" + UserName.rstrip(" ") + "&password=" + PassWord.rstrip(" ") + "' --user-agent='" + UserAgent.rstrip(" ") + "' --delay=" + TimeDelay.rstrip(" ") + " --timeout=" + TimeOut.rstrip(" ") + " --retries=" + Retries.rstrip(" ") + " --keep-alive --threads=" + Threads.rstrip(" ") + " --batch --dbms=" + DataBase.rstrip(" ") + " --os=" + OperatingSys.rstrip(" ") + " --level=" + Level.rstrip(" ") + " --risk=" + Risk.rstrip(" ") + " --tamper=" + Tamper_SeLEC.rstrip(" ") + " --cookie='PHPSESSIONID=" + CookieValue.rstrip(" ") + "; security=low' --banner --is-dba --dbs --tables --technique=" + Technique.rstrip(" ") + " --dump-all -s logs/scan_report.txt --flush-session -t logs/scan_trace.txt --fresh-queries > logs/scan_out.txt"
      # print(command); exit(0) # Debug command
      os.system(command)
      
      Filename1  = "logs/scan_out.txt"
      Filename2  = "scan_out.html"
      
      os.system("touch " + Filename1)
      os.system("touch " + Filename2)

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
      outputFile.write("<h1 class=\"success\">\t\t\tSQLMAP AUDITOR 2020</h1>")

# -------------------------------------------------------------------------------------
# Details : Read STDOUT file line by line.
# -------------------------------------------------------------------------------------

      for line in inputFile:
         if (line.strip().startswith("[")) and (line.find("[*]") == -1):         
            if(line.lower().find("[critical]") > -1):					# Check for critical error messages
               print(line)
            if(line.lower().find("all parameters are not injectable") > -1):		# Check for special message indicating audit global status
               injectable = False  
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
      print("[*] Audit finish", datetime.datetime.now())
      print("Report generated to " + Filename2 + "\n")
      exit(1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of WebName
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='1':
      Restore = WebName.rstrip(" ")
      WebName = input("[*] Please enter the url string: ")
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
      UserName = input("[*] Please enter username: ")
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
      PassWord = input("[*] Please enter password: ")
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
      print("[+] Available Options:", OSList)
      Restore = OperatingSys
      OperatingSys = input("[*] Please enter operating system: ")
      if OperatingSys != "" and OperatingSys in OSList:
         OperatingSys = padding(OperatingSys, PAD1)
      else:
         OperatingSys = Restore
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change Value of DataBase
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------
       
   if selection =='6':
      print("[+] Available Options:", DBList)
      Restore = DataBase
      DataBase = input("[*] Please enter database: ")
      if DataBase != "" and DataBase in DBList:
         DataBase = padding(DataBase, PAD1)
      else:
         DataBase = Restore

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of UserAgent
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='7':
      Restore = UserAgent
      UserAgent = input("[*] Please enter username: ")
      if UserAgent == "":
         UserAgent = Restore
      UserAgent = padding(UserAgent, PAD1)
   
## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Technique
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='8':
      print("[+] Available Options:", THList)
      Restore = Technique
      Technique = input("[*] Please enter technique values: ")
      if Technique != "":
         Technique = padding(Technique, PAD1)
      else:
         Technique = Restore
   
## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Parameter
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='9':
      Restore = Parameter
      Parameter = input("[*] Please enter parameter value: ")
      if Parameter == "":
         Parameter = Restore
      Parameter = padding(Parameter, PAD1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Tamper
# AUTHOR  : Terence Broadbent
# ------------------------------------------------------------------------------------- 

   if selection =='10':
      print("[+] Available Options:", TAList)
      Restore = Tamper
      Tamper = input("[*] Please enter tamper value: ")
      if Tamper != "" and Tamper in TAList:
         Tamper = padding(Tamper, PAD2)
      else:
         Tamper = Restore 
             
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of VerboseLevel
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='11':
      print("[+] Available Options:", VEList)
      Restore = VerboseLevel
      VerboseLevel = input("[*] Please enter verbose value: ")
      if VerboseLevel != "" and VerboseLevel in VEList:
         VerboseLevel = padding(VerboseLevel, PAD2)
      else:
         VerboseLevel = Restore
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Level
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='12':
      print("[+] Available Options:", TEList)
      Restore = Level
      Level = input("[*] Please enter test level value: ")
      if Level != "" and Level in TEList:
         Level = padding(Level, PAD2)
      else:
         Level = Restore
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Risk
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='13':
      print("[+] Available Options:", RIList)
      Restore = Risk
      Risk = input("[*] Please enter risk value: ")
      if Risk != "" and Risk in RIList:
         Risk = padding(Risk, PAD2)
      else:
         Risk = Restore
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeDelay
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='14':
      print("[+] Available Options:", DEList)
      Restore = TimeDelay
      TimeDelay = input("[*] Please enter time delay value: ")
      if TimeDelay != "" and TimeDelay in DEList:
         TimeDelay = padding(TimeDelay, PAD2)
      else:
         TimeDelay = Restore

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeOut
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='15':
      print("[+] Available Options:", TOList)
      Restore = TimeOut
      TimeOut = input("[*] Please enter timeOut value: ")
      if TimeOut != "" and TimeOut in TOList:
         TimeOut = padding(TimeOut, PAD2)
      else:
         TimeOut = Restore
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Retries
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='16':
      print("[+] Available Options:", REList)
      Restore = Retries
      Retries = input("[*] Please enter retries value: ")
      if Retries != "" and Retries in REList:
         Retries = padding(Retries, PAD2)
      else:
         Retries = Restore
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Threads
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='17':
      print("[+] Available Options:", TRList)
      Restore = Threads
      Threads = input("[*] Please enter threads value: ")
      if Threads != "" and Threads in TRList:
         Threads = padding(Threads, PAD2)
      else:
         Threads = Restore
               
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Exit Program
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='99':
      exit(1)
#End
