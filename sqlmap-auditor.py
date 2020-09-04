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

WebNam = sys.argv[1]

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
   print('\u2554' + ('\u2550')*89 + '\u2566' + ('\u2550')*30     + '\u2566' + ('\u2550')*42 + '\u2557')   
   print('\u2551' + "[1] THE TARGET URL: " + WebNam[:PPPAD1] + '\u2551' + " [10] TAMPER STRING : " + Tamper[:PPPAD2] + '\u2551' + " [19] SHOW DBASES : " + DBOptn[:PPPAD3] + '\u2551')
   print('\u2551' + "[2] PHP SESSION ID: " + Cookie[:PPPAD1] + '\u2551' + " [11] HTTP METHOD   : " + Method[:PPPAD2] + '\u2551' + " [20] SHOW TABLES : " + TABOtn[:PPPAD3] + '\u2551')
   print('\u2551' + "[3] USERNAME      : " + UsName[:PPPAD1] + '\u2551' + " [12] VERBOSE LEVEL : " + VernOT[:PPPAD2] + '\u2551' + " [21] SHOW COMMAND: " + ShowCD[:PPPAD3] + '\u2551')
   print('\u2551' + "[4] PASSWORD      : " + PaWord[:PPPAD1] + '\u2551' + " [13] SET LEVEL     : " + Levels[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2551' + "[5] TARGET SYSTEM : " + OperSY[:PPPAD1] + '\u2551' + " [14] SET RISK LEVEL: " + RiskLe[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2551' + "[6] DATABASE TYPE : " + DataBA[:PPPAD1] + '\u2551' + " [15] SET DELAY TIME: " + TimeDE[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2551' + "[7] USER AGENT    : " + UserAG[:PPPAD1] + '\u2551' + " [16] SET TIME OUT  : " + TimeOT[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2551' + "[8] TECHNIQUE     : " + TechNQ[:PPPAD1] + '\u2551' + " [17] SET RETRIES   : " + Retrie[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2551' + "[9] PARAMETER     : " + Params[:PPPAD1] + '\u2551' + " [18] SET THREADS   : " + Thread[:PPPAD2] + '\u2551' + "                    " + Blank2[:PPPAD3] + '\u2551')
   print('\u2560' + ('\u2550')*89 + '\u2569' + ('\u2550')*10 + ('\u2550')*20 + '\u2569' + ('\u2550')*42 + '\u2563')
   print('\u2551' + "[0] RUN AUDITOR     "   + " "*(PPPAD1) + " "*(74) + '\u2551')
   print('\u255A' + ('\u2550')*90 + ('\u2550')*73 + '\u255D')

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

PPPAD1	= 69
PPPAD2	= 8
PPPAD3	= 22
DABASO	= 1
TABLEO	= 1
SHOWCD	= 0

UsName	= "Administrator"
PaWord	= "Administrator"
OperSY	= "Linux"
DataBA 	= "MySQL"
UserAG	= "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
Tamper	= "None"
Cookie	= "p8g7kr0sgmpn1ej2tb62nsbi31"
TechNQ	= "BEUSTQ"
Params	= "id"
Method 	= "GET"
MethUD	= "GET"
VernOT	= "6"
TimeDE	= "5"
TimeOT	= "10"
Retrie	= "3"
Thread	= "10"
Levels 	= "5"
RiskLe	= "3"
DBOptn	= "Yes"
TABOtn   = "Yes"
ShowCD	= "No"
Blank1	= " "
Blank2	= " "

DAList	= "Yes, No"
TBList	= "Yes, No"
CMList   = "Yes, No"
OSList	= "Linux, Windows"
DBList	= "MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase, SAP MaxDB, Informix, MariaDB, Percona, MemSQL, TiDB2, CockroachDB, HSQLDB, H2, MonetDB, Apache Derby, Amazon Redshift, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, Cubrid, InterSystems Cache, IRIS, eXtremeDB, FrontBase, ''"
TAList	= "None, General, MsSQL, MySQL"
MEList	= "PUT, GET, POST, HEAD, DELETE, PATCH, TRACE, OPTIONS"
VEList	= "1, 2, 3, 4, 5, 6"
TEList	= "1, 2, 3, 4, 5"
RIList	= "1, 2, 3"
DEList	= "1, 2, 3, 4, 5"
TOList	= "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30"
REList	= "1, 2, 3"
TRList	= "1, 2, 3, 4, 5, 6, 7, 8, 9, 10"
THList	= "B: Boolean-based blind, E: Error-based, U: Union query-based, S: Stacked queries, T: Time-based blind, Q: Inline queries"
TNoSQL	= "''"
TSeLec	= "''"
TGeSQL	= "'apostrophemask, apostrophenullencode, base64encode, between, chardoubleencode, charencode, charunicodeencode, equaltolike, greatest, ifnull2ifisnull, multiplespaces, percentage, randomcase, space2comment, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
TMsSQL	= "'between, charencode, charunicodeencode, equaltolike, greatest, multiplespaces, percentage, randomcase, sp_password, space2comment, space2dash, space2mssqlblank, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes'"
TMySQL	= "'between, bluecoat, charencode, charunicodeencode, concat2concatws, equaltolike, greatest, halfversionedmorekeywords, ifnull2ifisnull, modsecurityversioned, modsecurityzeroversioned, multiplespaces, percentage, randomcase, space2comment, space2hash, space2morehash, space2mysqldash, space2plus, space2randomblank, unionalltounion, unmagicquotes, versionedkeywords, versionedmorekeywords, xforwardedfor'"

WebNam	= padding(WebNam, PPPAD1)
Cookie	= padding(Cookie, PPPAD1)
UsName	= padding(UsName, PPPAD1)
PaWord	= padding(PaWord, PPPAD1)
OperSY	= padding(OperSY, PPPAD1)
DataBA	= padding(DataBA, PPPAD1)
UserAG	= padding(UserAG, PPPAD1)
TechNQ	= padding(TechNQ, PPPAD1)
Params	= padding(Params, PPPAD1)

Blank1 	= padding(Blank1, PPPAD2)
Blank2	= padding(Blank2, PPPAD3)
VernOT	= padding(VernOT, PPPAD2)
TimeDE	= padding(TimeDE, PPPAD2)
TimeOT	= padding(TimeOT, PPPAD2)
Retrie	= padding(Retrie, PPPAD2)
Thread	= padding(Thread, PPPAD2)
Levels 	= padding(Levels, PPPAD2)
RiskLe	= padding(RiskLe, PPPAD2)
Tamper	= padding(Tamper, PPPAD2)
Method 	= padding(Method, PPPAD2)

DBOptn  = padding(DBOptn, PPPAD3)
TABOtn	= padding(TABOtn, PPPAD3)
ShowCD  = padding(ShowCD, PPPAD3)

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
      injectable = False
      print("[*] Audit start", datetime.datetime.now())
      
      if DABASO	== 0 and TABLEO	== 0:
         command = "sqlmap -v " + VernOT.rstrip(" ") + " -u " + WebNam.rstrip(" ") + " -p " + Params.rstrip(" ") +  " --data='username=" + UsName.rstrip(" ") + "&password=" + PaWord.rstrip(" ") + "' --user-agent='" + UserAG.rstrip(" ") + "' --method=" + MethUD.rstrip(" ") + " --delay=" + TimeDE.rstrip(" ") + " --timeout=" + TimeOT.rstrip(" ") + " --retries=" + Retrie.rstrip(" ") + " --keep-alive --threads=" + Thread.rstrip(" ") + " --dbms=" + DataBA.rstrip(" ") + " --os=" + OperSY.rstrip(" ") + " --level=" + Levels.rstrip(" ") + " --risk=" + RiskLe.rstrip(" ") + " --tamper=" + TSeLec.rstrip(" ") + " --cookie='PHPSESSIONID=" + Cookie.rstrip(" ") + "; security=low' --banner --is-dba --technique=" + TechNQ.rstrip(" ") + " --batch --flush-session --fresh-queries -s logs/scan_report.txt -t logs/scan_trace.txt > logs/scan_out.txt"
      if DABASO	== 0 and TABLEO	== 1:
         command = "sqlmap -v " + VernOT.rstrip(" ") + " -u " + WebNam.rstrip(" ") + " -p " + Params.rstrip(" ") +  " --data='username=" + UsName.rstrip(" ") + "&password=" + PaWord.rstrip(" ") + "' --user-agent='" + UserAG.rstrip(" ") + "' --method=" + MethUD.rstrip(" ") + " --delay=" + TimeDE.rstrip(" ") + " --timeout=" + TimeOT.rstrip(" ") + " --retries=" + Retrie.rstrip(" ") + " --keep-alive --threads=" + Thread.rstrip(" ") + " --dbms=" + DataBA.rstrip(" ") + " --os=" + OperSY.rstrip(" ") + " --level=" + Levels.rstrip(" ") + " --risk=" + RiskLe.rstrip(" ") + " --tamper=" + TSeLec.rstrip(" ") + " --cookie='PHPSESSIONID=" + Cookie.rstrip(" ") + "; security=low' --banner --is-dba --technique=" + TechNQ.rstrip(" ") + " --tables --batch --flush-session --fresh-queries -s logs/scan_report.txt -t logs/scan_trace.txt > logs/scan_out.txt"
      if DABASO	== 1 and TABLEO	== 0:
         command = "sqlmap -v " + VernOT.rstrip(" ") + " -u " + WebNam.rstrip(" ") + " -p " + Params.rstrip(" ") +  " --data='username=" + UsName.rstrip(" ") + "&password=" + PaWord.rstrip(" ") + "' --user-agent='" + UserAG.rstrip(" ") + "' --method=" + MethUD.rstrip(" ") + " --delay=" + TimeDE.rstrip(" ") + " --timeout=" + TimeOT.rstrip(" ") + " --retries=" + Retrie.rstrip(" ") + " --keep-alive --threads=" + Thread.rstrip(" ") + " --dbms=" + DataBA.rstrip(" ") + " --os=" + OperSY.rstrip(" ") + " --level=" + Levels.rstrip(" ") + " --risk=" + RiskLe.rstrip(" ") + " --tamper=" + TSeLec.rstrip(" ") + " --cookie='PHPSESSIONID=" + Cookie.rstrip(" ") + "; security=low' --banner --is-dba --technique=" + TechNQ.rstrip(" ") + " --dbs --batch --flush-session --fresh-queries -s logs/scan_report.txt -t logs/scan_trace.txt > logs/scan_out.txt"

      if SHOWCD == 1:
         print("\n" + command + "\n") 
                         
      os.system(command)
            
# -------------------------------------------------------------------------------------
# Details : Initialize HTML report stream.
# -------------------------------------------------------------------------------------

      Filename1  = "logs/scan_out.txt"
      Filename2  = "scan_out.html"
      inputFile  = open(Filename1,"r")
      outputFile = open(Filename2,"w")

      outputFile.write("<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">")
      outputFile.write("<head><link rel=\"StyleSheet\" href=\"style.css\" type=\"text/css\" media=\"screen\" /><title>SQLMap HTML Audit Report</title></head>")
      outputFile.write("<body><table id=\"myStyle\">")
      outputFile.write("<thead><tr><th scope=\"col\">Test datetime</th><th scope=\"col\">Test description</th></tr></thead>")
      outputFile.write("<tbody>")
      outputFile.write("<h1 class=\"success\">\t\t\tSQLMAP AUDITOR 2020</h1>")

# -------------------------------------------------------------------------------------
# Details : Read STDOUT file line by line and check results.
# -------------------------------------------------------------------------------------

      for line in inputFile:
         testparameter = MethUD.rstrip(" ") + " parameter " + Params.rstrip(" ") + " is vulnerable".lower()

         if(line.find(testparameter) != -1):							# Check for confirmation of injection points
            print("[+] " + line.rstrip("\n"))            
            injectable = True                  

         if(line.find("sqlmap identified the following injection point(s)") != -1):		# Check for confirmation of injection points
            print("[+] " + line.rstrip("\n"))            
            injectable = True
            
         if(line.find("current user is DBA:") != -1):						# Print INFO data
            print("[+] " + line.rstrip("\n"))   
            
         if(line.find("back-end DBMS:") != -1):							# Print INFO data
            print("[+] " + line.rstrip("\n"))
            
         if(line.find("[CRITICAL]") != -1):							# Print INFO data
            print("[+] " + line.rstrip("\n"))            
                     
         if(line.lower().find("all parameters are not injectable") != -1):			# Check for confirmation of injection points
            print("[+] " + line.rstrip("\n"))            
            injectable = False                
               
# -------------------------------------------------------------------------------------
# Details : Report Generation
# -------------------------------------------------------------------------------------
               
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

      if injectable == False:
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
# Details : Change the value of WebNam
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='1':
      Restore = WebNam.rstrip(" ")
      WebNam = input("[*] Please enter the url string: ")
      if WebNam == "":
         WebNam = Restore
      WebNam = padding(WebNam, PPPAD1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Cookie
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='2':
      Restore = Cookie.rstrip(" ")
      Cookie = input("[*] Please enter PHPSESSID value: ")
      if Cookie == "":
         Cookie = Restore
      Cookie = padding(Cookie, PPPAD1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of UsName
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='3':
      Restore = UsName.rstrip(" ")
      UsName = input("[*] Please enter username: ")
      if UsName == "":
         UsName = Restore
      UsName = padding(UsName, PPPAD1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of PaWord
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='4':
      Restore = PaWord.rstrip(" ")
      PaWord = input("[*] Please enter password: ")
      if PaWord == "":
         PaWord = Restore
      PaWord = padding(PaWord, PPPAD1)
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of OperSY
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='5':
      print("[+] Available Options:", OSList)
      Restore = OperSY
      OperSY = input("[*] Please enter operating system: ")
      if OperSY != "" and OperSY in OSList:
         OperSY = padding(OperSY, PPPAD1)
      else:
         OperSY = Restore
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change Value of DataBA
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------
       
   if selection =='6':
      print("[+] Available Options:", DBList)
      Restore = DataBA
      DataBA = input("[*] Please enter database: ")
      if DataBA != "" and DataBA in DBList:
         DataBA = padding(DataBA, PPPAD1)
      else:
         DataBA = Restore

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of UserAG
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='7':
      Restore = UserAG
      UserAG = input("[*] Please enter useragent string: ")
      if UserAG == "":
         UserAG = Restore
      UserAG = padding(UserAG, PPPAD1)
   
## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TechNQ
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='8':
      print("[+] Available Options:", THList)
      Restore = TechNQ
      TechNQ = input("[*] Please enter technique value(s): ")
      if TechNQ != "":
         TechNQ = padding(TechNQ, PPPAD1)
      else:
         TechNQ = Restore
   
## ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Params
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='9':
      Restore = Params
      Params = input("[*] Please enter parameter value: ")
      if Params == "":
         Params = Restore
      Params = padding(Params, PPPAD1)
      
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
         Tamper = padding(Tamper, PPPAD2)
         if Tamper.rstrip(" ") == "None":
            TSeLec = TNoSQL
         if Tamper.rstrip(" ") == "General":
            TSeLec = TGeSQL
         if Tamper.rstrip(" ") == "MsSQL":
            TSeLec = TMsSQL
         if Tamper.rstrip(" ") == "MySQL":
            TSeLec = TMySQL
      else:
         Tamper = Restore 
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Method
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='11':
      print("[+] Available Options:", MEList)
      Restore = Method
      Method = input("[*] Please enter method value: ")
      if Method != "" and Method in MEList:
         Method = padding(Method, PPPAD2)
         if Method.rstrip(" ") == "None":
            MethUD = ""
         else:
            MethUD = Method
      else:
         Method = Restore
                      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of VernOT
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='12':
      print("[+] Available Options:", VEList)
      Restore = VernOT
      VernOT = input("[*] Please enter verbose value: ")
      if VernOT != "" and VernOT in VEList:
         VernOT = padding(VernOT, PPPAD2)
      else:
         VernOT = Restore
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Levels
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='13':
      print("[+] Available Options:", TEList)
      Restore = Levels
      Levels = input("[*] Please enter level value: ")
      if Levels != "" and Levels in TEList:
         Levels = padding(Levels, PPPAD2)
      else:
         Levels = Restore
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of RiskLe
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='14':
      print("[+] Available Options:", RIList)
      Restore = RiskLe
      RiskLe = input("[*] Please enter risk value: ")
      if RiskLe != "" and RiskLe in RIList:
         RiskLe = padding(RiskLe, PPPAD2)
      else:
         RiskLe = Restore
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeDE
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='15':
      print("[+] Available Options:", DEList)
      Restore = TimeDE
      TimeDE = input("[*] Please enter delay value: ")
      if TimeDE != "" and TimeDE in DEList:
         TimeDE = padding(TimeDE, PPPAD2)
      else:
         TimeDE = Restore

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of TimeOT
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='16':
      print("[+] Available Options:", TOList)
      Restore = TimeOT
      TimeOT = input("[*] Please enter timeout value: ")
      if TimeOT != "" and TimeOT in TOList:
         TimeOT = padding(TimeOT, PPPAD2)
      else:
         TimeOT = Restore
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change value of Retrie
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='17':
      print("[+] Available Options:", REList)
      Restore = Retrie
      Retrie = input("[*] Please enter retries value: ")
      if Retrie != "" and Retrie in REList:
         Retrie = padding(Retrie, PPPAD2)
      else:
         Retrie = Restore
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of Thread
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='18':
      print("[+] Available Options:", TRList)
      Restore = Thread
      Thread = input("[*] Please enter threads value: ")
      if Thread != "" and Thread in TRList:
         Thread = padding(Thread, PPPAD2)
      else:
         Thread = Restore       
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of enum databases
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='19':
      print("[+] Available Options:", DAList)
      Restore = DBOptn
      DBOptn= input("[*] Please enter database option: ")
      if DBOptn != "" and DBOptn in DAList:
         DBOptn = padding(DBOptn, PPPAD3)
         if DBOptn.rstrip(" ") == "Yes":
            DABASO = 1
         else:
            DABASO = 0
      else:
         DBOptn = Restore

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of enum tables
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='20':
      print("[+] Available Options:", TBList)
      Restore = TABOtn
      TABOtn= input("[*] Please enter table option: ")
      if TABOtn != "" and TABOtn in TBList:
         TABOtn = padding(TABOtn, PPPAD3)
         if TABOtn.rstrip(" ") == "Yes":
            TABLEO = 1
         else:
            TABLEO = 0
      else:
         TABOtn = Restore
 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent
# CONTRACT: GitHub
# Version : 1.0
# Details : Change the value of ShowCD
# AUTHOR  : Terence Broadbent
# -------------------------------------------------------------------------------------

   if selection =='21':
      print("[+] Available Options:", CMList)
      Restore = ShowCD
      ShowCD= input("[*] Please enter command value: ")
      if ShowCD != "" and ShowCD in CMList:
         ShowCD = padding(ShowCD, PPPAD3)
         if ShowCD.rstrip(" ") == "Yes":
            SHOWCD = 1
         else:
            SHOWCD = 0
      else:
         ShowCD = Restore
            
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
