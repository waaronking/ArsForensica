setlocal enableextensions
cd /d "%~dp0"

ECHO OFF
CLS


:SYSMENU
CLS
CALL :ASCIIART
CALL :TITLE
ECHO.
ECHO    1 - Forensic Workstation
ECHO    2 - Incident Machine
ECHO    Q - EXIT
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO FINIT
IF /I '%IN%'=='2' GOTO IINIT
IF /I '%IN%'=='Q' GOTO QUIT




REM Forensic workstation menu
:FINIT
SET /P CASE="Case ID:"
SET /P IP="INCIDENT Machine IP Address:"
ECHO CASE ID: %CASE% > findings/%CASE%.txt
ECHO Incident Machine IP Address: %IP% >> findings/%CASE%.txt
date /t >> findings/%CASE%.txt
time /t >> findings/%CASE%.txt
ECHO. >> findings/%CASE%.txt
ECHO MD5Hashes: >> findings/%CASE%.txt

:FMENU
CLS
CALL :TITLE
ECHO.
ECHO  ------------- Forensic Workstation Menu ------------
ECHO  Case: %CASE%
ECHO.
ECHO    1 - Incident Response
ECHO    2 - Network Based Forensics
ECHO    3 - Data Capture
ECHO    4 - MISC
ECHO    Q - QUIT
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO INCIDENT
IF /I '%IN%'=='2' GOTO NBF
IF /I '%IN%'=='3' GOTO DATACAP
IF /I '%IN%'=='4' GOTO MISC
IF /I '%IN%'=='Q' GOTO QUIT







:INCIDENT
CLS
CALL :TITLE
ECHO.
ECHO  ----------------- Incident Response ----------------
ECHO  Case: %CASE%
ECHO.
ECHO    1 - Automated Information Capture
ECHO    2 - Memory Dump
ECHO    Q - Return to Forensic Workstation Menu
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO AUTOSCRIPT
IF /I '%IN%'=='2' GOTO MEMDUMP
IF /I '%IN%'=='Q' GOTO FMENU

    :AUTOSCRIPT
    SET IN=psinfo -h -s -d /accepteula
    SET FN=system_info
    CALL :EXECOMMAND

    SET IN=ipconfig /all
    SET FN=ipconfig
    CALL :EXECOMMAND
  
    SET IN=netstat
    SET FN=netstat_basic
    CALL :EXECOMMAND
  
    SET IN=netstat -anob
    SET FN=netstat_admin
    CALL :EXECOMMAND
  
    SET IN=psloggedon /accepteula
    SET FN=logged_on_users
    CALL :EXECOMMAND

    SET IN=psfile /accepteula
    SET FN=open_files
    CALL :EXECOMMAND    

    SET IN=pslist /accepteula
    SET FN=processes
    CALL :EXECOMMAND

    SET IN=psservice /accepteula
    SET FN=services
    CALL :EXECOMMAND    

    SET IN=schtasks.exe
    SET FN=scheduled_tasks
    CALL :EXECOMMAND  
    
	SET IN=nbtstat -c
    SET FN=netbios_cache
    CALL :EXECOMMAND

	SET IN=arp -a
    SET FN=arp_table
    CALL :EXECOMMAND

	SET IN=netstat -rn
    SET FN=routing_table
    CALL :EXECOMMAND	
	
	REM at is used in older Windows OSes
	SET IN=at
    SET FN=scheduled_tasks
    CALL :EXECOMMAND
	
	SET IN=schtasks
    SET FN=scheduled_tasks
    CALL :EXECOMMAND
	
    SET IN=handle /accepteula
    SET FN=handles
    CALL :EXECOMMAND 
	
	SET IN=listdlls /accepteula
    SET FN=loaded_dlls
    CALL :EXECOMMAND
	
    GOTO INCIDENT
	
	:MEMDUMP
	SET IN=dumpit
    SET FN=memdump
    CALL :EXECOMMAND
	GOTO INCIDENT
	
	


:NBF
CLS
CALL :TITLE
ECHO.
ECHO  -------------- Network Based Forensics -------------
ECHO  Case: %CASE%
ECHO.
ECHO    1 - Capture Network Data
ECHO    Q - Return to Forensic Workstation Menu
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO NETCAPTURE
IF /I '%IN%'=='Q' GOTO FMENU

	:NETCAPTURE
    REM - runs tshark (wireshark install) - captures first 1000 packets with source or destination of Forensic IP
	"C:\Program Files\Wireshark\tshark.exe" -c 1000 host %IP% -w %~dp0findings\%CASE%.pcap
    GOTO NBF

:DATACAP
CLS
CALL :TITLE
ECHO.
ECHO  -------------------- Data Capture -------------------
ECHO  Case: %CASE%
ECHO.
ECHO    1 - Full Image Capture
ECHO    2 - Capture Event Viewer Logs
ECHO    3 - Capture Registry
ECHO    4 - Capture All Web Browser Cache
ECHO    5 - Capture Prefetch
ECHO    6 - Capture Master File Table (MFT)
ECHO    7 - Copy iOS Backups
ECHO    Q - Return to Forensic Workstation Menu
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO FULLCAP
IF /I '%IN%'=='2' GOTO EVENTVWR
IF /I '%IN%'=='3' GOTO REGISTRY
IF /I '%IN%'=='4' GOTO BROWSERS
IF /I '%IN%'=='5' GOTO PREFETCH
IF /I '%IN%'=='6' GOTO MFT
IF /I '%IN%'=='7' GOTO iOS
IF /I '%IN%'=='8' GOTO THUNDERBIRD
IF /I '%IN%'=='9' GOTO OUTLOOK
IF /I '%IN%'=='Q' GOTO FMENU

    :FULLCAP
    SET IN=%~dp0ftkimager\ftkimager \\.\PHYSICALDRIVE1 %~dp0\%CASE% --e01
    SET FN=drive_image
    CALL :EXECOMMAND
    GOTO DATACAP

    :EVENTVWR
	SET IN=psloglist.exe /accepteula -s -x Security
    SET FN=security
    CALL :EXECOMMAND
    
	SET IN=psloglist.exe /accepteula -s -x Application
    SET FN=application
    CALL :EXECOMMAND
    
	SET IN=psloglist.exe /accepteula -s -x System
    SET FN=system
    CALL :EXECOMMAND
    GOTO DATACAP
	
    :REGISTRY
    SET IN=regedit /e registry.reg
    SET FN=registry
    CALL :EXECOMMAND
	GOTO DATACAP
	
    :BROWSERS
    SET IN=7za.exe a -tzip chrome.zip "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\"
    SET FN=chrome.zip
    CALL :EXECOMMAND
    GOTO DATACAP
	
    :PREFETCH
    SET IN=robocopy C:\Windows\Prefetch\*.pf %~dp0findings\
    SET FN=Prefetch
    CALL :EXECOMMAND
    GOTO DATACAP

    :MFT
    SET IN=hmft -d
    SET FN=mft.dat
    CALL :EXECOMMAND
	
	SET IN=hmft -l
    SET FN=mft_listing.dat
    CALL :EXECOMMAND
	GOTO DATACAP
	
    :iOS
    SET IN=robocopy "%appdata%\Apple Computer\MobileSync\Backup"
    SET FN=iOS
    CALL :EXECOMMAND
    GOTO DATACAP
	
	:THUNDERBIRD
    SET IN=robocopy %appdata%\Thunderbird\Profiles\*
    SET FN=Thunderbird
    CALL :EXECOMMAND
    GOTO DATACAP
	
	:OUTLOOK
    SET IN=robocopy %LOCALAPPDATA%\Local\Microsoft\Outlook\*
    SET FN=Outlook
    CALL :EXECOMMAND

    SET IN=robocopy %userprofile%\Documents\Outlook Files\*
    SET FN=Outlook2010
    CALL :EXECOMMAND	
	
    GOTO DATACAP
   

:MISC
CLS
CALL :TITLE
ECHO.
ECHO  --------------------- MISC MENU --------------------
ECHO  Case: %CASE%
ECHO.
ECHO    1 - Capture Individual Command
ECHO    2 - Console Output
ECHO    3 - NSRL
ECHO    Q - Return to Forensic Workstation Menu
ECHO.
SET /P IN= Type a number and then press ENTER:
IF /I '%IN%'=='1' GOTO INDCOMMAND
IF /I '%IN%'=='2' GOTO CONSOLE
IF /I '%IN%'=='3' GOTO NSRL
IF /I '%IN%'=='Q' GOTO FMENU


    :INDCOMMAND
    SET /P IN="Command:"
    SET /P FN="Output FileName:"
    CALL :EXECOMMAND
    GOTO MISC


    :CONSOLE
    CLS
    ECHO.
    ECHO Type "Q" to return to menu
    SET /P IN="Command:"
    IF /I '%IN%'=='Q' GOTO MISC
    ECHO %IN% | ncat --send-only %IP% 4441
    ncat -l -p 4440 > con
    SET /P OUT= < con
    ECHO %OUT%
    GOTO CONSOLE

    :NSRL
    REM add code for nsrl here
	ECHO Create a suspicious.txt file first!
	nsrllookup -s nsrl.kyr.us < suspicious.txt
    GOTO MISC













:IINIT
CLS
ECHO.
ECHO Run this script as "Administrator" if possible from this incident workstation
ECHO.
Pause
CLS
SET /P IP="FORENSIC Machine IP Address:"

:IMENU
CLS
CALL :TITLE
ECHO.
ECHO    .... LISTENING MODE ....
ECHO.
ncat -v -l -p 4441 > tmpFile
SET /P IN= < tmpFile
del tmpFile


GOTO THREE

    IF /I '%IN%'=='1' GOTO ONE
    IF /I '%IN%'=='2' GOTO TWO


    :ONE
    ECHO.
    ECHO %IN%
    ECHO.
    CALL :WAIT
    GOTO IMENU

    :TWO
    ECHO.
    ECHO %IN%
    ECHO.
    CALL :WAIT
    GOTO IMENU
    REM #### END ####


    :THREE
    ECHO.
    ECHO %IN%
    CALL :WAIT
    %IN% | ncat --send-only %IP% 4440
    GOTO IMENU









REM ## SHARED Sub Routines ##

:EXECOMMAND
ECHO %IN% | ncat --send-only %IP% 4441

date /t > findings/%CASE%_%FN%.txt
time /t >> findings/%CASE%_%FN%.txt
ncat -v -l -p 4440 >> findings/%CASE%_%FN%.txt

md5deep -b -s -z findings/%CASE%_%FN%.txt >> findings/%CASE%.txt
GOTO:EOF

REM - non txt files

:EXECOMMAND2
ECHO %IN% | ncat --send-only %IP% 4441

ncat -v -l -p 4440 >> findings/%CASE%_%FN%

md5deep -b -s -z findings/%CASE%_%FN%.zip >> findings/%CASE%.txt
GOTO:EOF


:WAIT
ECHO waiting...
REM Does 6 pings before returning. About 5 seconds wait
PING 127.0.0.1 -n 1 >nul
GOTO:EOF

:TITLE
ECHO _____________________________________________________
ECHO                    Ars Forensica
ECHO _____________________________________________________
GOTO:EOF

:ASCIIART
ECHO. 
ECHO                 MMMMMMMMM
ECHO              MMM         MMMM            
ECHO           MM                 MM          
ECHO          M                     M         
ECHO         M                       M        
ECHO        M  M                    M M       
ECHO         M M                   M  M       
ECHO         M M     MM     MMM    M M        
ECHO          MM MMMMMMM   MMMMMMM MM         
ECHO           M MMMMMM     MMMMMM M          
ECHO   MM M    M  MMMM       MMMM  M    M MM  
ECHO   M   M   M        M M        M   M   M  
ECHO  M      MM M      MM MM      MMMM      M 
ECHO  MMMMM     MMMMM  MM MM   MMMM     MMMMM 
ECHO        MMM   MMM         MMM   MMM       
ECHO            MMM    MMMMM    MMM           
ECHO              M   MMMM MM   M             
ECHO           MM M  MM MM   M  M MM          
ECHO    MMMMMM     M           M     MMMMMM   
ECHO    MM      MM  MM       MM  MM       M   
ECHO      M  MM        MMMMM        MM  M     
ECHO      M MM                        M M     
ECHO       M                           M         
ECHO. 
GOTO:EOF

:Quit
CLS
ECHO.
ECHO  ====== PRESS ANY KEY TO EXIT ======
ECHO. 
PAUSE>NUL
EXIT