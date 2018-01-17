@echo on
rem PC rename
wmic computersystem where caption=‘Текущее Имя ПК’ rename Новое Имя ПК
rem User rename
wmic useraccount where name=‘Текущее имя' rename Новое имя
rem Windows PID change
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \v ProductId \t REG_SZ \d Новый WPID
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \v DigitalProductId \t REG_BINARY \d Новый WPID
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \v DigitalProductId64 \t REG_BINARY \d Новый WPID
rem InternetExplorer PID change
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration" \v ProductId \t REG_SZ \d
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration" \v DigitalProductId \t REG_BINARY \d Новый WPID
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration" \v DigitalProductId64 \t REG_BINARY \d Новый WPID
rem Install data change
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \v InstallDate \t REG_DWORD \d Новая дата \f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Migration" \v Ie Installed Date \t REG_BINARY \d Новая дата установки \f
rem Version number change
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \v CurrentBuild \t REG_SZ \d Новый BuildID
rem SID\WSUS\PC GUID\Network Adapter GUID\DTC\DHCPv6 (CHANGE PATH TO SOFTWARE SIDCHG http:\\www.stratesave.com\html\sidchg.html)
C:\Folder\sidchg64 \F \R
rem VolumeID change (CHANGE PATH TO SOFTWARE volmeid https:\\technet.microsoft.com\ru-ru\sysinternals\bb897436.aspx)
C:\Folder\volumeidx64 C: xxxx-yyy
rem MAC address change (CHANGE PATH TO SOFTWARE TMac https:\\technitium.com\tmac\)
"C:\Program Files (x86)\Technitium\TMACv6.0\TMAC.exe" -n "Ethernet" -r -re

pause
