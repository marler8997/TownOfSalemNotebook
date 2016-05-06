@echo off

REM Download WinPcap Developer Pack
set WPD=D:\WpdPack

set CC_OPT=/DWIN32
set CC_OPT=%CC_OPT% /I %WPD%\Include

set LIBS=ws2_32.lib %WPD%\Lib\wpcap.lib

cl %CC_OPT% %LIBS% TownOfSalemSniffer.c
