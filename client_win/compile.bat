@ECHO OFF

rem set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
rem set LIB=%LIB%;C:\Program Files\OpenSSL\lib
rem set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.c /link /OUT:client.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

del *.obj

