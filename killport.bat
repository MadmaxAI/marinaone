@echo off
echo Killing processes on port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000 "') do (
    echo Killing PID %%a
    taskkill /F /PID %%a 2>nul
)
taskkill /F /IM node.exe /T 2>nul
echo Done.
