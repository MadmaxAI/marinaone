@echo off
netstat -ano | findstr :3000
echo ---
tasklist | findstr node
