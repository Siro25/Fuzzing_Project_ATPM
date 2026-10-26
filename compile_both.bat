@echo off
REM Script compile cả 2 phiên bản để test

echo.
echo ============================================================
echo   COMPILE NETWORK PARSER - BOTH VERSIONS
echo ============================================================
echo.

REM Check if gcc is available
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] gcc not found! Please install MinGW or MSYS2
    exit /b 1
)

REM Compile v0 (vulnerable)
echo [1/2] Compiling v0 (vulnerable version)...
gcc -g -O0 -Wall -o parser_v0.exe network_parser_v0.c
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile v0
    exit /b 1
)
echo [OK] parser_v0.exe created

echo.
REM Compile v1 (fixed)
echo [2/2] Compiling v1 (fixed version)...
gcc -g -O0 -Wall -o parser_v1.exe network_parser_v1.c
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile v1
    exit /b 1
)
echo [OK] parser_v1.exe created

echo.
echo ============================================================
echo   COMPILATION SUCCESSFUL
echo ============================================================
echo.
echo Test với demo mode:
echo   parser_v0.exe
echo   parser_v1.exe
echo.
echo Test với crash case:
echo   parser_v0.exe ch4_dynafuzz\logs\dynamic_loop_crash\run_20261020_001653_183598\r03_i0173_hang.bin
echo   parser_v1.exe ch4_dynafuzz\logs\dynamic_loop_crash\run_20261020_001653_183598\r03_i0173_hang.bin
echo.

pause
