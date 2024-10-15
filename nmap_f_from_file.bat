@echo off
setlocal enabledelayedexpansion

REM Ensure exactly two arguments (the file with IP addresses and the output directory) are provided
if "%~1"=="" (
  echo Usage: %~nx0 ^<ips_file^> ^<output_directory^>
  exit /b 1
)

if "%~2"=="" (
  echo Usage: %~nx0 ^<ips_file^> ^<output_directory^>
  exit /b 1
)

REM Input file containing the list of IP addresses
set "IPS_FILE=%~1"

REM Output directory to store results
set "OUTPUT_DIR=%~2"

REM Check if the file exists
if not exist "%IPS_FILE%" (
  echo File not found: %IPS_FILE%
  exit /b 1
)

REM Check if the directory exists, if not create it
if not exist "%OUTPUT_DIR%" (
  echo Output directory not found, creating: %OUTPUT_DIR%
  mkdir "%OUTPUT_DIR%"
)

REM Derive the output file name by appending "_results.txt" to the input file name without extension
for %%f in ("%IPS_FILE%") do set "OUTPUT_FILE=%OUTPUT_DIR%\%%~nf_results"

REM Empty the output file if it exists
break > "%OUTPUT_FILE%"

REM Count the total number of valid IP addresses (non-empty, non-comment lines)
set /a TOTAL_COUNT=0
for /f "usebackq tokens=*" %%a in ("%IPS_FILE%") do (
  set "line=%%a"
  REM Skip empty lines and lines starting with #
  if not "!line!"=="" if not "!line:~0,1!"=="#" (
    set /a TOTAL_COUNT+=1
  )
)

REM Initialize the current count
set /a CURRENT_COUNT=0

REM Loop through each IP address in the file
for /f "usebackq tokens=*" %%a in ("%IPS_FILE%") do (
  set "ip=%%a"

  REM Remove leading and trailing whitespace
  for /f "tokens=* delims= " %%b in ("!ip!") do set "ip=%%b"

  REM Skip empty lines and lines starting with #
  if not "!ip!"=="" if not "!ip:~0,1!"=="#" (
    REM Increment the current count
    set /a CURRENT_COUNT+=1

    REM Display progress
    echo Progress: !CURRENT_COUNT!/!TOTAL_COUNT!
    echo Scanning !ip!...

    REM Run nmap with -F option (make sure nmap is in your system PATH)
    echo Results from: !ip! >> "%OUTPUT_FILE%"
    nmap -F !ip! | findstr /R /C:"open" >> "%OUTPUT_FILE%"

    REM Check if nmap found any open ports
    if errorlevel 1 (
      echo Error scanning !ip! -Most likely no open ports were detected-
    )

    REM Optional: Add a separator for clarity
    echo --------------------------------- >> "%OUTPUT_FILE%"
  )
)

echo Scanning complete. Results saved to %OUTPUT_FILE%.
