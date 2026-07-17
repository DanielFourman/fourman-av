@echo off
REM Build the scanner engine. Requires a C compiler (gcc/MinGW-w64 or clang).

where gcc >nul 2>nul
if %errorlevel%==0 (
    echo Building with gcc...
    gcc -O2 -Wall -o scanner.exe scanner.c
    goto done
)

where clang >nul 2>nul
if %errorlevel%==0 (
    echo Building with clang...
    clang -O2 -Wall -o scanner.exe scanner.c
    goto done
)

where cl >nul 2>nul
if %errorlevel%==0 (
    echo Building with MSVC cl...
    cl /O2 /Fe:scanner.exe scanner.c
    goto done
)

echo.
echo No C compiler found (gcc, clang, or MSVC cl).
echo Install one, e.g.:
echo     winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT
echo or MSYS2 / mingw-w64, then re-run build.bat.
exit /b 1

:done
if exist scanner.exe (
    echo.
    echo Built scanner.exe successfully.
) else (
    echo.
    echo Build failed.
    exit /b 1
)
