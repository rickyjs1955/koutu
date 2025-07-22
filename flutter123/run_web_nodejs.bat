@echo off
echo.
echo 🚀 Running Koutu Animation with Node.js Server
echo =============================================
echo.

:: Get IP address
set IP=
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address" ^| findstr /v "127.0.0.1"') do (
    for /f "tokens=* delims= " %%b in ("%%a") do (
        set IP=%%b
        goto :found
    )
)
:found

echo Building web version...
call flutter build web

echo.
echo Starting Node.js server...
echo.
echo 💻 To view on THIS computer:
echo    http://localhost:8080
echo.
echo 📱 To view on your PHONE:
if defined IP (
    echo    http://%IP%:8080
) else (
    echo    http://[YOUR-IP]:8080
)
echo.
echo Press Ctrl+C to stop
echo.

:: Create a simple Node.js server
echo const http = require('http'); > server.js
echo const fs = require('fs'); >> server.js
echo const path = require('path'); >> server.js
echo. >> server.js
echo const server = http.createServer((req, res) =^> { >> server.js
echo   let filePath = path.join(__dirname, 'build', 'web', req.url === '/' ? 'index.html' : req.url); >> server.js
echo   const ext = path.extname(filePath); >> server.js
echo   const contentType = { >> server.js
echo     '.html': 'text/html', >> server.js
echo     '.js': 'text/javascript', >> server.js
echo     '.css': 'text/css', >> server.js
echo     '.json': 'application/json', >> server.js
echo     '.png': 'image/png', >> server.js
echo     '.jpg': 'image/jpg', >> server.js
echo     '.wasm': 'application/wasm' >> server.js
echo   }[ext] ^|^| 'text/plain'; >> server.js
echo. >> server.js
echo   fs.readFile(filePath, (err, content) =^> { >> server.js
echo     if (err) { >> server.js
echo       res.writeHead(404); >> server.js
echo       res.end('Not found'); >> server.js
echo     } else { >> server.js
echo       res.writeHead(200, { 'Content-Type': contentType }); >> server.js
echo       res.end(content); >> server.js
echo     } >> server.js
echo   }); >> server.js
echo }); >> server.js
echo. >> server.js
echo server.listen(8080, '0.0.0.0', () =^> { >> server.js
echo   console.log('Server running on http://localhost:8080'); >> server.js
echo }); >> server.js

node server.js