@echo off
REM Configurar o caminho do MariaDB
set MARIADB_PATH=C:\Users\Luis\Documents\GitHub\sistema_lab_campus_salinas\src\mariadb-10.4.11-winx64

REM Configurar o caminho do Node.js e nodemon
set NODE_MODULES_PATH=C:\Users\Luis\Documents\GitHub\sistema_lab_campus_salinas\node_modules\.bin

REM Adicionar caminhos ao PATH
set PATH=%PATH%;%MARIADB_PATH%\bin
set PATH=%PATH%;%NODE_PATH%
set PATH=%PATH%;%NODE_MODULES_PATH%

REM Mudar para o diretório do projeto
cd /d C:\Users\Luis\Documents\GitHub\sistema_lab_campus_salinas\src

REM Iniciar o MariaDB
echo Iniciando MariaDB...
start "" "%MARIADB_PATH%\bin\mysqld" --skip-grant-tables

REM Esperar alguns segundos para garantir que o MariaDB inicie
timeout /t 5

REM Iniciar o servidor Node.js com nodemon
echo Iniciando o servidor Node.js...
start "" nodemon app.js

REM Abrir o navegador com a URL
echo Abrindo o navegador...
start http://localhost:3002

echo O MariaDB e o Node.js estão rodando. Mude para C:\Users\Luis\Documents\GitHub\sistema_lab_campus_salinas e o MariaDB está em src.
