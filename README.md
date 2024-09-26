# Sistema de Inventário de produtos quimicos fiscalizados pela PF para o IFNMG Salinas

Este é um sistema de inventário que permite gerenciar e registrar consumos de produtos. O sistema inclui uma interface web e funcionalidades para gerar relatórios em PDF.

## Pré-requisitos

Certifique-se de que você tem as seguintes ferramentas instaladas:
- [Node.js](https://nodejs.org/) (v14 ou superior)
- [MySQL](https://www.mysql.com/) (ou MariaDB)

## Instalando

1. **Clonar o Repositório**

   Clone o repositório para a sua máquina local:

   ```bash
   git clone https://github.com/seu-usuario/sistema-inventario.git
   cd sistema-inventario
   
2. **Instalar Dependências**

Instale as dependências do projeto com o npm:
   npm install

3. **Configurar o Banco de Dados MySQL**

Certifique-se de que o MySQL está rodando em sua máquina local.

4. **Configuração do .env**

   Crie um arquivo .env na raiz do projeto e adicione as variáveis de ambiente conforme abaixo. Esse arquivo será usado para configurar a conexão com o banco de dados MySQL:
   ```bash
   PORT=3001
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=root
   DB_PASSWORD=sua_senha
   DB_NAME=nome_do_banco
