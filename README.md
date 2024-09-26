
# Sistema de Inventário de Produtos Químicos Fiscalizados pela PF para o IFNMG Salinas

<p align="center">
    <img src="https://qualitapps.com/wp-content/uploads/2023/02/102.png" width="120" height="80"/>
</p>



Este é um sistema de inventário que permite gerenciar e registrar consumos de produtos químicos. O sistema inclui uma interface web e funcionalidades para gerar relatórios em PDF.

## Pré-requisitos

Certifique-se de que você tem as seguintes ferramentas instaladas:

- Node.js (v14 ou superior)
- MySQL (ou MariaDB)

## Instalando

### Clonar o Repositório

Clone o repositório para a sua máquina local:

```bash
git clone https://github.com/seu-usuario/sistema-inventario.git
cd sistema-inventario
```

### Instalar Dependências

Instale as dependências do projeto com o npm:

```bash
npm install express path dotenv pdfkit fs express-session bcrypt

```

### Configurar o Banco de Dados MySQL

Certifique-se de que o MySQL está rodando em sua máquina local. Crie um banco de dados para o sistema.

## Configuração

1. **Configurar Variáveis de Ambiente:**
   Você precisa alterar a linha 11 do arquivo `app.js`, que contém:
   ```javascript
   dotenv.config({ path: 'seucaminho/variaveis.env' });
   ```
   Substitua `'seucaminho/variaveis.env'` pelo caminho correto onde seu arquivo `variaveis.env` está localizado.

2. **Configurar o Banco de Dados:**
   Certifique-se de que o MySQL está instalado e em execução. Crie um banco de dados e configure as tabelas conforme necessário.

```plaintext
PORT=3001
DB_HOST=localhost
DB_PORT=3306
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=seu_banco_de_dados
SESSION_SECRET=sua_chave_secreta
```
## Instruções para Importação de Dump do Banco de Dados
Salve este conteúdo em um arquivo `.sql` e execute com o MySQL:

```bash
mysql -u <usuario> -p < banco_dados_si_dump.sql
```

Substitua `<usuario>` pelo seu nome de usuário. Assim, você terá a estrutura das tabelas e o usuário admin configurado corretamente. Se precisar de mais ajustes, estou à disposição!

## Executando o Sistema

Para iniciar o servidor, execute o seguinte comando:

```bash
node server.js
```

O sistema estará acessível em `http://localhost:3001`.

## Funcionalidades do Sistema

### 1. Gerenciamento de Produtos
- **Adicionar Produtos:** Inclui novos produtos químicos ao inventário, com detalhes como sigla, concentração, densidade, nome completo, tipo de unidade (mililitros ou gramas) e NCM.
- **Editar Produtos:** Atualiza informações sobre produtos já cadastrados.
- **Remover Produtos:** Exclui produtos do inventário após confirmação do usuário.

### 2. Registro de Consumo
- **Registrar Consumo:** Permite o registro detalhado do consumo de produtos, incluindo a seleção do produto, quantidade, laboratório, data do consumo e descrição adicional.

### 3. Geração de Relatórios em PDF
- **Relatórios Detalhados:** Gera relatórios em PDF com informações sobre o inventário e consumos registrados.

## Sub-abas do Sistema

### 4. Inventário
- Exibe todos os produtos, mostrando o nome do produto, a quantidade disponível e informações adicionais.

### 5. Adicionar Produto
- O usuário preenche os campos necessários e clica em "Adicionar Estoque" para concluir o cadastro de novos produtos.

### 6. Excluir Produto
- O usuário seleciona um produto da lista e confirma a exclusão clicando em "Excluir Estoque".

### 7. Registrar Entrada
- O usuário registra a entrada de produtos ao selecionar o item, informar a quantidade, a data da entrada e uma descrição, clicando em "Registrar" para finalizar o processo.

## Acesso ao Sistema
- **Usuários do tipo "normal":** Têm acesso limitado, podendo usar apenas o inventário e as funcionalidades de registro.
- **Usuários do tipo "admin":** Têm acesso a opções administrativas adicionais para um maior controle do sistema.