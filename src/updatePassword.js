import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config({ path: 'D:/mariadb-10.4.11-winx64/variaveis.env' });

async function updatePassword() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  const saltRounds = 10;
  const plainPassword = '12345678'; // A senha que você deseja hash
  const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);

  // Atualizar a senha no banco de dados
  const [result] = await connection.execute('UPDATE usuario SET senha = ? WHERE email = ?', [hashedPassword, 'admin@sistema.com']);

  console.log('Número de registros atualizados:', result.affectedRows);
  await connection.end();
}

updatePassword().catch(err => console.error(err));
