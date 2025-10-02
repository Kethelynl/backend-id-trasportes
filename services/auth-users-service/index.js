const express = require('express');
const pool = require('../../shared/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

// Debug: verificar se JWT_SECRET está carregado
console.log('🔍 Debug - JWT_SECRET:', process.env.JWT_SECRET ? 'DEFINIDO' : 'NÃO DEFINIDO');
if (process.env.JWT_SECRET) {
  console.log('🔍 Debug - JWT_SECRET (primeiros 10 chars):', process.env.JWT_SECRET.substring(0, 10) + '...');
}
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Auth/Users',
    version: '1.0.0',
    description: 'Documentação da API de autenticação e usuários'
  }
};
const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:8080', credentials: true }));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login de usuário
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token JWT
 */
// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password, company_domain } = req.body;
  try {
    // Se fornecido company_domain, buscar empresa primeiro
    let companyId = null;
    if (company_domain) {
      const [companyRows] = await pool.query('SELECT id FROM companies WHERE domain = ? AND is_active = 1', [company_domain]);
      if (companyRows.length === 0) {
        return res.status(401).json({ error: 'Empresa não encontrada ou inativa' });
      }
      companyId = companyRows[0].id;
    }

    // Buscar usuário com ou sem filtro de empresa
    let query = 'SELECT u.*, c.name as company_name, c.domain as company_domain FROM users u LEFT JOIN companies c ON u.company_id = c.id WHERE u.username = ?';
    let params = [username];
    
    if (companyId) {
      query += ' AND u.company_id = ?';
      params.push(companyId);
    }
    
    const [rows] = await pool.query(query, params);
    const user = rows[0];
    
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
    if (!user.is_active) return res.status(401).json({ error: 'Usuário inativo' });
    
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Senha inválida' });
    
    // Atualizar último login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
    
    // Debug: verificar JWT_SECRET antes de gerar token
    console.log('🔍 Debug - Gerando token para usuário:', user.username);
    console.log('🔍 Debug - JWT_SECRET disponível:', !!process.env.JWT_SECRET);
    
    const token = jwt.sign({ 
      id: user.id, 
      user_type: user.user_type, 
      company_id: user.company_id 
    }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    // Montar objeto user sem o hash da senha
    const userResponse = {
      id: user.id,
      username: user.username,
      name: user.full_name,
      email: user.email,
      role: user.user_type,
      company_id: user.company_id,
      company_name: user.company_name,
      company_domain: user.company_domain,
      is_active: user.is_active,
      last_login: user.last_login,
      created_at: user.created_at,
      updated_at: user.updated_at
    };
    res.json({ user: userResponse, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware de autenticação e autorização
function authorize(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
    const token = auth.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(decoded.user_type)) {
        return res.status(403).json({ error: 'Acesso negado' });
      }
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token inválido' });
    }
  };
}

// Middleware para verificar acesso à empresa (exceto para MASTER)
function checkCompanyAccess() {
  return (req, res, next) => {
    if (req.user.user_type === 'MASTER') {
      return next();
    }
    
    const companyId = req.params.company_id || req.body.company_id;
    if (companyId && req.user.company_id != companyId) {
      return res.status(403).json({ error: 'Acesso negado a esta empresa' });
    }
    
    next();
  };
}

// Recuperação de senha (simulado)
app.post('/api/auth/forgot-password', async (req, res) => {
  const { username } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    // Aqui você geraria um token e enviaria por e-mail
    // Exemplo: const token = crypto.randomBytes(20).toString('hex');
    res.json({ message: 'Instruções de recuperação enviadas (simulado)' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Listar usuários (apenas ADMIN e MASTER)
app.get('/api/users', authorize(['ADMIN', 'MASTER']), async (req, res) => {
  try {
    let query = `
      SELECT u.id, u.username, u.email, u.full_name, u.user_type, u.is_active, 
             u.last_login, u.created_at, u.updated_at, c.name as company_name
      FROM users u
      LEFT JOIN companies c ON u.company_id = c.id
    `;
    let params = [];
    
    // Se não for MASTER, filtrar apenas usuários da empresa
    if (req.user.user_type !== 'MASTER') {
      query += ' WHERE u.company_id = ?';
      params.push(req.user.company_id);
    }
    
    query += ' ORDER BY u.created_at DESC';
    
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cadastro de usuário (apenas ADMIN e MASTER)
app.post('/api/users', authorize(['ADMIN', 'MASTER']), async (req, res) => {
  const { username, password, email, full_name, user_type, company_id } = req.body;
  
  // Determinar company_id
  let targetCompanyId = company_id;
  if (req.user.user_type !== 'MASTER') {
    targetCompanyId = req.user.company_id;
  }
  
  if (!targetCompanyId) {
    return res.status(400).json({ error: 'Company ID é obrigatório' });
  }
  
  // Validação de senha forte
  if (!password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'A senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula e número.' });
  }
  
  // Validação de username único por empresa
  const [exists] = await pool.query('SELECT id FROM users WHERE username = ? AND company_id = ?', [username, targetCompanyId]);
  if (exists.length > 0) return res.status(400).json({ error: 'Username já cadastrado nesta empresa' });
  
  const hash = await bcrypt.hash(password, 10);
  try {
    await pool.query(
      'INSERT INTO users (company_id, username, password_hash, email, full_name, user_type) VALUES (?, ?, ?, ?, ?, ?)',
      [targetCompanyId, username, hash, email, full_name, user_type]
    );
    res.status(201).json({ message: 'Usuário criado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Troca de senha
app.put('/api/users/:id/password', authorize(), async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula e número.' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    const user = rows[0];
    const valid = await bcrypt.compare(oldPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Senha atual incorreta' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, req.params.id]);
    res.json({ message: 'Senha alterada com sucesso' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Detalhes de usuário
app.get('/api/users/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar usuário
app.put('/api/users/:id', async (req, res) => {
  const { email, full_name, user_type, is_active } = req.body;
  try {
    await pool.query(
      'UPDATE users SET email=?, full_name=?, user_type=?, is_active=? WHERE id=?',
      [email, full_name, user_type, is_active, req.params.id]
    );
    res.json({ message: 'Usuário atualizado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Desativar/excluir usuário
app.delete('/api/users/:id', async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_active=0 WHERE id=?', [req.params.id]);
    res.json({ message: 'Usuário desativado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

if (require.main === module) {
  app.listen(3001, () => console.log('Auth/Users Service rodando na porta 3001'));
}
module.exports = app; 
