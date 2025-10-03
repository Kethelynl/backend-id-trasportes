const express = require('express');
const pool = require('../../shared/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();
// Debug: verificar se JWT_SECRET estÃ¡ carregado
console.log('ðŸ” Debug - JWT_SECRET:', process.env.JWT_SECRET ? 'DEFINIDO' : 'NÃƒO DEFINIDO');
if (process.env.JWT_SECRET) {
  console.log('ðŸ” Debug - JWT_SECRET (primeiros 10 chars):', process.env.JWT_SECRET.substring(0, 10) + '...');
}
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');
const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Auth/Users',
    version: '1.0.0',
    description: 'DocumentaÃ§Ã£o da API de autenticaÃ§Ã£o e usuÃ¡rios'
  }
};
const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);
const app = express();
async function ensureUserTableColumns() {
  try {
    const [cpfColumn] = await pool.query("SHOW COLUMNS FROM users LIKE 'cpf'");
    if (!cpfColumn.length) {
      await pool.query("ALTER TABLE users ADD COLUMN cpf VARCHAR(14) NULL AFTER full_name");
      console.log('ðŸ› ï¸ Coluna cpf adicionada Ã  tabela users');
    }
    const [statusColumn] = await pool.query("SHOW COLUMNS FROM users LIKE 'status'");
    if (!statusColumn.length) {
      await pool.query("ALTER TABLE users ADD COLUMN status ENUM('ATIVO','INATIVO') NOT NULL DEFAULT 'ATIVO' AFTER user_type");
      await pool.query("UPDATE users SET status = CASE WHEN is_active = 1 THEN 'ATIVO' ELSE 'INATIVO' END");
      console.log('ðŸ› ï¸ Coluna status adicionada Ã  tabela users');
    }
  } catch (error) {
    console.error('Erro ao garantir colunas da tabela users:', error);
    throw error;
  }
}
const ensureUserColumnsPromise = ensureUserTableColumns().catch((error) => {
  console.error('Falha ao preparar colunas da tabela users:', error);
  throw error;
});
app.use(express.json());

const allowedOrigins = [
  'http://localhost:8080', 
  'http://localhost:5173', // Adicionando porta do Vite para desenvolvimento
  'https://frontend-id-transportes-6ruh7wk5m.vercel.app' // Adicionando URL de produção do frontend
];
app.use(cors({ 
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }, 
  credentials: true 
}));

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login de usuÃ¡rio
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
        return res.status(401).json({ error: 'Empresa nÃ£o encontrada ou inativa' });
      }
      companyId = companyRows[0].id;
    }
    // Buscar usuÃ¡rio com ou sem filtro de empresa
    let query = 'SELECT u.*, c.name as company_name, c.domain as company_domain FROM users u LEFT JOIN companies c ON u.company_id = c.id WHERE u.username = ?';
    let params = [username];
    if (companyId) {
      query += ' AND u.company_id = ?';
      params.push(companyId);
    }
    const [rows] = await pool.query(query, params);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
    if (!user.is_active) return res.status(401).json({ error: 'UsuÃ¡rio inativo' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Senha invÃ¡lida' });
    // Atualizar Ãºltimo login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
    // Debug: verificar JWT_SECRET antes de gerar token
    console.log('ðŸ” Debug - Gerando token para usuÃ¡rio:', user.username);
    console.log('ðŸ” Debug - JWT_SECRET disponÃ­vel:', !!process.env.JWT_SECRET);
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
// Middleware de autenticaÃ§Ã£o e autorizaÃ§Ã£o
function authorize(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token nÃ£o fornecido' });
    const token = auth.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(decoded.user_type)) {
        return res.status(403).json({ error: 'Acesso negado' });
      }
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token invÃ¡lido' });
    }
  };
}
// Middleware para verificar acesso Ã  empresa (exceto para MASTER)
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
// RecuperaÃ§Ã£o de senha (simulado)
app.post('/api/auth/forgot-password', async (req, res) => {
  const { username } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(404).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
    // Aqui vocÃª geraria um token e enviaria por e-mail
    // Exemplo: const token = crypto.randomBytes(20).toString('hex');
    res.json({ message: 'InstruÃ§Ãµes de recuperaÃ§Ã£o enviadas (simulado)' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Listar usuÃ¡rios (apenas ADMIN e MASTER)
app.get('/api/users', authorize(['ADMIN', 'MASTER']), async (req, res) => {
  try {
    let query = `
      SELECT u.id, u.username, u.email, u.full_name, u.user_type, u.is_active,
             u.cpf, u.company_id, COALESCE(u.status, CASE WHEN u.is_active = 1 THEN 'ATIVO' ELSE 'INATIVO' END) AS status,
             u.last_login, u.created_at, u.updated_at, c.name as company_name
      FROM users u
      LEFT JOIN companies c ON u.company_id = c.id
    `;
    let params = [];
    let whereConditions = [];
    // Se nÃ£o for MASTER, filtrar apenas usuÃ¡rios da empresa
    if (req.user.user_type !== 'MASTER') {
      whereConditions.push('u.company_id = ?');
      params.push(req.user.company_id);
    }
    // ðŸ”’ PROTEÃ‡ÃƒO: Ocultar usuÃ¡rio master para usuÃ¡rios nÃ£o-master
    // Apenas usuÃ¡rios MASTER podem ver outros usuÃ¡rios MASTER
    if (req.user.user_type !== 'MASTER') {
      whereConditions.push("u.user_type != 'MASTER'");
    }
    // Adicionar condiÃ§Ãµes WHERE se existirem
    if (whereConditions.length > 0) {
      query += ' WHERE ' + whereConditions.join(' AND ');
    }
    query += ' ORDER BY u.created_at DESC';
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Cadastro de usuario (ADMIN/MASTER/SUPERVISOR)
app.post('/api/users', authorize(['ADMIN', 'MASTER', 'SUPERVISOR']), async (req, res) => {
  const { username, password, email, full_name, user_type, company_id, cpf, status } = req.body;
  const allowedUserTypes = {
    'MASTER': ['ADMIN', 'SUPERVISOR', 'OPERATOR', 'DRIVER', 'CLIENT'],
    'ADMIN': ['SUPERVISOR', 'OPERATOR', 'DRIVER', 'CLIENT'],
    'SUPERVISOR': ['OPERATOR', 'DRIVER']
  };
  const userAllowedTypes = allowedUserTypes[req.user.user_type] || [];
  if (!userAllowedTypes.includes(user_type)) {
    return res.status(403).json({
      success: false,
      error: `Voce nao tem permissao para criar usuarios do tipo ${user_type}. Tipos permitidos: ${userAllowedTypes.join(', ')}`
    });
  }
  let targetCompanyId = company_id;
  if (req.user.user_type !== 'MASTER') {
    targetCompanyId = req.user.company_id;
  }
  if (!targetCompanyId) {
    return res.status(400).json({ success: false, error: 'Company ID e obrigatorio' });
  }
  if (!password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ success: false, error: 'A senha deve ter pelo menos 8 caracteres, incluindo maiuscula, minuscula e numero.' });
  }
  const normalizedStatus = typeof status === 'string' && status.trim().toUpperCase() === 'INATIVO' ? 'INATIVO' : 'ATIVO';
  const isActiveFlag = normalizedStatus === 'ATIVO';
  const sanitizedCpfDigits = cpf ? cpf.toString().replace(/\D/g, '').slice(0, 14) : '';
  const sanitizedCpf = sanitizedCpfDigits ? sanitizedCpfDigits : null;
  try {
    const [exists] = await pool.query('SELECT id FROM users WHERE username = ? AND company_id = ?', [username, targetCompanyId]);
    if (exists.length > 0) {
      return res.status(400).json({ success: false, error: 'Username ja cadastrado nesta empresa' });
    }
    if (sanitizedCpf) {
      const [cpfConflict] = await pool.query('SELECT id FROM users WHERE cpf = ? AND company_id = ?', [sanitizedCpf, targetCompanyId]);
      if (cpfConflict.length > 0) {
        return res.status(400).json({ success: false, error: 'CPF ja cadastrado para outro usuario desta empresa' });
      }
    }
    const hash = await bcrypt.hash(password, 10);
    const [insertResult] = await pool.query(
      'INSERT INTO users (company_id, username, password_hash, email, full_name, user_type, cpf, status, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [targetCompanyId, username, hash, email, full_name, user_type, sanitizedCpf, normalizedStatus, isActiveFlag]
    );
    const newUserId = insertResult.insertId;
    const [createdRows] = await pool.query(
      'SELECT id, company_id, username, email, full_name, user_type, cpf, status, is_active, created_at, updated_at FROM users WHERE id = ? LIMIT 1',
      [newUserId]
    );
    const createdUser = createdRows[0] || null;
    res.status(201).json({
      success: true,
      message: 'Usuario criado',
      data: createdUser ? createdUser : { id: newUserId }
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Cadastro combinado de usuario e motorista (SUPERVISOR pode criar motoristas)
app.post('/api/users/driver', authorize(['ADMIN', 'MASTER', 'SUPERVISOR']), async (req, res) => {
  const {
    username,
    password,
    email,
    full_name,
    cpf,
    phone,
    cnh,
    company_id: requestCompanyId,
    tech_knowledge,
    is_outsourced,
    status
  } = req.body || {};
  const normalizedUsername = typeof username === 'string' ? username.trim() : '';
  const normalizedFullName = typeof full_name === 'string' ? full_name.trim() : '';
  const normalizedEmail = typeof email === 'string' ? email.trim() : '';
  const normalizedStatus = typeof status === 'string' && status.trim().toUpperCase() === 'INATIVO' ? 'INATIVO' : 'ATIVO';
  if (!normalizedUsername || !password || !normalizedEmail || !normalizedFullName || !cpf) {
    return res.status(400).json({ success: false, error: 'Campos obrigatorios ausentes para criar o motorista' });
  }
  if (!password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ success: false, error: 'A senha deve ter pelo menos 8 caracteres, incluindo maiuscula, minuscula e numero.' });
  }
  let targetCompanyId = req.user.company_id;
  if (req.user.user_type === 'MASTER' && requestCompanyId) {
    targetCompanyId = requestCompanyId;
  }
  if (!targetCompanyId) {
    return res.status(400).json({ success: false, error: 'Company ID e obrigatorio' });
  }
  const companyIdNumber = Number(targetCompanyId);
  if (!Number.isFinite(companyIdNumber)) {
    return res.status(400).json({ success: false, error: 'Company ID invalido' });
  }
  const sanitizedCpf = cpf ? cpf.toString().replace(/\D/g, '').slice(0, 14) : '';
  if (!sanitizedCpf) {
    return res.status(400).json({ success: false, error: 'CPF e obrigatorio' });
  }
  const sanitizedPhone = phone ? phone.toString().replace(/[^0-9+]/g, '').slice(0, 20) : null;
  const sanitizedCnh = cnh ? cnh.toString().replace(/\D/g, '').slice(0, 20) : null;
  const normalizedIsOutsourced = typeof is_outsourced === 'boolean' ? (is_outsourced ? 1 : 0) : 1;
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [usernameRows] = await connection.query(
      'SELECT id FROM users WHERE username = ? AND company_id = ? LIMIT 1',
      [normalizedUsername, companyIdNumber]
    );
    if (usernameRows.length > 0) {
      throw new Error('Username ja cadastrado nesta empresa');
    }
    const [cpfUsers] = await connection.query(
      'SELECT id FROM users WHERE cpf = ? AND company_id = ? LIMIT 1',
      [sanitizedCpf, companyIdNumber]
    );
    if (cpfUsers.length > 0) {
      throw new Error('CPF ja cadastrado para outro usuario desta empresa');
    }
    const [cpfDrivers] = await connection.query(
      'SELECT id FROM drivers WHERE cpf = ? AND company_id = ? LIMIT 1',
      [sanitizedCpf, companyIdNumber]
    );
    if (cpfDrivers.length > 0) {
      throw new Error('CPF ja cadastrado para outro motorista desta empresa');
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const [userResult] = await connection.query(
      'INSERT INTO users (company_id, username, password_hash, email, full_name, user_type, cpf, status, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [companyIdNumber, normalizedUsername, passwordHash, normalizedEmail, normalizedFullName, 'DRIVER', sanitizedCpf, normalizedStatus, normalizedStatus === 'ATIVO']
    );
    const newUserId = userResult.insertId;
    let driverInsertId = null;
    try {
      const [driverResult] = await connection.query(
        'INSERT INTO drivers (company_id, user_id, cpf, phone_number, license_number, tech_knowledge, is_outsourced, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
        [companyIdNumber, newUserId, sanitizedCpf, sanitizedPhone, sanitizedCnh, tech_knowledge || null, normalizedIsOutsourced, 'active']
      );
      driverInsertId = driverResult.insertId;
    } catch (driverError) {
      if (driverError && driverError.code === 'ER_BAD_FIELD_ERROR') {
        const [fallbackDriverResult] = await connection.query(
          'INSERT INTO drivers (company_id, user_id, cpf, phone_number, tech_knowledge, is_outsourced, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
          [companyIdNumber, newUserId, sanitizedCpf, sanitizedPhone, tech_knowledge || null, normalizedIsOutsourced, 'active']
        );
        driverInsertId = fallbackDriverResult.insertId;
      } else {
        throw driverError;
      }
    }
    await connection.commit();
    const responsePayload = {
      user: {
        id: newUserId,
        company_id: companyIdNumber,
        username: normalizedUsername,
        email: normalizedEmail,
        full_name: normalizedFullName,
        user_type: 'DRIVER',
        cpf: sanitizedCpf,
        status: normalizedStatus,
        is_active: normalizedStatus === 'ATIVO'
      },
      driver: {
        id: driverInsertId,
        user_id: newUserId,
        company_id: companyIdNumber,
        cpf: sanitizedCpf,
        phone_number: sanitizedPhone,
        status: 'active'
      }
    };
    if (sanitizedCnh) {
      responsePayload.driver.license_number = sanitizedCnh;
    }
    res.status(201).json({
      success: true,
      message: 'Motorista criado com sucesso',
      data: responsePayload
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error('Erro ao reverter criacao de motorista:', rollbackError);
      }
    }
    res.status(400).json({
      success: false,
      error: error.message || 'Erro ao cadastrar motorista'
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// Troca de senha
app.put('/api/users/:id/password', authorize(), async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'A nova senha deve ter pelo menos 8 caracteres, incluindo maiÃºscula, minÃºscula e nÃºmero.' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
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
// Detalhes de usuÃ¡rio
app.get('/api/users/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Atualizar usuÃ¡rio
app.put('/api/users/:id', authorize(['ADMIN', 'MASTER', 'SUPERVISOR']), async (req, res) => {
  const { email, full_name, user_type, is_active, cpf, status } = req.body;
  try {
    // ðŸ”’ PROTEÃ‡ÃƒO: Verificar se estÃ¡ tentando editar um usuÃ¡rio MASTER
    const [targetUser] = await pool.query('SELECT user_type, username, is_active, status FROM users WHERE id = ?', [req.params.id]);
    if (targetUser.length === 0) {
      return res.status(404).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
    }
    // Apenas usuÃ¡rios MASTER podem editar outros usuÃ¡rios MASTER
    if (targetUser[0].user_type === 'MASTER' && req.user.user_type !== 'MASTER') {
      return res.status(403).json({ 
        error: 'Acesso negado: Apenas usuÃ¡rios MASTER podem editar outros usuÃ¡rios MASTER',
        details: 'OperaÃ§Ã£o nÃ£o permitida por questÃµes de seguranÃ§a'
      });
    }
    // ðŸ”’ VALIDAÃ‡ÃƒO DE PERMISSÃ•ES: Verificar se o usuÃ¡rio pode alterar para o tipo solicitado
    if (user_type && user_type !== targetUser[0].user_type) {
      const allowedUserTypes = {
        'MASTER': ['ADMIN', 'SUPERVISOR', 'OPERATOR', 'DRIVER', 'CLIENT'], // Master pode alterar para qualquer tipo
        'ADMIN': ['SUPERVISOR', 'OPERATOR', 'DRIVER', 'CLIENT'], // Admin nÃ£o pode criar MASTER nem ADMIN
        'SUPERVISOR': ['OPERATOR', 'DRIVER'] // Supervisor sÃ³ pode alterar para OPERATOR e DRIVER
      };
      const userAllowedTypes = allowedUserTypes[req.user.user_type] || [];
      if (!userAllowedTypes.includes(user_type)) {
        return res.status(403).json({ 
          error: `VocÃª nÃ£o tem permissÃ£o para alterar usuÃ¡rios para o tipo ${user_type}. Tipos permitidos: ${userAllowedTypes.join(', ')}` 
        });
      }
    }
    // ðŸ”’ PROTEÃ‡ÃƒO: Impedir que usuÃ¡rios nÃ£o-MASTER alterem o tipo de usuÃ¡rio para MASTER
    if (user_type === 'MASTER' && req.user.user_type !== 'MASTER') {
      return res.status(403).json({ 
        error: 'Acesso negado: Apenas usuÃ¡rios MASTER podem criar outros usuÃ¡rios MASTER',
        details: 'NÃ£o Ã© possÃ­vel alterar o tipo de usuÃ¡rio para MASTER'
      });
    }
    const currentTarget = targetUser[0];
    const normalizedStatus = (() => {
      if (typeof status === 'string') {
        const upper = status.trim().toUpperCase();
        if (upper === 'ATIVO' || upper === 'INATIVO') {
          return upper;
        }
      }
      if (typeof is_active === 'boolean' || typeof is_active === 'number') {
        return is_active ? 'ATIVO' : 'INATIVO';
      }
      if (typeof is_active === 'string') {
        const normalized = is_active.trim().toUpperCase();
        if (normalized === 'ATIVO' || normalized === 'INATIVO') {
          return normalized;
        }
        if (normalized === '1' || normalized === 'TRUE') {
          return 'ATIVO';
        }
        if (normalized === '0' || normalized === 'FALSE') {
          return 'INATIVO';
        }
      }
      if (currentTarget.status) {
        const upper = currentTarget.status.toUpperCase();
        if (upper === 'ATIVO' || upper === 'INATIVO') {
          return upper;
        }
      }
      return currentTarget.is_active ? 'ATIVO' : 'INATIVO';
    })();
    const isActiveFlag = normalizedStatus === 'ATIVO';
    const sanitizedCpfDigits = cpf ? cpf.toString().replace(/\D/g, '').slice(0, 14) : '';
  const sanitizedCpf = sanitizedCpfDigits ? sanitizedCpfDigits : null;
    await pool.query(
      'UPDATE users SET email=?, full_name=?, user_type=?, cpf=?, status=?, is_active=? WHERE id=?',
      [email, full_name, user_type, sanitizedCpf, normalizedStatus, isActiveFlag, req.params.id]
    );
    res.json({ message: 'UsuÃ¡rio atualizado com sucesso' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
// Excluir usuÃ¡rio permanentemente
app.delete('/api/users/:id', authorize(['ADMIN', 'MASTER']), async (req, res) => {
  try {
    // ðŸ”’ PROTEÃ‡ÃƒO: Verificar se estÃ¡ tentando deletar um usuÃ¡rio MASTER
    const [targetUser] = await pool.query('SELECT user_type, username, is_active, status FROM users WHERE id = ?', [req.params.id]);
    if (targetUser.length === 0) {
      return res.status(404).json({ error: 'UsuÃ¡rio nÃ£o encontrado' });
    }
    // Apenas usuÃ¡rios MASTER podem deletar outros usuÃ¡rios MASTER
    if (targetUser[0].user_type === 'MASTER' && req.user.user_type !== 'MASTER') {
      return res.status(403).json({ 
        error: 'Acesso negado: Apenas usuÃ¡rios MASTER podem deletar outros usuÃ¡rios MASTER',
        details: `OperaÃ§Ã£o nÃ£o permitida para o usuÃ¡rio: ${targetUser[0].username}`
      });
    }
    // ðŸ”’ PROTEÃ‡ÃƒO ADICIONAL: Impedir auto-exclusÃ£o do Ãºltimo usuÃ¡rio MASTER
    if (targetUser[0].user_type === 'MASTER') {
      const [masterCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE user_type = "MASTER" AND is_active = 1');
      if (masterCount[0].count <= 1) {
        return res.status(403).json({ 
          error: 'OperaÃ§Ã£o nÃ£o permitida: NÃ£o Ã© possÃ­vel deletar o Ãºltimo usuÃ¡rio MASTER do sistema',
          details: 'Deve existir pelo menos um usuÃ¡rio MASTER ativo no sistema'
        });
      }
    }
    // Excluir permanentemente do banco de dados
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ message: 'UsuÃ¡rio excluÃ­do permanentemente do sistema' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
if (require.main === module) {
  ensureUserColumnsPromise
    .then(() => {
      app.listen(3001, () => console.log('Auth/Users Service rodando na porta 3001'));
    })
    .catch((err) => {
      console.error('Auth/Users Service nÃ£o pÃ´de iniciar devido a erro de preparaÃ§Ã£o do banco:', err);
      process.exit(1);
    });
}
module.exports = app;
