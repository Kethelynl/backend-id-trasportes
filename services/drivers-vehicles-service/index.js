const express = require('express');
const pool = require('../../shared/db');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
const cors = require('cors');
const axios = require('axios'); // Adicionado para chamadas entre serviços

const jwtSecret = process.env.JWT_SECRET || 'fda76ff877a92f9a86e7831fad372e2d9e777419e155aab4f5b18b37d280d05a';

const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Drivers/Vehicles',
    version: '1.0.0',
    description: 'Documentação da API de motoristas e veículos'
  }
};
const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const allowedOrigins = [
  'http://localhost:8080', 
  'http://localhost:5173', 
  'https://frontend-id-transportes-6ruh7wk5m.vercel.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
};
app.use(cors(corsOptions));

/**
 * @swagger
 * /api/drivers:
 *   get:
 *     summary: Lista todos os motoristas
 *     responses:
 *       200:
 *         description: Lista de motoristas
 */
// Middleware de autenticação e autorização
function authorize(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
    const token = auth.split(' ')[1];
    try {
      const decoded = jwt.verify(token, jwtSecret);
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

// Cadastro de motorista (ADMIN/SUPERVISOR/MASTER)
app.post('/api/drivers', authorize(['ADMIN', 'SUPERVISOR', 'MASTER']), async (req, res) => {
  // Expande para receber dados de criação de usuário
  const { 
    user_id: existing_user_id, 
    cpf, 
    phone_number, 
    tech_knowledge, 
    is_outsourced, 
    company_id: companyIdBody, 
    companyId,
    // Novos campos para criação de usuário
    username,
    password,
    email,
    name, // O frontend envia 'name'
    full_name, // E também 'full_name'
    cnh
  } = req.body;

  let userIdToUse = existing_user_id;

  try {
    // Se não houver user_id, mas houver dados de usuário, cria um novo usuário
    if (!userIdToUse && username && password) {
      const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';
      const userPayload = {
        username,
        password,
        email,
        full_name: name || full_name,
        user_type: 'DRIVER',
        company_id: companyIdBody ?? companyId ?? req.user?.company_id,
        cpf,
        cnh
      };
      // CORREÇÃO: A rota para criar usuários no auth-service, conforme a documentação, é /api/auth/register.
      // O endpoint /api/users não existe para POST no auth-service.
      const userResponse = await axios.post(`${authServiceUrl}/api/auth/register`, userPayload);
      userIdToUse = userResponse.data.data.id; // A resposta do auth-service aninha os dados em `data`
    }

    if (!userIdToUse || !cpf) {
      return res.status(400).json({ error: 'user_id (ou dados de usuário) e cpf são obrigatórios' });
    }

    const requesterRole = req.user?.user_type;
    const requesterCompanyId = req.user?.company_id ?? null;
    const providedCompanyId = companyIdBody ?? companyId ?? null;

    let targetCompanyId = requesterCompanyId;
    if (requesterRole === 'MASTER' && providedCompanyId) {
      targetCompanyId = providedCompanyId;
    }

    if (!targetCompanyId) {
      return res.status(400).json({ error: 'company_id não informado' });
    }

    const companyIdNumber = Number(targetCompanyId);
    if (!Number.isFinite(companyIdNumber)) {
      return res.status(400).json({ error: 'company_id inválido' });
    }

    const [userRows] = await pool.query('SELECT id, company_id FROM users WHERE id = ? LIMIT 1', [userIdToUse]);
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const userCompanyId = userRows[0].company_id;
    if (requesterRole !== 'MASTER' && userCompanyId && Number(userCompanyId) !== companyIdNumber) {
      return res.status(403).json({ error: 'Usuário não pertence à empresa do solicitante' });
    }

    const [driverByUser] = await pool.query('SELECT id FROM drivers WHERE user_id = ?', [userIdToUse]);
    if (driverByUser.length > 0) {
      return res.status(400).json({ error: 'Usuário já possui motorista cadastrado' });
    }

    const [driverByCpf] = await pool.query('SELECT id FROM drivers WHERE cpf = ?', [cpf]);
    if (driverByCpf.length > 0) {
      return res.status(400).json({ error: 'CPF já cadastrado' });
    }

    const normalizedIsOutsourced = typeof is_outsourced === 'boolean'
      ? (is_outsourced ? 1 : 0)
      : (is_outsourced === 0 || is_outsourced === 1 ? is_outsourced : 1);

    await pool.query(
      // CORREÇÃO: Adiciona a coluna `cnh` no insert, pois ela pertence a esta tabela.
      'INSERT INTO drivers (user_id, company_id, cpf, cnh, phone_number, tech_knowledge, is_outsourced, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [
        userIdToUse,
        companyIdNumber,
        cpf,
        cnh || null,
        phone_number || null,
        tech_knowledge || null,
        normalizedIsOutsourced,
        'active'
      ]
    );

    res.status(201).json({ success: true, message: 'Motorista cadastrado com sucesso' });
  } catch (err) {
    console.error("Erro ao criar motorista:", err.response ? err.response.data : err.message);
    res.status(400).json({ success: false, error: err.response?.data?.error || err.message });
  }
});

// Listar motoristas
app.get('/api/drivers', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM drivers');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Detalhes de motorista
app.get('/api/drivers/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM drivers WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Motorista não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar motorista (ADMIN/SUPERVISOR)
app.put('/api/drivers/:id', authorize(['ADMIN', 'SUPERVISOR']), async (req, res) => {
  const { phone_number, tech_knowledge, is_outsourced } = req.body;
  try {
    await pool.query(
      'UPDATE drivers SET phone_number=?, tech_knowledge=?, is_outsourced=? WHERE id=?',
      [phone_number, tech_knowledge, is_outsourced, req.params.id]
    );
    res.json({ message: 'Motorista atualizado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Cadastro de veículo (ADMIN/SUPERVISOR)
app.post('/api/vehicles', authorize(['ADMIN', 'SUPERVISOR']), async (req, res) => {
  const { plate, model, year } = req.body;
  try {
    // Validação de placa única
    const [exists] = await pool.query('SELECT id FROM vehicles WHERE plate = ?', [plate]);
    if (exists.length > 0) return res.status(400).json({ error: 'Placa já cadastrada' });
    await pool.query(
      'INSERT INTO vehicles (plate, model, year) VALUES (?, ?, ?)',
      [plate, model, year]
    );
    res.status(201).json({ message: 'Veículo cadastrado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Listar veículos
app.get('/api/vehicles', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM vehicles');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Detalhes de veículo
app.get('/api/vehicles/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM vehicles WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Veículo não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar veículo (ADMIN/SUPERVISOR)
app.put('/api/vehicles/:id', authorize(['ADMIN', 'SUPERVISOR']), async (req, res) => {
  const { model, year } = req.body;
  try {
    await pool.query(
      'UPDATE vehicles SET model=?, year=? WHERE id=?',
      [model, year, req.params.id]
    );
    res.json({ message: 'Veículo atualizado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

if (require.main === module) {
  app.listen(3002, () => console.log('Drivers/Vehicles Service rodando na porta 3002'));
}
module.exports = app; 
