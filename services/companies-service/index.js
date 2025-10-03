require('dotenv').config();

const express = require('express');
const pool = require('../../shared/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Companies Management',
    version: '1.0.0',
    description: 'Documentação da API de gerenciamento de empresas'
  }
};
const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);

const app = express();
app.use(express.json());

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
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware de autenticação e autorização
function authorize(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
    const token = auth.split(' ')[1];
    try {
      const decoded = jwt.verify(token, "fda76ff877a92f9a86e7831fad372e2d9e777419e155aab4f5b18b37d280d05a");
      if (roles.length && !roles.includes(decoded.user_type)) {
        return res.status(403).json({ error: 'Acesso negado' });
      }
      req.user = decoded;
      next();
    } catch (err) {
      console.error('JWT Error:', err.message);
      res.status(401).json({ error: 'Token inválido' });
    }
  };
}

/**
 * @swagger
 * /api/companies:
 *   get:
 *     summary: Lista todas as empresas
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de empresas
 */
// Listar empresas (apenas MASTER)
app.get('/api/companies', authorize(['MASTER']), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, name, cnpj, domain, logo_url, primary_color, secondary_color, 
             address, phone, email, is_active, subscription_plan, 
             subscription_expires_at, max_users, max_drivers, created_at, updated_at
      FROM companies 
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/companies:
 *   post:
 *     summary: Cria uma nova empresa
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               cnpj:
 *                 type: string
 *               domain:
 *                 type: string
 *               email:
 *                 type: string
 *               subscription_plan:
 *                 type: string
 *     responses:
 *       201:
 *         description: Empresa criada
 */
// Criar empresa (apenas MASTER)
app.post('/api/companies', authorize(['MASTER']), async (req, res) => {
  const { 
    name, cnpj, domain, logo_url, primary_color, secondary_color, 
    address, phone, email, subscription_plan, max_users, max_drivers 
  } = req.body;

  try {
    // Verificar se o domínio já existe
    const [existingDomain] = await pool.query('SELECT id FROM companies WHERE domain = ?', [domain]);
    if (existingDomain.length > 0) {
      return res.status(400).json({ error: 'Domínio já cadastrado' });
    }

    // Verificar se o CNPJ já existe
    if (cnpj) {
      const [existingCnpj] = await pool.query('SELECT id FROM companies WHERE cnpj = ?', [cnpj]);
      if (existingCnpj.length > 0) {
        return res.status(400).json({ error: 'CNPJ já cadastrado' });
      }
    }

    // Inserir empresa
    const [result] = await pool.query(`
      INSERT INTO companies (name, cnpj, domain, logo_url, primary_color, secondary_color, 
                           address, phone, email, subscription_plan, max_users, max_drivers) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, cnpj, domain, logo_url, primary_color, secondary_color, 
        address, phone, email, subscription_plan, max_users, max_drivers]);

    const companyId = result.insertId;

    // Criar configurações padrão para a empresa
    await pool.query(`
      INSERT INTO company_settings (company_id) VALUES (?)
    `, [companyId]);

    // Criar usuário admin padrão para a empresa
    const adminPassword = 'admin123';
    const adminHash = await bcrypt.hash(adminPassword, 10);
    
    await pool.query(`
      INSERT INTO users (company_id, username, password_hash, email, full_name, user_type) 
      VALUES (?, ?, ?, ?, ?, ?)
    `, [companyId, 'admin', adminHash, `admin@${domain}.com`, 'Administrador', 'ADMIN']);

    res.status(201).json({ 
      message: 'Empresa criada com sucesso',
      company_id: companyId,
      admin_credentials: {
        username: 'admin',
        password: adminPassword
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/companies/{id}:
 *   get:
 *     summary: Obtém detalhes de uma empresa
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalhes da empresa
 */
// Obter detalhes de uma empresa
app.get('/api/companies/:id', authorize(['MASTER']), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.*, cs.*
      FROM companies c
      LEFT JOIN company_settings cs ON c.id = cs.company_id
      WHERE c.id = ?
    `, [req.params.id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Empresa não encontrada' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/companies/{id}:
 *   put:
 *     summary: Atualiza uma empresa
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Empresa atualizada
 */
// Atualizar empresa
app.put('/api/companies/:id', authorize(['MASTER']), async (req, res) => {
  const { 
    name, cnpj, domain, logo_url, primary_color, secondary_color, 
    address, phone, email, subscription_plan, max_users, max_drivers, is_active 
  } = req.body;

  try {
    await pool.query(`
      UPDATE companies 
      SET name=?, cnpj=?, domain=?, logo_url=?, primary_color=?, secondary_color=?,
          address=?, phone=?, email=?, subscription_plan=?, max_users=?, max_drivers=?, is_active=?
      WHERE id=?
    `, [name, cnpj, domain, logo_url, primary_color, secondary_color, 
        address, phone, email, subscription_plan, max_users, max_drivers, is_active, req.params.id]);
    
    res.json({ message: 'Empresa atualizada com sucesso' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/companies/{id}/stats:
 *   get:
 *     summary: Obtém estatísticas de uma empresa
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Estatísticas da empresa
 */
// Obter estatísticas da empresa
app.get('/api/companies/:id/stats', authorize(['MASTER', 'ADMIN']), async (req, res) => {
  try {
    const companyId = req.params.id;
    
    // Verificar se o usuário tem acesso à empresa
    if (req.user.user_type !== 'MASTER') {
      if (req.user.company_id != companyId) {
        return res.status(403).json({ error: 'Acesso negado' });
      }
    }

    const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE company_id = ?', [companyId]);
    const [driverCount] = await pool.query('SELECT COUNT(*) as count FROM drivers WHERE company_id = ?', [companyId]);
    const [vehicleCount] = await pool.query('SELECT COUNT(*) as count FROM vehicles WHERE company_id = ?', [companyId]);
    const [clientCount] = await pool.query('SELECT COUNT(*) as count FROM clients WHERE company_id = ?', [companyId]);
    const [deliveryCount] = await pool.query('SELECT COUNT(*) as count FROM delivery_notes WHERE company_id = ?', [companyId]);
    const [activeDeliveryCount] = await pool.query('SELECT COUNT(*) as count FROM delivery_notes WHERE company_id = ? AND status IN ("PENDING", "IN_TRANSIT")', [companyId]);

    res.json({
      users: userCount[0].count,
      drivers: driverCount[0].count,
      vehicles: vehicleCount[0].count,
      clients: clientCount[0].count,
      total_deliveries: deliveryCount[0].count,
      active_deliveries: activeDeliveryCount[0].count
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/companies/{id}/settings:
 *   put:
 *     summary: Atualiza configurações de uma empresa
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Configurações atualizadas
 */
// Atualizar configurações da empresa
app.put('/api/companies/:id/settings', authorize(['MASTER', 'ADMIN']), async (req, res) => {
  const { 
    timezone, working_hours_start, working_hours_end, delivery_timeout_hours,
    auto_reattempt_days, notification_email, notification_sms, notification_whatsapp 
  } = req.body;

  try {
    // Verificar se o usuário tem acesso à empresa
    if (req.user.user_type !== 'MASTER') {
      if (req.user.company_id != req.params.id) {
        return res.status(403).json({ error: 'Acesso negado' });
      }
    }

    await pool.query(`
      UPDATE company_settings 
      SET timezone=?, working_hours_start=?, working_hours_end=?, delivery_timeout_hours=?,
          auto_reattempt_days=?, notification_email=?, notification_sms=?, notification_whatsapp=?
      WHERE company_id=?
    `, [timezone, working_hours_start, working_hours_end, delivery_timeout_hours,
        auto_reattempt_days, notification_email, notification_sms, notification_whatsapp, req.params.id]);
    
    res.json({ message: 'Configurações atualizadas com sucesso' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

if (require.main === module) {
  app.listen(3007, () => console.log('Companies Service rodando na porta 3007'));
}
module.exports = app; 
