const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../../shared/db');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Auth Service',
    version: '1.0.0',
    description: 'API para autenticação e gerenciamento de usuários'
  }
};

const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);

const app = express();
app.use(express.json());
app.options('*', cors(corsOptions));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware de autenticação
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
      res.status(401).json({ error: 'Token inválido' });
    }
  };
}

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login do usuário
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
 *         description: Login realizado com sucesso
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username e password são obrigatórios' });
    }

    // Buscar usuário
    const [userRows] = await pool.query(
      'SELECT u.*, c.name as company_name, c.domain as company_domain FROM users u LEFT JOIN companies c ON u.company_id = c.id WHERE u.username = ?',
      [username]
    );

    if (userRows.length === 0) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    const user = userRows[0];

    // Verificar senha
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    // Gerar token sem company_id (usuário escolherá depois)
    const token = jwt.sign({
      user_id: user.id,
      username: user.username,
      email: user.email,
      full_name: user.full_name,
      user_type: user.user_type,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 horas
    }, "fda76ff877a92f9a86e7831fad372e2d9e777419e155aab4f5b18b37d280d05a");

    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          user_type: user.user_type,
          company_id: user.company_id,
          company_name: user.company_name,
          company_domain: user.company_domain
        }
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/companies:
 *   get:
 *     summary: Listar empresas do usuário
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de empresas
 */
app.get('/api/auth/companies', authorize([]), async (req, res) => {
  try {
    // Buscar empresas do usuário
    const [companyRows] = await pool.query(`
      SELECT DISTINCT c.id, c.name, c.domain, c.email, c.subscription_plan
      FROM companies c
      INNER JOIN users u ON c.id = u.company_id
      WHERE u.id = ?
    `, [req.user.user_id]);

    res.json({
      success: true,
      data: companyRows
    });

  } catch (error) {
    console.error('Erro ao listar empresas:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/select-company:
 *   post:
 *     summary: Selecionar empresa
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               company_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Empresa selecionada com sucesso
 */
app.post('/api/auth/select-company', authorize([]), async (req, res) => {
  try {
    const { company_id } = req.body;

    if (!company_id) {
      return res.status(400).json({ error: 'company_id é obrigatório' });
    }

    // Verificar se o usuário tem acesso à empresa
    const [userRows] = await pool.query(
      'SELECT * FROM users WHERE id = ? AND company_id = ?',
      [req.user.user_id, company_id]
    );

    if (userRows.length === 0) {
      return res.status(403).json({ error: 'Usuário não tem acesso a esta empresa' });
    }

    const user = userRows[0];

    // Gerar novo token com company_id
    const token = jwt.sign({
      user_id: user.id,
      username: user.username,
      email: user.email,
      full_name: user.full_name,
      user_type: user.user_type,
      company_id: user.company_id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 horas
    }, "fda76ff877a92f9a86e7831fad372e2d9e777419e155aab4f5b18b37d280d05a");

    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          user_type: user.user_type,
          company_id: user.company_id
        }
      }
    });

  } catch (error) {
    console.error('Erro ao selecionar empresa:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Obter perfil do usuário
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Perfil do usuário
 */
app.get('/api/auth/profile', authorize([]), async (req, res) => {
  try {
    const [userRows] = await pool.query(
      'SELECT u.*, c.name as company_name FROM users u LEFT JOIN companies c ON u.company_id = c.id WHERE u.id = ?',
      [req.user.user_id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const user = userRows[0];

    res.json({
      success: true,
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        user_type: user.user_type,
        company_id: user.company_id,
        company_name: user.company_name
      }
    });

  } catch (error) {
    console.error('Erro ao obter perfil:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout do usuário
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout realizado com sucesso
 */
app.post('/api/auth/logout', authorize([]), async (req, res) => {
  try {
    // Em um sistema real, você poderia invalidar o token aqui
    res.json({
      success: true,
      message: 'Logout realizado com sucesso'
    });

  } catch (error) {
    console.error('Erro no logout:', error);
    res.status(500).json({ error: error.message });
  }
});

if (require.main === module) {
  app.listen(3000, () => console.log('Auth Service rodando na porta 3000'));
}

module.exports = app; 
