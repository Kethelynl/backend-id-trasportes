const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pool = require('../../shared/db');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API Tracking Service',
    version: '1.0.0',
    description: 'API para rastreamento em tempo real de motoristas'
  }
};

const options = {
  swaggerDefinition,
  apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(cors({ origin: 'http://localhost:8080', credentials: true }));

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

// Armazenar conexões WebSocket por empresa
const connections = new Map();

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

// WebSocket para rastreamento em tempo real
wss.on('connection', (ws, req) => {
  console.log('Nova conexão WebSocket estabelecida');

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'auth') {
        // Autenticar conexão WebSocket
        const decoded = jwt.verify(data.token, "fda76ff877a92f9a86e7831fad372e2d9e777419e155aab4f5b18b37d280d05a");
        ws.user = decoded;
        ws.companyId = decoded.company_id;
        
        // Adicionar à lista de conexões da empresa
        if (!connections.has(decoded.company_id)) {
          connections.set(decoded.company_id, new Set());
        }
        connections.get(decoded.company_id).add(ws);
        
        ws.send(JSON.stringify({ type: 'auth_success' }));
      }
      
      if (data.type === 'location_update') {
        // Salvar localização no banco
        await saveLocation(data);
        
        // Broadcast para outros usuários da mesma empresa
        broadcastToCompany(ws.companyId, {
          type: 'location_update',
          driver_id: data.driver_id,
          location: data.location,
          timestamp: new Date().toISOString()
        });
      }
      
    } catch (error) {
      console.error('Erro no WebSocket:', error);
      ws.send(JSON.stringify({ type: 'error', message: error.message }));
    }
  });

  ws.on('close', () => {
    if (ws.companyId && connections.has(ws.companyId)) {
      connections.get(ws.companyId).delete(ws);
    }
  });
});

// Função para salvar localização no banco
async function saveLocation(data) {
  try {
    await pool.query(`
      INSERT INTO tracking_points (driver_id, company_id, latitude, longitude, accuracy, speed, heading, delivery_id, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      data.driver_id,
      data.company_id,
      data.location.latitude,
      data.location.longitude,
      data.location.accuracy || null,
      data.location.speed || null,
      data.location.heading || null,
      data.delivery_id || null
    ]);
  } catch (error) {
    console.error('Erro ao salvar localização:', error);
  }
}

// Função para broadcast para empresa
function broadcastToCompany(companyId, message) {
  if (connections.has(companyId)) {
    connections.get(companyId).forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }
}

/**
 * @swagger
 * /api/tracking/location:
 *   post: 
 *     summary: Enviar localização do motorista
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               driver_id:
 *                 type: string
 *               latitude:
 *                 type: number
 *               longitude:
 *                 type: number
 *               accuracy:
 *                 type: number
 *               speed:
 *                 type: number
 *               heading:
 *                 type: number
 *               delivery_id:
 *                 type: string
 *     responses:
 *       200:
 *         description: Localização enviada com sucesso
 */
app.post('/api/tracking/location', authorize(['DRIVER']), async (req, res) => {
    try {
        const { latitude, longitude, accuracy, speed, heading, delivery_id } = req.body;
        const company_id = req.user.company_id;
        const user_id = req.user.id; // Pega o user_id do token JWT

        // Busca o driver_id correspondente ao user_id
        const [driverRows] = await pool.query('SELECT id FROM drivers WHERE user_id = ? AND company_id = ?', [user_id, company_id]);

        if (driverRows.length === 0) {
            console.warn(`[Tracking] Tentativa de salvar localização para um usuário sem registro de motorista. User ID: ${user_id}`);
            return res.status(404).json({ error: 'Motorista não encontrado para este usuário.' });
        }
        const driver_id = driverRows[0].id; // Este é o ID correto para a tabela tracking_points

        const parsedLatitude = latitude === undefined || latitude === null ? null : Number(latitude);
        const parsedLongitude = longitude === undefined || longitude === null ? null : Number(longitude);
        const rawAccuracy = accuracy === undefined || accuracy === null ? null : Number(accuracy);
        const parsedAccuracy = rawAccuracy !== null && Number.isFinite(rawAccuracy) && rawAccuracy >= 0 ? rawAccuracy : null;
        const sanitizedAccuracy = parsedAccuracy !== null ? Math.min(parsedAccuracy, 999.99) : null;
        const parsedSpeed = typeof speed === 'number' && Number.isFinite(speed) ? speed : null;
        const parsedHeading = typeof heading === 'number' && Number.isFinite(heading) ? heading : null;
        const parsedDeliveryId = delivery_id ?? null;

        console.log('[Tracking] Recebido ping de localização', {
            driver_id,
            company_id,
            user_id,
            latitude,
            longitude,
            accuracy: sanitizedAccuracy,
            rawAccuracy: parsedAccuracy,
            speed,
            heading,
            delivery_id,
            timestamp: new Date().toISOString(),
        });

        if (!driver_id || parsedLatitude === null || Number.isNaN(parsedLatitude) || parsedLongitude === null || Number.isNaN(parsedLongitude) || !company_id) {
            return res.status(400).json({ error: 'Dados de localização incompletos' });
        }

        // Insere a localização na tabela tracking_points
        await pool.execute(
            `INSERT INTO tracking_points (driver_id, company_id, latitude, longitude, accuracy, speed, heading, delivery_id, timestamp)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [driver_id, company_id, parsedLatitude, parsedLongitude, sanitizedAccuracy, parsedSpeed, parsedHeading, parsedDeliveryId]
        );

        console.log('[Tracking] Localização persistida', { driver_id, company_id });
        res.status(200).json({ success: true, message: 'Localização salva com sucesso' });
    } catch (error) {
        console.error('Erro ao salvar localização:', error);
        res.status(500).json({ error: 'Erro interno ao salvar localização', details: error.message });
    }
});

/**
 * @swagger
 * /api/tracking/drivers/current-locations:
 *   get: 
 *     summary: Obter localizações atuais de todos os motoristas
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: LocalizaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes dos motoristas
 */
app.get('/api/tracking/drivers/current-locations', authorize(['ADMIN', 'SUPERVISOR', 'DRIVER']), async (req, res) => {
  try {
    console.log('[Tracking] Buscando localizações atuais', { company_id: req.user.company_id });
    const [rows] = await pool.query(`
      SELECT 
        d.id as driver_id,
        u.full_name as driver_name,
        tp.latitude,
        tp.longitude,
        tp.accuracy,
        tp.speed,
        tp.heading,
        tp.timestamp as last_update,
        IF(tp.timestamp < DATE_SUB(NOW(), INTERVAL 10 MINUTE), 'idle', 'active') as activity_status,
        d.status,
        del.id as current_delivery_id,
        del.client_name as current_delivery_client
      FROM drivers d
      INNER JOIN (
        SELECT driver_id, MAX(timestamp) as max_timestamp
        FROM tracking_points 
        WHERE company_id = ?
          AND timestamp >= DATE_SUB(NOW(), INTERVAL 2 HOUR) -- Aumenta a janela de busca para 2 horas
        GROUP BY driver_id
      ) latest ON latest.driver_id = d.id
      INNER JOIN tracking_points tp ON tp.driver_id = latest.driver_id AND tp.timestamp = latest.max_timestamp
      LEFT JOIN users u ON d.user_id = u.id
      LEFT JOIN (
          SELECT 
              id, 
              driver_id, 
              client_name,
              -- Subconsulta para pegar apenas a entrega mais recente em trânsito por motorista
              ROW_NUMBER() OVER(PARTITION BY driver_id ORDER BY created_at DESC) as rn 
          FROM deliveries 
          WHERE status = 'IN_TRANSIT'
      ) del ON d.id = del.driver_id AND del.rn = 1
      WHERE d.company_id = ?
        AND tp.latitude IS NOT NULL
        AND tp.longitude IS NOT NULL
      ORDER BY tp.timestamp DESC
    `, [req.user.company_id, req.user.company_id]);

    console.log(`[Tracking] Consulta executada. ${rows.length} localizações encontradas.`);
    if (rows.length > 0) {
        console.log('[Tracking] Exemplo de dados retornados:', JSON.stringify(rows[0], null, 2));
    }
    res.json({
      success: true,
      data: rows.map(row => ({ ...row, activity_status: row.activity_status }))
    });

  } catch (error) {
    console.error('Erro ao obter localizações:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/tracking/drivers/{driverId}/history:
 *   get: 
 *     summary: Obter histórico de rastreamento do motorista
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: driverId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: start_date
 *         schema:
 *           type: string
 *       - in: query
 *         name: end_date
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Histórico de rastreamento
 */
app.get('/api/tracking/drivers/:driverId/history', authorize(['ADMIN', 'SUPERVISOR', 'DRIVER']), async (req, res) => {
  try {
    const { driverId } = req.params;
    const { start_date, end_date } = req.query;

    let query = `
      SELECT 
        timestamp,
        latitude,
        longitude,
        accuracy,
        speed,
        heading,
        delivery_id
      FROM tracking_points 
      WHERE driver_id = ? AND company_id = ?
    `;
    const params = [driverId, req.user.company_id];

    if (start_date) {
      query += ' AND timestamp >= ?';
      params.push(start_date);
    }

    if (end_date) {
      query += ' AND timestamp <= ?';
      params.push(end_date);
    }

    query += ' ORDER BY timestamp DESC LIMIT 1000';

    const [rows] = await pool.query(query, params);

    res.json({
      success: true,
      data: rows
    });

  } catch (error) {
    console.error('Erro ao obter histórico:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/tracking/drivers/{driverId}/status:
 *   put:
 *     summary: Atualizar status do motorista
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: driverId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [online, offline, busy, available]
 *     responses:
 *       200:
 *         description: Status atualizado com sucesso
 */
app.put('/api/tracking/drivers/:driverId/status', authorize(['DRIVER', 'ADMIN']), async (req, res) => {
  try {
    const { driverId } = req.params;
    const { status: frontendStatus } = req.body;
    const companyId = req.user.company_id;

    console.log(`[Tracking] Recebida atualização de status para driver ${driverId} com status: ${frontendStatus}`);

    // Mapeia o status do frontend para o status do banco de dados
    const statusMap = {
      online: 'active',
      offline: 'inactive',
      idle: 'inactive', 
      busy: 'active', 
    };

    const dbStatus = statusMap[frontendStatus];

    if (!dbStatus) {
      console.error(`[Tracking] Status inválido recebido: ${frontendStatus}`);
      return res.status(400).json({ error: `Status inválido: ${frontendStatus}` });
    }

    let driverIdToUpdate = driverId;
    const [driverRows] = await pool.query(
      'SELECT * FROM drivers WHERE id = ? AND company_id = ?',
      [driverId, companyId]
    );

    if (driverRows.length === 0) {
      const [rowsByUser] = await pool.query(
        'SELECT * FROM drivers WHERE user_id = ? AND company_id = ?',
        [req.user.user_id, companyId]
      );

      if (rowsByUser.length === 0) {
        console.warn('[Tracking] Driver não encontrado para atualização de status', { driverId, userId: req.user.user_id });
        return res.status(404).json({ error: 'Motorista não encontrado' });
      }

      driverIdToUpdate = rowsByUser[0].id;
    }

    await pool.query(
      'UPDATE drivers SET status = ?, last_status_update = NOW() WHERE id = ?',
      [dbStatus, driverIdToUpdate]
    );
    console.log(`[Tracking] Status do driver ${driverIdToUpdate} atualizado para '${dbStatus}' no banco de dados.`);

    broadcastToCompany(companyId, {
      type: 'driver_status',
      driver_id: driverIdToUpdate,
      status: dbStatus, // Envia o status do DB para consistência
      timestamp: new Date().toISOString()
    });

    res.json({ success: true, message: 'Status atualizado com sucesso' });

  } catch (error) {
    console.error('Erro ao atualizar status:', error);
    res.status(500).json({ error: error.message });
  }
});



if (require.main === module) {
  server.listen(3005, () => console.log('Tracking Service rodando na porta 3005'));
}

module.exports = app; 
