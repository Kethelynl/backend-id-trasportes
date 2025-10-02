const whitelist = [
  'http://localhost:5173', // Frontend local
  'https://frontend-id-transportes-6ruh7wk5m.vercel.app' // Seu frontend na Vercel
  // Adicione aqui outras URLs de frontend se houver (ex: staging)
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

module.exports = corsOptions;
