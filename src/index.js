require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./docs/openapi.json');
const authRoutes = require('./api/routes/auth.routes');
const { connectMongo } = require('./infra/mongoose');

const PORT = process.env.PORT || 4000;

async function start() {
  await connectMongo(process.env.MONGO_URI);

  const app = express();
  app.use(helmet());
  app.use(cors());
  app.use(bodyParser.json());

  app.use('/health', (req, res) => res.json({ status: 'ok' }));
  app.use('/auth', authRoutes);
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.use('/uploads', express.static(process.env.LOCAL_UPLOAD_PATH || 'uploads'));

  app.listen(PORT, () => console.log(`🚀 Auth service running on ${PORT}`));
}

start();
