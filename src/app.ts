import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import queryRoutes from './routes/query';
import { config } from './config/settings';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', queryRoutes);

app.get('/', (req, res) => {
  res.json({
    name: 'SIEM NLP Layer',
    version: '1.0.0',
    endpoints: {
      query: 'POST /api/query',
      context: 'GET /api/context',
      health: 'GET /api/health',
    },
  });
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const startServer = () => {
  app.listen(config.server.port,() => {
    console.log(`SIEM NLP Layer running on PORT: ${config.server.port}`);
  });
};

if (require.main === module) {
  startServer();
}

export default app;
