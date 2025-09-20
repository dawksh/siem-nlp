import { Router } from 'express';
import { NLPParser } from '../nlp/NLPParser';
import { QueryGenerator } from '../nlp/QueryGenerator';
import { ElasticConnector } from '../connectors/ElasticConnector';
import { WazuhConnector } from '../connectors/WazuhConnector';
import { ContextManager } from '../context/ContextManager';

const router = Router();
const nlpParser = new NLPParser();
const queryGenerator = new QueryGenerator();
const elasticConnector = new ElasticConnector();
const wazuhConnector = new WazuhConnector();
const contextManager = new ContextManager();

router.post('/query', async (req, res) => {
  try {
    const { query, source = 'elasticsearch', context } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    const siemQuery = await nlpParser.parseQuery(query, context);
    
    let result;
    if (source === 'elasticsearch') {
      const esQuery = queryGenerator.generateElasticsearchQuery(siemQuery);
      const rawResult = await elasticConnector.search(esQuery);
      result = {
        ...rawResult,
        events: queryGenerator.normalizeResults(rawResult.events, 'elasticsearch'),
      };
    } else if (source === 'wazuh') {
      const wazuhQuery = queryGenerator.generateWazuhQuery(siemQuery);
      const rawResult = await wazuhConnector.search(wazuhQuery);
      result = {
        ...rawResult,
        events: queryGenerator.normalizeResults(rawResult.events, 'wazuh'),
      };
    } else {
      return res.status(400).json({ error: 'Invalid source. Use elasticsearch or wazuh' });
    }

    const analysis = await nlpParser.analyzeResults(query, result.events);
    
    contextManager.addMessage('user', query, siemQuery);
    contextManager.addMessage('assistant', analysis, siemQuery, result.events);

    res.json({
      query: siemQuery,
      result,
      analysis,
      context: contextManager.getContextSummary(),
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Internal server error',
    });
  }
});

router.get('/context', (req, res) => {
  const context = contextManager.getRecentContext(20);
  res.json({ context });
});

router.delete('/context', (req, res) => {
  contextManager.clearHistory();
  res.json({ message: 'Context cleared' });
});

router.get('/health', async (req, res) => {
  const elasticHealth = await elasticConnector.testConnection();
  const wazuhHealth = await wazuhConnector.testConnection();
  
  res.json({
    elasticsearch: elasticHealth,
    wazuh: wazuhHealth,
    status: elasticHealth || wazuhHealth ? 'healthy' : 'unhealthy',
  });
});

export default router;
