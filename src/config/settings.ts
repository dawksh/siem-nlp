export const config = {
  api: {
    openai: {
      apiKey: process.env.OPENAI_API_KEY || '',
      model: process.env.OPENAI_MODEL || 'gpt-4',
      maxTokens: parseInt(process.env.OPENAI_MAX_TOKENS || '1000'),
    },
    gemini: {
      apiKey: process.env.GEMINI_API_KEY || '',
      model: process.env.GEMINI_MODEL || 'gemini-pro',
    },
  },
  elasticsearch: {
    url: process.env.ELASTICSEARCH_URL || 'http://54.80.24.14:9200',
    username: process.env.ELASTICSEARCH_USERNAME || 'elastic',
    password: process.env.ELASTICSEARCH_PASSWORD || 'changeme',
    apiKey: process.env.ELASTICSEARCH_API_KEY || '',
    index: process.env.ELASTICSEARCH_INDEX || 'logs-siem',
  },
  kibana: {
    host: process.env.KIBANA_HOST || 'http://kibana:5601',
    username: process.env.KIBANA_USERNAME || 'kibana_system',
    password: process.env.KIBANA_PASSWORD || 'kibana_password',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://redis:6379',
  },
  wazuh: {
    url: process.env.WAZUH_URL || 'http://localhost:55000',
    username: process.env.WAZUH_USERNAME || '',
    password: process.env.WAZUH_PASSWORD || '',
  },
  server: {
    port: parseInt(process.env.PORT || '3000'),
    host: process.env.HOST || 'localhost',
  },
} as const;
