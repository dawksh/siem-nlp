export interface APIConfig {
  openai?: {
    apiKey: string;
    model: string;
    maxTokens: number;
  };
  gemini?: {
    apiKey: string;
    model: string;
  };
}

export interface DataSourceConfig {
  elasticsearch?: {
    url: string;
    username?: string;
    password?: string;
    index: string;
  };
  wazuh?: {
    url: string;
    username: string;
    password: string;
  };
}

export interface ServerConfig {
  port: number;
  host: string;
}

export interface ConversationMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  metadata?: {
    query?: any;
    results?: any[];
    processingTime?: number;
  };
}

export interface QueryContext {
  recentQueries: string[];
  activeFilters: Record<string, any>;
  timeRange: {
    start: string;
    end: string;
  };
  userPreferences: {
    defaultSource: 'elasticsearch' | 'wazuh';
    maxResults: number;
    autoAnalysis: boolean;
  };
}

export interface SecurityAlert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  source: string;
  timestamp: string;
  indicators: string[];
  recommendedActions: string[];
  falsePositive: boolean;
}

export interface QueryMetrics {
  queryTime: number;
  resultCount: number;
  cacheHit: boolean;
  source: string;
  complexity: 'simple' | 'medium' | 'complex';
}
