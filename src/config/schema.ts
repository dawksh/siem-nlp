export interface SIEMEvent {
  timestamp: string;
  source: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  user?: string;
  ip_address?: string;
  hostname?: string;
  process?: string;
  raw_log: string;
}

export interface SIEMQuery {
  query?: {
    description: string;
    time_range: any;
    event_types?: string[];
    data_sources?: string[];
    filters?: any[];
    aggregation?: any;
    kql?: string;
    optimization_notes?: string[];
    security_implications?: string[];
  };
  filters?: Record<string, any>;
  time_range?: {
    start: string;
    end: string;
  };
  limit?: number;
}

export interface NLPPrompt {
  system: string;
  user: string;
  context?: string;
}

export interface QueryResult {
  events: SIEMEvent[];
  total: number;
  query_time: number;
  error?: string;
}
