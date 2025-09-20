import { config } from '../config/settings';
import type { QueryResult } from '../config/schema';

export class ElasticConnector {
  private baseUrl: string;
  private credentials?: string;

  constructor() {
    this.baseUrl = config.elasticsearch.url;
    if (config.elasticsearch.username && config.elasticsearch.password) {
      this.credentials = btoa(`${config.elasticsearch.username}:${config.elasticsearch.password}`);
    }
  }

  private async makeRequest(endpoint: string, body: any): Promise<any> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.credentials) {
      headers['Authorization'] = `Basic ${this.credentials}`;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Elasticsearch error: ${response.statusText}`);
    }

    return response.json();
  }

  async search(query: any): Promise<QueryResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.makeRequest(`/${config.elasticsearch.index}/_search`, query);
      
      const events = result.hits.hits.map((hit: any) => ({
        ...hit._source,
        _id: hit._id,
        _score: hit._score,
      }));

      return {
        events,
        total: result.hits.total.value,
        query_time: Date.now() - startTime,
      };
    } catch (error) {
      return {
        events: [],
        total: 0,
        query_time: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  async getIndices(): Promise<string[]> {
    try {
      const response = await fetch(`${this.baseUrl}/_cat/indices?format=json`, {
        headers: this.credentials ? {
          'Authorization': `Basic ${this.credentials}`,
        } : {},
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch indices: ${response.statusText}`);
      }

      const indices = await response.json();
      return indices.map((index: any) => index.index);
    } catch {
      return [];
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/_cluster/health`, {
        headers: this.credentials ? {
          'Authorization': `Basic ${this.credentials}`,
        } : {},
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
