import axios, { type AxiosInstance } from "axios";
import { config } from "../config/settings";
import type { QueryResult } from "../config/schema";

export class ElasticConnector {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: config.elasticsearch.url,
      timeout: 60000,
      auth: {
        username: config.elasticsearch.username,
        password: config.elasticsearch.password,
      },
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async search(query: any): Promise<QueryResult> {
    const startTime = Date.now();

    try {
      const response = await this.client.post(`/${config.elasticsearch.index}/_search`, query);
      const result = response.data;

      const events = result.hits.hits.map((hit: any) => ({
        ...hit._source,
        _id: hit._id,
        _score: hit._score,
      }));

      return {
        events,
        total:
          typeof result.hits.total === "number"
            ? result.hits.total
            : result.hits.total?.value || 0,
        query_time: Date.now() - startTime,
      };
    } catch (error) {
      return {
        events: [],
        total: 0,
        query_time: Date.now() - startTime,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async getIndices(): Promise<string[]> {
    try {
      const response = await this.client.get('/_cat/indices?format=json');
      return response.data.map((index: any) => index.index);
    } catch {
      return [];
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.client.get('/_cluster/stats');
      console.log("✅ Elasticsearch connection successful");
      return true;
    } catch (error) {
      console.error("❌ Elasticsearch connection failed:", error);
      return false;
    }
  }
}
