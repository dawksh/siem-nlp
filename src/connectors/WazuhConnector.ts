import { config } from "../config/settings";
import type { QueryResult } from "../config/schema";

export class WazuhConnector {
  private baseUrl: string;
  private token?: string;

  constructor() {
    this.baseUrl = config.wazuh.url;
  }

  private async authenticate(): Promise<string> {
    if (!this.token) {
      const response = await fetch(
        `${this.baseUrl}/security/user/authenticate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: config.wazuh.username,
            password: config.wazuh.password,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`Wazuh authentication failed: ${response.statusText}`);
      }

      const data = await response.json();
      this.token = data.data.token;
    }

    return this.token ?? "";
  }

  private async makeRequest(
    endpoint: string,
    params?: Record<string, any>
  ): Promise<any> {
    const token = await this.authenticate();
    const url = new URL(`${this.baseUrl}${endpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.append(key, String(value));
      });
    }

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`Wazuh API error: ${response.statusText}`);
    }

    return response.json();
  }

  async search(query: any): Promise<QueryResult> {
    const startTime = Date.now();

    try {
      const params: Record<string, any> = {
        limit: query.limit || 100,
        offset: 0,
      };

      if (query.time_range) {
        params.date_from = query.time_range.start;
        params.date_to = query.time_range.end;
      }

      if (query.query) {
        params.q = query.query;
      }

      Object.entries(query.filters || {}).forEach(([key, value]) => {
        params[key] = value;
      });

      const result = await this.makeRequest("/alerts", params);

      return {
        events: result.data?.affected_items || [],
        total: result.data?.total_affected_items || 0,
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

  async getAgents(): Promise<any[]> {
    try {
      const result = await this.makeRequest("/agents");
      return result.data?.affected_items || [];
    } catch {
      return [];
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.makeRequest("/agents");
      return true;
    } catch {
      return false;
    }
  }
}
