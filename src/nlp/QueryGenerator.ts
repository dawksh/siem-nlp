import type { SIEMQuery, SIEMEvent } from '../config/schema';

export class QueryGenerator {
  generateElasticsearchQuery(siemQuery: SIEMQuery): any {
    const mustQueries: any[] = [];
    const shouldQueries: any[] = [];

    if (siemQuery.query) {
      mustQueries.push({
        multi_match: {
          query: siemQuery.query,
          fields: ['description', 'event_type', 'source', 'raw_log'],
          type: 'best_fields',
        },
      });
    }

    Object.entries(siemQuery.filters).forEach(([field, value]) => {
      if (Array.isArray(value)) {
        shouldQueries.push({
          terms: { [field]: value },
        });
      } else {
        mustQueries.push({
          term: { [field]: value },
        });
      }
    });

    const query: any = {
      bool: {
        must: mustQueries,
        filter: [
          {
            range: {
              timestamp: {
                gte: siemQuery.time_range.start,
                lte: siemQuery.time_range.end,
              },
            },
          },
        ],
      },
    };

    if (shouldQueries.length > 0) {
      query.bool.should = shouldQueries;
      query.bool.minimum_should_match = 1;
    }

    return {
      query,
      sort: [{ timestamp: { order: 'desc' } }],
      size: siemQuery.limit || 100,
    };
  }

  generateWazuhQuery(siemQuery: SIEMQuery): any {
    return {
      query: siemQuery.query,
      filters: siemQuery.filters,
      time_range: siemQuery.time_range,
      limit: siemQuery.limit || 100,
    };
  }

  normalizeResults(rawResults: any[], source: 'elasticsearch' | 'wazuh'): SIEMEvent[] {
    return rawResults.map((result: any): SIEMEvent => {
      if (source === 'elasticsearch') {
        const source = result._source || result;
        return {
          timestamp: source.timestamp || new Date().toISOString(),
          source: source.source || 'unknown',
          event_type: source.event_type || 'unknown',
          severity: source.severity || 'medium',
          description: source.description || '',
          user: source.user,
          ip_address: source.ip_address,
          hostname: source.hostname,
          process: source.process,
          raw_log: source.raw_log || JSON.stringify(source),
        };
      } else {
        return {
          timestamp: result.timestamp || new Date().toISOString(),
          source: result.agent?.name || 'wazuh',
          event_type: result.rule?.description || 'unknown',
          severity: this.mapWazuhSeverity(result.rule?.level || 3),
          description: result.rule?.description || '',
          user: result.data?.user,
          ip_address: result.data?.srcip,
          hostname: result.agent?.name,
          process: result.data?.process,
          raw_log: JSON.stringify(result),
        };
      }
    });
  }

  private mapWazuhSeverity(level: number): 'low' | 'medium' | 'high' | 'critical' {
    if (level >= 12) return 'critical';
    if (level >= 8) return 'high';
    if (level >= 4) return 'medium';
    return 'low';
  }
}
