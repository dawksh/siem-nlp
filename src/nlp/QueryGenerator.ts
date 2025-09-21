import type { SIEMQuery, SIEMEvent } from '../config/schema';

export class QueryGenerator {
  generateElasticsearchQuery(siemQuery: SIEMQuery): any {
    const mustQueries: any[] = [];
    const shouldQueries: any[] = [];

    if (siemQuery.query?.description) {
      mustQueries.push({
        multi_match: {
          query: siemQuery.query.description,
          fields: ['description', 'event_type', 'source', 'raw_log', 'message', 'log'],
          type: 'best_fields',
        },
      });
    }

    if (siemQuery.query?.event_types) {
      shouldQueries.push({
        terms: { event_type: siemQuery.query.event_types },
      });
    }

    if (siemQuery.query?.data_sources) {
      shouldQueries.push({
        terms: { source: siemQuery.query.data_sources },
      });
    }

    if (siemQuery.filters) {
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
    }

    const timeRange = siemQuery.query?.time_range || siemQuery.time_range;
    
    // Try different timestamp field names that might exist
    const timestampFields = ['@timestamp', 'timestamp', 'date', 'time', 'created_at', 'updated_at'];
    
    // If no queries are specified, use match_all
    if (mustQueries.length === 0 && shouldQueries.length === 0) {
      const query: any = {
        match_all: {}
      };

      if (timeRange) {
        const timeFilter = timestampFields.map(field => ({
          range: {
            [field]: {
              gte: timeRange.start || timeRange[0],
              lte: timeRange.end || timeRange[1],
            },
          },
        }));

        return {
          query: {
            bool: {
              must: [query],
              should: timeFilter,
              minimum_should_match: 1,
            },
          },
          size: siemQuery.limit || 100,
        };
      }

      return {
        query,
        size: siemQuery.limit || 100,
      };
    }

    const query: any = {
      bool: {
        must: mustQueries.length > 0 ? mustQueries : [{ match_all: {} }],
      },
    };

    if (timeRange) {
      const timeFilter = timestampFields.map(field => ({
        range: {
          [field]: {
            gte: timeRange.start || timeRange[0],
            lte: timeRange.end || timeRange[1],
          },
        },
      }));
      
      if (!query.bool.should) {
        query.bool.should = [];
      }
      query.bool.should.push(...timeFilter);
      query.bool.minimum_should_match = 1;
    }

    if (shouldQueries.length > 0) {
      if (!query.bool.should) {
        query.bool.should = [];
      }
      query.bool.should.push(...shouldQueries);
      query.bool.minimum_should_match = (query.bool.minimum_should_match || 0) + 1;
    }

    return {
      query,
      size: siemQuery.limit || 100,
    };
  }

  generateWazuhQuery(siemQuery: SIEMQuery): any {
    return {
      query: siemQuery.query?.description || siemQuery.query,
      filters: siemQuery.filters,
      time_range: siemQuery.query?.time_range || siemQuery.time_range,
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
