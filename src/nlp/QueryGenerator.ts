import type { SIEMQuery, SIEMEvent } from '../config/schema';

export class QueryGenerator {
generateElasticsearchQuery(siemQuery: SIEMQuery): any {
  const mustQueries: any[] = [];
  const shouldQueries: any[] = [];

  // Handle nested structure from NLP parser
  const actualQuery = (siemQuery as any).siemQuery?.query || siemQuery.query || siemQuery;

  // Free text description - only add if no specific filters exist
  if (actualQuery?.description && !actualQuery?.filters?.length && !actualQuery?.event_types?.length) {
    mustQueries.push({
      multi_match: {
        query: actualQuery.description,
        fields: [
          'event.type',
          'event.action',
          'host.name',
          'user.name',
          'process.name',
          'malware.name',
          'file.hash',
          'network.protocol',
        ],
        type: 'best_fields',
      },
    });
  }

  // Event types
  if (actualQuery?.event_types) {
    shouldQueries.push({ terms: { 'event.type': actualQuery.event_types } });
  }

  // Handle filters from the prompt template (avoid duplicates)
  if (actualQuery?.filters && Array.isArray(actualQuery.filters)) {
    const addedFilters = new Set<string>();
    
    actualQuery.filters.forEach((filter: any) => {
      if (filter.field && filter.value) {
        const filterKey = `${filter.field}:${filter.value}`;
        
        if (!addedFilters.has(filterKey)) {
          addedFilters.add(filterKey);
          
          if (filter.operator === 'equals') {
            mustQueries.push({ term: { [filter.field]: filter.value } });
          } else if (filter.operator === 'in') {
            mustQueries.push({ terms: { [filter.field]: Array.isArray(filter.value) ? filter.value : [filter.value] } });
          } else if (filter.operator === 'range') {
            mustQueries.push({ range: { [filter.field]: filter.value } });
          }
        }
      }
    });
  }


  // KQL conversion to Elasticsearch DSL (add to existing queries)
  if (actualQuery?.kql) {
    const kqlQueries = this.convertKQLToElasticsearch(actualQuery.kql);
    if (kqlQueries && Array.isArray(kqlQueries)) {
      mustQueries.push(...kqlQueries);
    } else if (kqlQueries && typeof kqlQueries === 'object') {
      mustQueries.push(kqlQueries);
    }
  } else {
    console.log('No KQL found in actualQuery');
  }

  // Build the final query
  let query: any;
  
  // Time range
  const timeRange = actualQuery?.time_range || siemQuery.time_range;
  const timestampFields = [
    '@timestamp',
  ];

  if (mustQueries.length === 0 && shouldQueries.length === 0) {
    query = { match_all: {} };
  } else {
    query = {
      bool: {
        must: mustQueries.length > 0 ? mustQueries : [{ match_all: {} }],
      },
    };
  }

  if (timeRange) {
    const startTime = this.parseTimeRange(timeRange.start || timeRange[0]);
    const endTime = this.parseTimeRange(timeRange.end || timeRange[1]);
    
    const timeFilter = timestampFields.map((field) => ({
      range: {
        [field]: {
          gte: startTime,
          lte: endTime,
        },
      },
    }));

    query.bool.must = [...(query.bool.must || []), ...timeFilter];
  }

  if (shouldQueries.length > 0) {
    query.bool.should = [...(query.bool.should || []), ...shouldQueries];
    query.bool.minimum_should_match = 1;
  }

  const esQuery: any = {
    query,
    size: siemQuery.limit || 100,
  };

  // Aggregation passthrough
  if (actualQuery?.aggregation) {
    if (actualQuery.aggregation.fields && Array.isArray(actualQuery.aggregation.fields)) {
      // Convert fields array to proper Elasticsearch aggregation structure
      const fields = actualQuery.aggregation.fields;
      const limit = actualQuery.aggregation.limit || 100;
      
      esQuery.aggs = {
        grouped_results: {
          terms: {
            field: fields[0] || 'user.name',
            size: limit
          },
          aggs: fields.slice(1).reduce((acc: any, field: any, index: number) => {
            acc[`sub_agg_${index}`] = {
              terms: {
                field: field,
                size: 10
              }
            };
            return acc;
          }, {})
        }
      };
    } else {
      esQuery.aggs = actualQuery.aggregation;
    }
  }

  return esQuery;
}

  generateWazuhQuery(siemQuery: SIEMQuery): any {
    const actualQuery = (siemQuery as any).siemQuery?.query || siemQuery.query || siemQuery;
    return {
      query: actualQuery?.description || actualQuery,
      filters: siemQuery.filters,
      time_range: actualQuery?.time_range || siemQuery.time_range,
      limit: siemQuery.limit || 100,
    };
  }

  normalizeResults(rawResults: any[], source: 'elasticsearch' | 'wazuh'): SIEMEvent[] {
    return rawResults.map((result: any): SIEMEvent => {
      if (source === 'elasticsearch') {
        const sourceData = result._source || result;
        return {
          timestamp: sourceData['@timestamp'] || new Date().toISOString(),
          source: sourceData.host?.name || 'unknown',
          event_type: sourceData.event?.type || 'unknown',
          severity: this.mapElasticsearchSeverity(sourceData.event?.severity || 3),
          description: sourceData.event?.action || sourceData.event?.type || '',
          user: sourceData.user?.name,
          ip_address: sourceData.source?.ip || sourceData.destination?.ip,
          hostname: sourceData.host?.name,
          process: sourceData.process?.name,
          raw_log: JSON.stringify(sourceData),
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

  private mapElasticsearchSeverity(level: number): 'low' | 'medium' | 'high' | 'critical' {
    if (level >= 12) return 'critical';
    if (level >= 8) return 'high';
    if (level >= 4) return 'medium';
    return 'low';
  }

  private mapWazuhSeverity(level: number): 'low' | 'medium' | 'high' | 'critical' {
    if (level >= 12) return 'critical';
    if (level >= 8) return 'high';
    if (level >= 4) return 'medium';
    return 'low';
  }

  private parseTimeRange(timeStr: string): string {
    if (!timeStr) return new Date().toISOString();
    
    const now = new Date();
    
    if (timeStr === 'now') {
      return now.toISOString();
    }
    
    if (timeStr.startsWith('now-')) {
      const match = timeStr.match(/now-(\d+)([dhms])/);
      if (match && match[1] && match[2]) {
        const value = parseInt(match[1]);
        const unit = match[2];
        let agoMs = 0;
        
        switch (unit) {
          case 'd': agoMs = value * 24 * 60 * 60 * 1000; break;
          case 'h': agoMs = value * 60 * 60 * 1000; break;
          case 'm': agoMs = value * 60 * 1000; break;
          case 's': agoMs = value * 1000; break;
        }
        
        return new Date(now.getTime() - agoMs).toISOString();
      }
    }
    
    // If it's already an ISO string, return as-is
    if (timeStr.includes('T') && timeStr.includes('Z')) {
      return timeStr;
    }
    
    // Default to 7 days ago for backward compatibility
    return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  }

  private convertKQLToElasticsearch(kql: string): any {
    try {
      const mustQueries: any[] = [];
      const addedTerms = new Set<string>();
      
      // Handle simple field comparisons
      const fieldPatterns = [
        { pattern: /event\.type == "([^"]+)"/g, field: 'event.type' },
        { pattern: /host\.name == "([^"]+)"/g, field: 'host.name' },
        { pattern: /user\.name == "([^"]+)"/g, field: 'user.name' },
        { pattern: /source\.ip == "([^"]+)"/g, field: 'source.ip' },
        { pattern: /event\.action == "([^"]+)"/g, field: 'event.action' },
        { pattern: /event\.outcome == "([^"]+)"/g, field: 'event.outcome' },
        { pattern: /process\.name == "([^"]+)"/g, field: 'process.name' },
        { pattern: /malware\.name == "([^"]+)"/g, field: 'malware.name' },
      ];

      fieldPatterns.forEach(({ pattern, field }) => {
        let match;
        while ((match = pattern.exec(kql)) !== null) {
          const termKey = `${field}:${match[1]}`;
          if (!addedTerms.has(termKey)) {
            addedTerms.add(termKey);
            mustQueries.push({
              term: {
                [field]: match[1]
              }
            });
          }
        }
      });

      // Handle range queries for severity
      const severityMatch = kql.match(/event\.severity (>=|<=|>|<|==) (\d+)/);
      if (severityMatch && severityMatch[1] && severityMatch[2]) {
        const operator = severityMatch[1];
        const value = parseInt(severityMatch[2]);
        const rangeQuery: any = {};
        
        switch (operator) {
          case '>=': rangeQuery.gte = value; break;
          case '<=': rangeQuery.lte = value; break;
          case '>': rangeQuery.gt = value; break;
          case '<': rangeQuery.lt = value; break;
          case '==': rangeQuery.gte = value; rangeQuery.lte = value; break;
        }
        
        mustQueries.push({
          range: {
            'event.severity': rangeQuery
          }
        });
      }

      // Handle AND/OR logic
      if (kql.includes(' and ')) {
        // For AND conditions, we already have multiple mustQueries
        // No additional processing needed
      } else if (kql.includes(' or ')) {
        // Convert to should queries if needed
        const orQueries = kql.split(' or ').map(part => {
          const partQueries: any[] = [];
          fieldPatterns.forEach(({ pattern, field }) => {
            let match;
            const partPattern = new RegExp(pattern.source, 'g');
            while ((match = partPattern.exec(part)) !== null) {
              partQueries.push({
                term: {
                  [field]: match[1]
                }
              });
            }
          });
          return partQueries.length > 0 ? partQueries : null;
        }).filter(Boolean);

        if (orQueries.length > 1) {
          return [{
            bool: {
              should: orQueries.flat(),
              minimum_should_match: 1
            }
          }];
        }
      }
      
      // If we have specific queries, return them
      if (mustQueries.length > 0) {
        return mustQueries;
      }
      
      // Default fallback for complex queries
      return [
        {
          query_string: {
            query: kql.replace(/SecurityEvent\s*\|\s*where\s+/g, '').replace(/\s*\|\s*/g, ' AND ')
          }
        }
      ];
      
    } catch (error) {
      console.error('Error converting KQL to Elasticsearch:', error);
      return null;
    }
  }
}
