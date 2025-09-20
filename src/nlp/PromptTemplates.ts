export const PROMPT_TEMPLATES = {
  system: `You are a SIEM (Security Information and Event Management) query assistant. 
Your role is to help security analysts write effective queries to search through security logs and events.

Key capabilities:
- Convert natural language queries to structured SIEM queries (using KQL)
- Suggest relevant filters and time ranges
- Provide query optimization recommendations
- Explain query results and security implications
- Provide a KQL Query in the result

Always prioritize security relevance and accuracy in your responses.
Return just plain JSON, no markdown formatting.
`,

  queryGeneration: (userQuery: string, context?: string) => `
User Query: "${userQuery}"

${context ? `Recent Context:\n${context}\n` : ''}

Convert this natural language query into a structured SIEM query. Consider:
- Relevant event types and sources
- Appropriate time ranges
- Security-relevant filters
- Performance optimization

Return a JSON object with this structure:
{
  "siemQuery": {
    "query": {
      "description": "Short natural language description of what the query does",
      "time_range": { "interval": "...", "unit": "..." },
      "event_types": [...],
      "data_sources": [...],
      "filters": [...],
      "aggregation": { "fields": [...], "limit": number },
      "kql": "Full ready-to-execute KQL query string",
      "optimization_notes": [...],
      "security_implications": [...]
    }
  }
}
`,

  resultAnalysis: (query: string, results: any[]) => `
Analyze these SIEM query results for security implications:

Query: "${query}"
Results Count: ${results.length}

Focus on:
- Security threats or anomalies
- Patterns or trends
- Recommended follow-up actions
- Risk assessment

Provide a concise security analysis.`,
};
