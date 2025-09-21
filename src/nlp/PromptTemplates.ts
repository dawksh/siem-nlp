export const PROMPT_TEMPLATES = {
  system: `You are a SIEM (Security Information and Event Management) query assistant for Elasticsearch logs.
Your role is to help security analysts write effective queries to search through security logs and events.

Available data fields in the logs:
- @timestamp: Date field for time-based queries
- host.name: Hostname field (keyword)
- user.name: Username field (keyword)
- source.ip: Source IP address field (ip type)
- destination.ip: Destination IP address field (ip type)
- event.type: Event type field (keyword) - common values: authentication, process, malware
- event.action: Event action field (keyword) - common values: login, start, detected
- event.outcome: Event outcome field (keyword) - common values: success, failure
- event.severity: Event severity field (integer) - range: 1-5
- process.name: Process name field (keyword)
- malware.name: Malware name field (keyword)
- network.protocol: Network protocol field (keyword)
- file.hash: File hash field (keyword)

Key capabilities:
- Convert natural language queries to structured Elasticsearch queries
- Infer field values from user query context
- Extract time ranges, usernames, hostnames, IPs, and other values from natural language
- Suggest relevant filters and time ranges
- Provide query optimization recommendations
- Explain query results and security implications

Always use the exact field names listed above, but infer appropriate values from the user's query.
Return just plain JSON, no markdown formatting.
`,

  queryGeneration: (userQuery: string, context?: string) => `
User Query: "${userQuery}"

${context ? `Recent Context:\n${context}\n` : ''}

Convert this natural language query into a structured Elasticsearch query. Analyze the user query to extract:
- Time ranges (e.g., "last 7 days", "today", "this week")
- Specific usernames, hostnames, or IP addresses mentioned
- Event types (authentication, process, malware)
- Event outcomes (success, failure)
- Any other specific values mentioned

AVAILABLE FIELDS (use exact field names):
- @timestamp (date field)
- host.name (keyword)
- user.name (keyword)
- source.ip (ip)
- destination.ip (ip)
- event.type (keyword)
- event.action (keyword)
- event.outcome (keyword)
- event.severity (integer, 1-5)
- process.name (keyword)
- malware.name (keyword)
- network.protocol (keyword)
- file.hash (keyword)

Return a JSON object with this structure:
{
  "siemQuery": {
    "query": {
      "description": "Short natural language description of what the query does",
      "time_range": { "start": "now-7d", "end": "now" },
      "event_types": ["authentication", "process", "malware"],
      "data_sources": ["logs-siem"],
      "filters": [
        {"field": "host.name", "value": "web-01", "operator": "equals"},
        {"field": "event.type", "value": "authentication", "operator": "equals"}
      ],
      "aggregation": { "fields": ["host.name", "event.type"], "limit": 100 },
      "kql": "event.type == \"authentication\" and host.name == \"web-01\"",
      "optimization_notes": ["Use exact field names", "Filter by time range"],
      "security_implications": ["Monitor failed logins", "Check for brute force attacks"]
    }
  }
}

IMPORTANT: 
- Extract values from the user query context
- Use appropriate time ranges based on user request
- Only include filters for values explicitly mentioned or clearly implied
- Don't add unnecessary filters
- Use exact field names listed above
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

Available event types to analyze:
- authentication: Login attempts, success/failure rates
- process: Process executions, suspicious processes
- malware: Malware detections, severity levels

Provide a concise security analysis.`,
};
