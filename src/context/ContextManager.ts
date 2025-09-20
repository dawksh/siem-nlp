import { SIEMEvent, SIEMQuery } from '../config/schema';

export class ContextManager {
  private conversationHistory: Array<{
    role: 'user' | 'assistant';
    content: string;
    timestamp: Date;
    query?: SIEMQuery;
    results?: SIEMEvent[];
  }> = [];

  addMessage(role: 'user' | 'assistant', content: string, query?: SIEMQuery, results?: SIEMEvent[]) {
    this.conversationHistory.push({
      role,
      content,
      timestamp: new Date(),
      query,
      results,
    });
  }

  getRecentContext(limit: number = 10) {
    return this.conversationHistory.slice(-limit);
  }

  getQueryHistory() {
    return this.conversationHistory
      .filter(msg => msg.query)
      .map(msg => ({
        query: msg.query,
        results: msg.results,
        timestamp: msg.timestamp,
      }));
  }

  clearHistory() {
    this.conversationHistory = [];
  }

  getContextSummary() {
    const recentEvents = this.conversationHistory
      .flatMap(msg => msg.results || [])
      .slice(-50);
    
    const eventTypes = new Set(recentEvents.map(e => e.event_type));
    const sources = new Set(recentEvents.map(e => e.source));
    
    return {
      totalEvents: recentEvents.length,
      eventTypes: Array.from(eventTypes),
      sources: Array.from(sources),
      recentSeverities: recentEvents.map(e => e.severity),
    };
  }
}
