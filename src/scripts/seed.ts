import { ElasticConnector } from '../connectors/ElasticConnector';
import { config } from '../config/settings';
import type { SIEMEvent } from '../config/schema';

const generateMockEvent = (): SIEMEvent => {
  const eventTypes = [
    'authentication', 'file_access', 'network_connection', 'process_execution',
    'privilege_escalation', 'malware_detection', 'data_exfiltration', 'system_reboot'
  ];
  
  const sources = [
    'Windows Security', 'Linux Audit', 'Firewall', 'IDS/IPS', 'Antivirus',
    'Database', 'Web Server', 'Mail Server', 'DNS Server', 'VPN Gateway'
  ];
  
  const severities: ('low' | 'medium' | 'high' | 'critical')[] = ['low', 'medium', 'high', 'critical'];
  
  const users = ['admin', 'john.doe', 'jane.smith', 'service.account', 'guest', 'root'];
  const hosts = ['web-server-01', 'db-server-02', 'mail-server-03', 'file-server-04', 'monitoring-05'];
  const processes = ['explorer.exe', 'sshd', 'nginx', 'mysql', 'postgresql', 'apache2'];
  
  const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)]!;
  const source = sources[Math.floor(Math.random() * sources.length)]!;
  const severity = severities[Math.floor(Math.random() * severities.length)]!;
  
  const timestamp = new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000);
  
  const descriptions: Record<string, string[]> = {
    authentication: [
      'Successful login attempt',
      'Failed login attempt - invalid credentials',
      'User account locked due to multiple failed attempts',
      'Password change successful',
      'Multi-factor authentication required'
    ],
    file_access: [
      'File created successfully',
      'Unauthorized file access attempt',
      'File deleted by user',
      'File permissions modified',
      'Sensitive file accessed'
    ],
    network_connection: [
      'Outbound connection established',
      'Inbound connection blocked by firewall',
      'Suspicious network activity detected',
      'VPN connection established',
      'Connection to malicious IP address blocked'
    ],
    process_execution: [
      'Process started successfully',
      'Unauthorized process execution blocked',
      'Process terminated abnormally',
      'Privileged process executed',
      'Suspicious process behavior detected'
    ],
    privilege_escalation: [
      'User granted administrative privileges',
      'Unauthorized privilege escalation attempt',
      'Service account elevated permissions',
      'Root access granted',
      'Suspicious privilege escalation detected'
    ],
    malware_detection: [
      'Malware signature detected',
      'Suspicious file quarantined',
      'Trojan horse identified and removed',
      'Ransomware attack prevented',
      'Malicious script execution blocked'
    ],
    data_exfiltration: [
      'Large data transfer detected',
      'Suspicious data access pattern',
      'Unauthorized data export attempt',
      'Sensitive data accessed',
      'Data breach attempt detected'
    ],
    system_reboot: [
      'System reboot initiated by user',
      'System reboot due to maintenance',
      'Emergency system reboot',
      'System reboot after security update',
      'System reboot due to power failure'
    ]
  };
  
  const description = descriptions[eventType]![Math.floor(Math.random() * descriptions[eventType]!.length)]!;
  
  const event: SIEMEvent = {
    timestamp: timestamp.toISOString(),
    source: source,
    event_type: eventType,
    severity: severity,
    description: description,
    raw_log: `[${timestamp.toISOString()}] ${source}: ${description} - Event ID: ${Math.floor(Math.random() * 10000)} - Severity: ${severity.toUpperCase()}`
  };
  
  if (Math.random() > 0.3) {
    event.user = users[Math.floor(Math.random() * users.length)]!;
  }
  
  if (Math.random() > 0.4) {
    event.ip_address = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  }
  
  if (Math.random() > 0.2) {
    event.hostname = hosts[Math.floor(Math.random() * hosts.length)]!;
  }
  
  if (Math.random() > 0.5) {
    event.process = processes[Math.floor(Math.random() * processes.length)]!;
  }
  
  return event;
};

const createIndex = async (connector: ElasticConnector): Promise<void> => {
  const indexName = config.elasticsearch.index;
  
  const indexMapping = {
    mappings: {
      properties: {
        timestamp: { type: 'date' },
        source: { type: 'keyword' },
        event_type: { type: 'keyword' },
        severity: { type: 'keyword' },
        description: { type: 'text' },
        user: { type: 'keyword' },
        ip_address: { type: 'ip' },
        hostname: { type: 'keyword' },
        process: { type: 'keyword' },
        raw_log: { type: 'text' }
      }
    },
    settings: {
      number_of_shards: 1,
      number_of_replicas: 0
    }
  };
  
  try {
    const response = await fetch(`${config.elasticsearch.url}/${indexName}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        ...(config.elasticsearch.username && config.elasticsearch.password ? {
          'Authorization': `Basic ${btoa(`${config.elasticsearch.username}:${config.elasticsearch.password}`)}`
        } : {})
      },
      body: JSON.stringify(indexMapping)
    });
    
    if (response.ok) {
      console.log(`✅ Index '${indexName}' created successfully`);
    } else if (response.status === 400) {
      console.log(`ℹ️  Index '${indexName}' already exists`);
    } else {
      throw new Error(`Failed to create index: ${response.statusText}`);
    }
  } catch (error) {
    console.error('❌ Error creating index:', error);
    throw error;
  }
};

const bulkIndexEvents = async (connector: ElasticConnector, events: SIEMEvent[]): Promise<void> => {
  const indexName = config.elasticsearch.index;
  const bulkBody = events.flatMap(event => [
    { index: { _index: indexName } },
    event
  ]);
  
  try {
    const response = await fetch(`${config.elasticsearch.url}/_bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-ndjson',
        ...(config.elasticsearch.username && config.elasticsearch.password ? {
          'Authorization': `Basic ${btoa(`${config.elasticsearch.username}:${config.elasticsearch.password}`)}`
        } : {})
      },
      body: bulkBody.map(item => JSON.stringify(item)).join('\n') + '\n'
    });
    
    if (!response.ok) {
      throw new Error(`Bulk indexing failed: ${response.statusText}`);
    }
    
    const result = await response.json();
    if (result.errors) {
      console.error('❌ Some documents failed to index:', result.items.filter((item: any) => item.index.error));
    }
    
    console.log(`✅ Successfully indexed ${events.length} events`);
  } catch (error) {
    console.error('❌ Error during bulk indexing:', error);
    throw error;
  }
};

const main = async (): Promise<void> => {
  console.log('🚀 Starting Elasticsearch seeding process...');
  
  const connector = new ElasticConnector();
  
  try {
    const isConnected = await connector.testConnection();
    if (!isConnected) {
      throw new Error('❌ Cannot connect to Elasticsearch. Please check your configuration.');
    }
    console.log('✅ Connected to Elasticsearch');
    
    await createIndex(connector);
    
    const eventCount = parseInt(process.argv[2] || '1000');
    console.log(`📊 Generating ${eventCount} mock events...`);
    
    const events: SIEMEvent[] = [];
    for (let i = 0; i < eventCount; i++) {
      events.push(generateMockEvent());
    }
    
    const batchSize = 100;
    for (let i = 0; i < events.length; i += batchSize) {
      const batch = events.slice(i, i + batchSize);
      await bulkIndexEvents(connector, batch);
      console.log(`📈 Progress: ${Math.min(i + batchSize, events.length)}/${events.length} events indexed`);
    }
    
    console.log('🎉 Seeding completed successfully!');
    
    const indices = await connector.getIndices();
    console.log(`📋 Available indices: ${indices.join(', ')}`);
    
  } catch (error) {
    console.error('💥 Seeding failed:', error);
    process.exit(1);
  }
};

if (import.meta.main) {
  main();
}
