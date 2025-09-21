# Elasticsearch Seeding Script

This script populates Elasticsearch with mock SIEM (Security Information and Event Management) data for testing and development purposes.

## Usage

```bash
# Seed with default 1000 events
bun run seed

# Seed with custom number of events
bun run seed 5000
```

## Features

- **Realistic SIEM Events**: Generates 8 different types of security events:

  - Authentication events
  - File access events
  - Network connection events
  - Process execution events
  - Privilege escalation events
  - Malware detection events
  - Data exfiltration events
  - System reboot events

- **Varied Data Sources**: Events from multiple sources like Windows Security, Linux Audit, Firewall, IDS/IPS, etc.

- **Proper Index Mapping**: Creates Elasticsearch index with appropriate field mappings for SIEM data

- **Bulk Indexing**: Efficiently indexes data in batches of 100 events

## Configuration

The script uses the same Elasticsearch configuration as your main application:

- `ELASTICSEARCH_URL` (default: http://localhost:9200)
- `ELASTICSEARCH_USERNAME` (optional)
- `ELASTICSEARCH_PASSWORD` (optional)
- `ELASTICSEARCH_INDEX` (default: siem-logs)

## Generated Data Structure

Each event includes:

- `timestamp`: Random timestamp within last 30 days
- `source`: Security system source
- `event_type`: Type of security event
- `severity`: low, medium, high, or critical
- `description`: Detailed event description
- `user`: Associated user (optional)
- `ip_address`: IP address (optional)
- `hostname`: Server hostname (optional)
- `process`: Process name (optional)
- `raw_log`: Full log entry

## Requirements

- Elasticsearch instance running and accessible
- Proper environment configuration
- Bun runtime
