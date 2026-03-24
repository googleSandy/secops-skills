# SecOps SIEM Network Connection Statistics Query

## Query Purpose
Analyze network connection activity grouped by source IP address to identify communication patterns, volume, and frequency across the network.

## Query

```sql
SELECT
  source_ip,
  COUNT(*) as event_count,
  SUM(bytes_sent) as total_bytes_sent,
  ROUND(AVG(bytes_sent), 2) as avg_bytes_sent
FROM
  network_connections
WHERE
  event_timestamp >= TIMESTAMP_SUB(NOW(), INTERVAL 24 HOUR)
  AND event_type = 'connection'
GROUP BY
  source_ip
ORDER BY
  event_count DESC
LIMIT 1000
```

## Query Breakdown

### SELECT Clause
- **source_ip**: The source IP address initiating the network connection
- **event_count**: Total number of connection events from the source IP (using COUNT(*))
- **total_bytes_sent**: Aggregate bytes transmitted from the source IP (using SUM)
- **avg_bytes_sent**: Average bytes per event from the source IP (using AVG, rounded to 2 decimals)

### WHERE Clause
- **event_timestamp**: Filters to events from the last 24 hours (configurable time window)
- **event_type = 'connection'**: Ensures only network connection events are included

### GROUP BY
- Groups all metrics by source IP to show per-IP statistics

### ORDER BY
- **event_count DESC**: Results sorted by event frequency in descending order, highlighting the most active source IPs

## Use Cases
- **Threat Detection**: Identify anomalous communication patterns and potential lateral movement
- **Network Baseline**: Establish baseline communication volumes by source IP
- **Security Investigation**: Quickly find sources generating unusual traffic volumes
- **Performance Monitoring**: Track high-bandwidth source IPs for network optimization

## Sample Output
```
source_ip        | event_count | total_bytes_sent | avg_bytes_sent
-----------------+-------------+------------------+---------------
192.168.1.100    | 2543        | 8524987          | 3352.49
192.168.1.105    | 1987        | 6234156          | 3137.45
10.0.0.50        | 1654        | 4567890          | 2761.14
192.168.1.200    | 1432        | 3198765          | 2232.75
10.0.0.75        | 987         | 2156789          | 2186.25
```

## Query Customization Options

### Time Window Adjustment
Change the interval in the WHERE clause:
- Last hour: `INTERVAL 1 HOUR`
- Last 7 days: `INTERVAL 7 DAY`
- Last 30 days: `INTERVAL 30 DAY`

### Add Additional Filters
- By destination IP: `AND destination_ip = '10.0.0.x'`
- By protocol: `AND protocol IN ('TCP', 'UDP')`
- By port: `AND destination_port = 443`
- By source subnet: `AND source_ip LIKE '192.168.1.%'`

### Enhance Metrics
- Add destination port: `destination_port,`
- Add packet count: `COUNT(DISTINCT packet_id) as packet_count,`
- Add unique destinations: `COUNT(DISTINCT destination_ip) as unique_destinations,`
- Add connection duration: `AVG(connection_duration_seconds) as avg_duration_secs,`
