# SecOps SIEM Network Connection Activity Query

## Query

```
metadata.event_type = "NETWORK_CONNECTION"
$source_ip = principal.ip

match:
    $source_ip

outcome:
    $event_count = count(metadata.id)
    $total_bytes_sent = sum(network.sent_bytes)
    $avg_bytes_sent = math.round(avg(network.sent_bytes), 2)

order:
    $event_count desc
```

## Query Explanation

- **Filter**: Selects only NETWORK_CONNECTION events
- **Variable Assignment**: `$source_ip = principal.ip` extracts the source IP address from each event
- **Match**: Groups results by source IP
- **Outcome Metrics**:
  - `$event_count`: Total number of network connection events per source IP
  - `$total_bytes_sent`: Sum of all bytes sent from each source IP
  - `$avg_bytes_sent`: Average bytes sent per connection (rounded to 2 decimal places)
- **Order**: Results sorted by event count in descending order (most active IPs first)

## Output

The query returns a table showing:
- Source IP
- Total network connection events
- Total bytes sent
- Average bytes sent per event
