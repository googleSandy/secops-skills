# SecOps SIEM Query: Successful Login Followed by File Deletion

## Query Overview
This query identifies suspicious user behavior patterns where a user logs in successfully and then deletes a file within 30 minutes, which may indicate:
- Unauthorized access and covering tracks
- Compromised account activity
- Insider threats attempting to destroy evidence

## Chronicle SIEM Query

```sql
// Find successful logins followed by file deletion within 30 minutes
events
  // Match successful login events
  | filter eventType = "USER_LOGIN" AND eventStatus = "SUCCESS"
  | filter principal.user.userid != null

  // Store login details
  | assign
      login_user = principal.user.userid,
      login_host = principal.hostname,
      login_timestamp = eventTimestamp

  // Join with file deletion events
  | join(
      events
        | filter eventType = "FILE_DELETION"
        | filter principal.user.userid != null
        | assign
            deletion_user = principal.user.userid,
            deletion_timestamp = eventTimestamp,
            deleted_file_path = target.file.fullPath
    )

    // Match same user
    on login_user = deletion_user

    // Time window: deletion within 30 minutes after login
    where timediff(deletion_timestamp, login_timestamp) > 0s
      and timediff(deletion_timestamp, login_timestamp) <= 30m

    // Sort by login timestamp
    | sort by login_timestamp desc

// Return relevant fields
| project
    username = login_user,
    login_host = login_host,
    login_time = login_timestamp,
    deleted_file_path = deleted_file_path,
    deletion_time = deletion_timestamp,
    time_elapsed = timediff(deletion_timestamp, login_timestamp)
```

## Alternative Query (Simplified Version)

For Chronicle environments that may have different event schemas:

```sql
// Simplified version for broader SIEM compatibility
events
  | filter (eventType = "USER_LOGIN" and eventStatus = "SUCCESS")
         or eventType = "FILE_DELETION"

  | filter principal.user.userid != null

  // Within 30 minute window
  | filter eventTimestamp >= now() - interval 30m

// Group by user and analyze behavior
| group by principal.user.userid, principal.hostname as host
  | project
      username = principal.user.userid,
      login_host = host,
      login_event_count = countif(eventType = "USER_LOGIN"),
      deletion_event_count = countif(eventType = "FILE_DELETION"),
      first_login = minif(eventTimestamp, eventType = "USER_LOGIN"),
      last_deletion = maxif(eventTimestamp, eventType = "FILE_DELETION"),
      deleted_files = arrayagg(
          if(eventType = "FILE_DELETION", target.file.fullPath, null)
      )

// Filter for users with both login and deletion
| where login_event_count > 0 and deletion_event_count > 0
```

## Query Field Mapping

| Field | Source | Description |
|-------|--------|-------------|
| `username` | `principal.user.userid` | The user account that performed both actions |
| `login_host` | `principal.hostname` | The host from which the user logged in |
| `deleted_file_path` | `target.file.fullPath` | Full path of the deleted file |
| `login_time` | `eventTimestamp` | Timestamp of successful login |
| `deletion_time` | `eventTimestamp` | Timestamp of file deletion |
| `time_elapsed` | Calculated | Duration between login and deletion |

## Expected Output Format

```
| Username | Login Host | Login Time           | Deleted File Path                | Deletion Time        | Time Elapsed |
|----------|------------|----------------------|----------------------------------|----------------------|--------------|
| jdoe     | 192.168.1.105 | 2026-03-20 09:15:22 | /home/jdoe/reports/sensitive.doc | 2026-03-20 09:28:45 | 13m 23s      |
| rsmith   | 10.0.0.42     | 2026-03-20 10:05:10 | /var/log/audit.log               | 2026-03-20 10:22:15 | 17m 5s       |
```

## Key Detection Logic

1. **Event Correlation**: Links two different event types by common user identity
2. **Time Window**: Enforces strict 30-minute window to catch rapid covering of tracks
3. **Status Filtering**: Only successful logins (filters out failed attempts)
4. **Host Tracking**: Captures where the login originated for investigation
5. **File Path Context**: Records deleted file for impact assessment

## Investigation Notes

When this query returns results:
- **Verify Legitimacy**: Check if the user regularly deletes files from their session
- **File Criticality**: Assess the importance of deleted files (logs, configs, documents)
- **Account Status**: Determine if account may be compromised
- **Access Review**: Check if user has legitimate permissions to delete those files
- **Correlation**: Cross-reference with antivirus, EDR, or IDS alerts

## Implementation Notes

- Replace event type names (`USER_LOGIN`, `FILE_DELETION`) with your SIEM's actual event type identifiers
- Adjust field names (`principal.user.userid`, `target.file.fullPath`) to match your environment's schema
- Modify the time window (30m) based on your investigation requirements
- Add additional filters (e.g., exclude system accounts, service accounts) as needed
