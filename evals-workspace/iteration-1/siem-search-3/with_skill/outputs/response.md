# SecOps SIEM Query: Login Followed by File Deletion

## Query

```
events:
    $user = $e1.principal.user.userid
    $login_host = $e1.principal.hostname
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"

    $user = $e2.principal.user.userid
    $file_path = $e2.target.file.full_path
    $e2.metadata.event_type = "FILE_DELETION"

match:
    $user over 30m

condition:
    $e1 and $e2
```

## Results Format

The query returns:
- **Username** (`$user`): The userid matching between login and file deletion events
- **Login Host** (`$login_host`): The hostname where the user successfully logged in
- **Deleted File Path** (`$file_path`): The full path of the file that was deleted

## Explanation

1. **Event 1 ($e1)**: Captures successful user logins
   - Filters for `USER_LOGIN` events with `ALLOW` action
   - Extracts username and hostname

2. **Event 2 ($e2)**: Captures file deletion events
   - Filters for `FILE_DELETION` events
   - Extracts the file path

3. **Join Key**: Username (`$user`) must match between both events

4. **Time Window**: 30-minute correlation window (`over 30m`) ensures the file deletion occurs within 30 minutes of the login

5. **Condition**: Both events must be present (`$e1 and $e2`)

This query identifies potentially suspicious activity where a user logs in and immediately deletes files, which could indicate unauthorized access or data exfiltration attempts.
