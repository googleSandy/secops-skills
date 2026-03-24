# Windows Event Logs metadata.log_type Value for SecOps SIEM

To search Windows Event Logs in SecOps SIEM, use one of the following `metadata.log_type` values:

## Primary Options (Premium License Required)

- **`WINEVTLOG`** - Windows Event (standard format)
- **`WINEVTLOG_XML`** - Windows Event (XML format)

## Alternative Options (Standard License)

- **`WINDOWS_SYSMON`** - Windows Sysmon (requires premium license)
- Various Windows-specific log types from the standard tier:
  - `WINDOWS_APPLOCKER` - Windows Applocker logs
  - `WINDOWS_DEFENDER_ATP` - Windows Defender ATP
  - `WINDOWS_DEFENDER_AV` - Windows Defender AV
  - `WINDOWS_FIREWALL` - Windows Firewall logs
  - `WINDOWS_HYPERV` - Windows Hyper-V logs
  - `WINDOWS_NET_POLICY_SERVER` - Windows Network Policy Server

## Recommendation

For general Windows Event Logs, use:
- **`WINEVTLOG`** (standard Windows Event format)
- **`WINEVTLOG_XML`** (if logs are in XML format)

Both require a premium SecOps license tier. Confirm availability in your instance before building queries or rules against these log types.

### Sources
- [SecOps Standard Log Types](../../references/standard-log-types.md)
- [SecOps Premium Log Types](../../references/premium-log-types.md)
- Chronicle Ingestion Documentation: https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/default-parser-configuration
