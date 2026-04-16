# Source: https://docs.cloud.google.com/chronicle/docs/investigation/investigate-file

# Investigate a file
Supported in:    Google secops   SIEM
You can use Google Security Operations to search your data for a specific file based on its MD5, SHA-1, or SHA-256 hash value.
If additional information is available for a file hash found within a customer's Google SecOps account, this additional information is added to the associated UDM events automatically. You can search for these UDM events manually using UDM Search or by using rules.
## View a file hash
To view a file hash, you can:
View a file in File hash view directly
Navigate to File hash view from another view
## View a file in File hash view directly
To open File hash view directly, enter the hash value in the Google SecOps search field and click Search. Note: UDM search provides enhanced capabilities that let you conduct more thorough investigatzions of the events and alerts within your Google SecOps instance than is possible using File hash view alone. For more information, see UDM search.
Google SecOps provides additional information about the file, including the following:
Partner engines detecting: Other security vendors who have detected the file.
Properties/metadata: Known properties of the file.
VT submitted/ITW filenames: Known malicious in-the-wild (ITW) malware submitted to VirusTotal.
## Navigate to File hash view from another view
You can also navigate to File hash view while investigating an asset in an another view (for example, Asset view) by completing the following steps:
Open an investigation view. For example, select an asset to view it within Asset view.
In the Timeline to the left, scroll to any event tied to a process or file modification, such as Network Connection.
Selecting an Event in Asset view
Open the Raw Log and UDM viewer by clicking the open icon in the Timeline.
You can open File hash view for the file by clicking the hash value (for example, principal.process.file.md5) within the displayed UDM event.
## Considerations
Hash view has the following limitations:  You can only filter events that are displayed in this view. Only DNS, EDR, Webproxy, and Alert event types are populated in this view. The first seen and last seen information populated in this view is also limited to these event types. Generic events don't appear in any of the curated views. They appear only in raw log and UDM searches.