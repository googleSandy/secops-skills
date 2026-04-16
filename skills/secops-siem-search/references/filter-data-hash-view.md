# Source: https://docs.cloud.google.com/chronicle/docs/investigation/filter-data-hash-view

# Filter data in Hash view
Supported in:    Google secops   SIEM
Hash view lets you search and investigate files based on their hash value.
## Open Hash view
You can open Hash view the following ways:  Search for the file hash directly Pivot to Hash view when viewing a process- or file-based event in Asset view
### Search for the file hash directly
To open Hash view directly:
Enter the hash value in the Google Security Operations search field. Click Search.
Select the hash value from the Hashes menu. Hash view is displayed.
### Navigate to Hash view from Asset view
You can also navigate to Hash view while investigating an asset in Asset view.
Search for an asset and view it in Asset view. Asset view is displayed.
From the Timeline tab to the left, scroll to any event tied to a process or file modification, such as PROCESS_LAUNCH. Note: If you are not able to locate PROCESS_LAUNCH in the Event column, change the start-date on the top left corner to a few days previous to the present date. Also, slide the Time slider on the top right corner to 1 Day. Doing this will refresh the Timeline panel and display the other required events.
Expand the file to view details and investigate.
You can open Hash view for the file by clicking the hash value in Asset view. Hash view is displayed.
## Filter options in Hash view
The following Procedural Filtering options are available in Hash view:  ASSETS EVENT TYPE LOG SOURCE PID PROCESS NAME