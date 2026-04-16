# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/request-log-type

# Request prebuilt and create custom log types
Supported in:    Google secops   SIEM
This document describes options to help you process log data that isn't processed by existing Google Security Operations parsers. In such cases, Google SecOps supports the creation of log types to enable parsing and ingestion.
You can choose between the following log types:
## Prebuilt log types
This path is for formats you want to contribute as a platform standard, making them available to all Google SecOps customers.
If the log type is meant for internal use in your tenant, we recommend using a custom log type (even if the product is commercial).
If needed, you can send a request to Google SecOps to have a prebuilt log type added to the platform:    Action item Process and timeline     Request a new log type Contact your Google account manager or support representative to submit the request. Once approved, the new prebuilt log type is available to all Google SecOps customers.   Request a new prebuilt parser Google manages a new, prebuilt parser request as a new Feature Request, which is part of the product backlog.    Note: Because the parser request isn't picked up immediately, we strongly advise you to configure your own custom parser for the new log type to enable immediate ingestion and use.
## Custom log types
This path is recommended for proprietary or tenant-specific logs where speed and privacy are key.
Recommendation: Use a custom log type if the format is intended only for internal use within your tenant, even if the source product is commercial.
Ownership: Created and fully managed by your organization.
Parser requirement: You must configure the corresponding custom parsers in-house.
Availability: The custom log types and parsers become available only to your organization approximately 10 minutes after creation.
For information about corresponding prebuilt parsers and custom parsers, see Manage prebuilt and custom parsers.
## Create a custom log type
To create a custom log type, do the following:
Go to SIEM settings > Available Log Types. You can view available log types using the Search feature.
Click Request a Log Type.
Under the Create a custom log type on your own, enter details for your log type.
For example, to create a custom log type for Azure Key Vault logging, complete the following:
In the Vendor/Product field, enter `Azure Key Vault logging`.
In the Log Type field, enter `AZURE_KEYVAULT_LOGGING`.
Click Create Log Type. Note that the `_CUSTOM`suffix is added to the log type.
Wait 10 minutes to ensure that the new log type is available in all components before creating feeds with it.
The custom log type limitations are:
Total: 400
Daily: 25
Hourly: 8