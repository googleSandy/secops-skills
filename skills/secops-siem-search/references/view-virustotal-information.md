# Source: https://docs.cloud.google.com/chronicle/docs/investigation/view-virustotal-information

# View information from VirusTotal
Supported in:    Google secops   SIEM
Use Google Security Operations's integration with VirusTotal to pivot from finding domains linked to an asset in Google SecOps to viewing information about that domain from VirusTotal and launching VirusTotal Graph.
VirusTotal Graph is a visualization tool built on top of the VirusTotal dataset. It analyzes the relationship between files, URLs, domains, IP addresses, and other items encountered. VirusTotal Graph helps to illustrate the interconnections between potentially malicious domains and the assets within your enterprise. Note: Some of the VirusTotal information is only available with a VirusTotal Enterprise account.
To view the VirusTotal Context for a domain, complete the following steps: Note: The same steps apply for IP address and file or hash views.
Search for a suspicious domain in Google SecOps. Select the domain in the search results to open Domain view.
Click VT CONTEXT at the top of Domain view to open the VT Context window. The numbers next to VT CONTEXT indicate the number of security vendors that have flagged this domain as malicious.
Domain view with VT CONTEXT option
The VT Context window opens to the Detections tab. This tab displays more information from VirusTotal with regards to what is known about this domain, for example, whether or not the domain is malicious.
Detections tab
Click the IoCs tab to view any of the IoCs VirusTotal has in its database for this domain. To view the VirusTotal IoCs, you must be signed you must have a VirusTotal Enterprise account. Enter your VirusTotal login credentials when asked.
IoCs tab
Click the Graph tab to open the control to launch VirusTotal Graph. To use VirusTotal Graph, you must have a VirusTotal Enterprise account. Enter your VirusTotal login credentials when asked.
VirusTotal Graph