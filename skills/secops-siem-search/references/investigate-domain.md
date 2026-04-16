# Source: https://docs.cloud.google.com/chronicle/docs/investigation/investigate-domain

# Investigate a domain
Supported in:    Google secops   SIEM
Google Security Operations lets you to investigate specific domains to determine if any are present within your enterprise, and what impact these outside systems might have had on your assets.
To access Domain view in Google SecOps, complete the following steps:
Enter the domain (ending with a known public suffix) or URL in the search bar on the Google SecOps landing page. Note: The public suffix data list from publicsuffix.org includes both public and private domains as public suffixes. However, this function doesn't treat a private domain as a public suffix. For example, if us.com is listed as a private domain, calling the function with foo.us.com returns us.com—interpreted as the public suffix com plus the preceding label us—instead of foo.us.com (which would treat us.com as a private domain).
Click Search. If the domain is present in your enterprise, it is listed under the Domains heading. Click the domain name link to pivot to Domain view. If the domain is present within your enterprise, additional information is displayed in Domain view. If the domain is not present, Domain view will be empty. Note: UDM search provides enhanced capabilities that let you conduct more thorough investigations of the events and alerts within your Google SecOps instance than is possible using Domain view alone. For more information, see UDM search.
## Domain context
Domain view displays context about the queried domain, to include references in ingested log data as well as third-party and external enrichments from sources like VirusTotal.
#### VT Context
Click VT Context to view the VirusTotal information available for this domain.
#### WHOIS
Google SecOps displays the WHOIS information associated with the registered domain. This information can be useful when assessing a domain's reputation.
#### Prevalence
Google SecOps provides a graphical representation of the historical prevalence of a given FQDN and its TLD. This graph can be used to determine whether the domain has been accessed from within the enterprise before, and can provide an indication of whether the domain is associated with a particular campaign targeting the enterprise. Typically, less prevalent domains, ones that fewer assets have connected to, might represent a greater threat to your enterprise.
When you hold the pointer over a bar in the Prevalence graph, the graph lists the assets that accessed the domain. Due to the high prevalence of DNS servers, they aren't listed. If all of the assets are DNS servers, no assets are listed.
#### Domain insights
Domain insights provide you with more context about domains under investigation. You can use them to determine whether a domain is benign or malicious. They also let you further investigate an indicator to determine if there is a broader compromise.
The domain insights displayed vary depending on the availability of information associated with the domain within your Google SecOps account, but might include the following:
ET Intelligence Rep List: Checks against ProofPoint's Emerging Threats (ET) Intelligence Rep List and lists known threats tied to specific IP addresses and domains.
ESET Threat Intelligence: Checks against ESET's threat intelligence service.
Resolved IPs: All resolved IP addresses that have been seen in your organization for a given Fully Qualified Domain Name. For example:  Search for test.altostrat.com (Fully Qualified Domain Name) 2 resolved IPs (198.51.100.81 and 203.0.113.81) are displayed
Associated subdomains: All associated subdomains that have been seen in your organization for a given Fully Qualified Domain Name. Many adversaries use the same domain and subdomain for their attacks. For example:  Search for sandbox.altostrat.com (Fully Qualified Domain Name) 2 subdomains (test.sandbox.altostrat.com and staging.sandbox.altostrat.com) are displayed
Sibling Domains: All sibling domains that have been seen in your organization for a given Fully Qualified Domain Name at a given level. For example:  Search for sandbox.altostrat.com 1 sibling domain (foo.altostrat.com) is displayed
## Timeline
The Timeline tab lists all of the events for the domain. The Asset identifier column shows the asset ID. In a small number of cases, Google SecOps replaces the asset ID with the IP address of the asset.
## Considerations
Domain view has the following limitations:  Only 1000 events can be displayed in this view. You can only filter events that are displayed in this view. Only DNS, EDR, and Webproxy event types are populated in this view. The first seen and last seen information populated in this view is also limited to these event types. Generic events don't appear in any of the curated views. They appear only in raw log and UDM searches.