# Source: https://docs.cloud.google.com/chronicle/docs/investigation/investigate-ipaddress

# Investigate an IP address
Supported in:    Google secops   SIEM
Google Security Operations enables you to investigate specific IP addresses to determine if any are present within your enterprise and what impact these outside systems might have had on your assets. The Google SecOps IP address view is derived from the same security information and data forwarded from your enterprise and can examine using Asset view. Make sure you are ingesting and normalizing data from devices on your network, such as EDR, firewall, web proxy, etc.
From Asset view, you begin your investigation from within your enterprise and look outward. From IP address view, you begin your investigation from outside your enterprise and look in.
To access IP address view in Google SecOps, complete the following steps:  On the Google SecOps landing page, enter the IP address in the search bar. Click Search. Click the IP address in the results to open IP address view.  Note: UDM search provides enhanced capabilities that let you conduct more thorough investigations of the events and alerts within your Google SecOps instance than is possible using IP address view alone. For more information, see UDM search.
## IP Address context
IP Address view
#### 1 Prevalence
Google SecOps provides a graphical representation of the historical prevalence of a given IP address. This graph can be used to determine whether the IP address has been accessed from within the enterprise before, and can provide an indication of whether the IP address is associated with a particular campaign targeting the enterprise.
Typically, less prevalent IP addresses, ones that fewer assets have connected to, might represent a greater threat to your enterprise. Unlike the Prevalence graph in Asset view, the graph this figure shows a high prevalence access at the top of the graph, and low prevalence access at the bottom.
When you hold the pointer over a bar in the Prevalence graph, the graph lists the assets that accessed the IP address. Due to the high prevalence of DNS servers, they aren't listed. If all of the assets are DNS servers, no assets are listed.
#### 2 Slider for Prevalence graph
Adjust the slider to focus on events tied to a specific range of dates as shown in the Prevalence graph.
#### 3 IP Address insights
IP address insights provide you with more context about the IP address under investigation. You can use them to determine whether an IP address is benign or malicious. They also provide you with the ability to further investigate an indicator to determine if there is a broader compromise.
ET Intelligence Rep List: Checks against ProofPoint's Emerging Threats (ET) Intelligence Rep List. Lists known threats tied to specific IP addresses and domains.
ESET Threat Intelligence: Checks against ESET's threat intelligence service.
#### 4 VT Context
Click VT Context to view the VirusTotal information available for this IP address.
## Considerations
IP address view has the following limitations:  You can only filter events that are displayed in this view. Only DNS, EDR, Webproxy event types are populated in this view. The first seen and last seen information populated in this view is also limited to these event types. Generic events don't appear in any of the curated views. They appear only in raw log and UDM searches.