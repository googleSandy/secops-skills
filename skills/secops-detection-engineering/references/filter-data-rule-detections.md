# Source: https://docs.cloud.google.com/chronicle/docs/investigation/filter-data-rule-detections

# Filter data in Rule Detections view
Rule Detections view displays the metadata attached to the rule and a graph showing the number of detections found by the rule over recent days.
To access the Rule Detection view in Google Security Operations, complete the following steps:
In the navigation bar under Detections, select Rules & Detections to display the Rules dashboard.
Click a rule name. The Rule Detections view is displayed.
Click the right arrow in the Detections column in the left navigation panel.
Click the  icon in the top right corner of the Google SecOps user interface to open the Procedural Filtering menu.
The following Procedural Filtering options are displayed in the Rule Detection view (this list does not include all the filtering options):  METADATA.EVENT_TYPE METADATA.PRODUCT_NAME NETWORK.APPLICATION_PROTOCOL NETWORK.DNS.QUESTIONS.CLASS NETWORK.DNS.ANSWERS.DATA NETWORK.DNS.ANSWERS.NAME NETWORK.DNS.ANSWERS.TTL NETWORK.DNS.ANSWERS.TYPE NETWORK.DNS.QUESTIONS.CLASS NETWORK.DNS.QUESTIONS.NAME NETWORK.DNS.QUESTIONS.TYPE   Note: The fields available for Procedural Filtering are dependent on the events returned for this detection.       Send feedback