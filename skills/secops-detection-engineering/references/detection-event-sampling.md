# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/detection-event-sampling

# Detection event sampling
Supported in:    Google secops   SIEM
Detections from multi-event rules contain event samples, which provide context about the events that triggered the alert. There is a limit of up to 10 event samples for each event variable defined in the rule. For example, if a rule defines 2 event variables, each detection can have up to 20 event samples. The limit applies to each event variable separately. If one event variable has 2 applicable events in this detection, and the other event variable has 10 applicable events, the resulting detection contains 12 event samples (2 + 10).
Any event samples over the limit are omitted from the detection.
If you want more information about the events that caused your detection, you can use aggregations in the outcome section to output additional information in your detection.
If you are viewing detections in the UI, you can download all events samples for a detection. For more information, see Download events.