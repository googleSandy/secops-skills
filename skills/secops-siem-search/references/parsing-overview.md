# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/parsing-overview

# Overview of log parsing
Supported in:    Google secops   SIEM
This document provides an overview of how Google Security Operations parses raw logs to the Unified Data Model (UDM) format.
Google SecOps can receive log data originating from the following ingestion sources:  Google SecOps forwarder Chronicle API Feed Chronicle Ingestion API Third-party technology partner
In general, customers send data as original raw logs. Google SecOps uniquely identifies the device that generated the logs using the LogType. The LogType identifies both:  the vendor and device that generated the log, such as Cisco Firewall, Linux DHCP Server, or Bro DNS. which parser converts the raw log to structured UDM. There is a one-to-one relationship between a parser and a LogType. Each parser converts data received by a single LogType.
Google SecOps provides a set of default parsers that read original raw logs and generate structured UDM records using data in the original raw log. Google SecOps maintains these parsers. Customers can also define custom data mapping instructions by creating a customer-specific parser. If you submit a multi-line payload, the system interprets each line as a separate log entry.
The parser contains data mapping instructions. It defines how data is mapped from the original raw log to one or more fields in the UDM data structure.
If there are no parsing errors, Google SecOps creates a UDM-structured record using data from the raw log. The process of converting a raw log to a UDM record is called normalization.
A default parser might map a subset of core values from the raw log. Typically, these core fields are the most important to provide security insights in Google SecOps. Unmapped values remain in the raw log, but are not stored in the UDM record.
A customer can also use the Ingestion API, to send data in structured UDM format.
## Customize how ingested data is parsed
Google SecOps provides the following capabilities that enable customers to customize data parsing on incoming original log data.  Customer-specific parsers: customers create a custom parser configuration for a specific log type that meets their specific requirements. A customer-specific parser replaces the default parser for the specific LogType. For more details, see Manage prebuilt and custom parsers. Parser extensions: Customers can add custom mapping instructions in addition to the default parser configuration. Each customer can create their own unique set of custom mapping instructions. These mapping instructions define how to extract and transform additional fields from original raw logs to UDM fields. A parser extension does not replace the default or customer-specific parser.
## An example using a Squid web proxy log
This section provides an example Squid web proxy log and describes how the values are mapped to a UDM record. For description of all fields in the UDM schema, see Unified Data Model field list.
The example Squid web proxy log contains space-separated values. Each record represents one event and stores the following data: timestamp, duration, client, result code/result status, bytes transmitted, request method, URL, user, hierarchy code, and content type. In this example, the following fields are extracted and mapped into a UDM record: time, client, result status, bytes, request method, and URL.
```
1588059648.129 23 192.168.23.4 TCP_HIT/200 904 GET www.google.com/images/sunlogo.png - HIER_DIRECT/203.0.113.52 image/jpeg

```
As you compare these structures, notice that only a subset of the original log data is included in the UDM record. Certain fields are required and others are optional. In addition, only a subset of the sections in the UDM record contain data. If the parser does not map data from the original log to the UDM record, then you do not see that section of the UDM record in Google SecOps.
The `metadata` section stores the event timestamp. Notice that the value was converted from Epoch to RFC 3339 format. This conversion is optional. The timestamp can be stored as Epoch format, with preprocessing to separate the seconds and milliseconds portions into separate fields.
The `metadata.event_type` field stores the value `NETWORK_HTTP` which is an enumerated value that identifies the type of event. The value of the `metadata.event_type` determines which additional UDM fields are required versus optional. The `product_name` and `vendor_name` values contain user-friendly descriptions of the device that recorded the original log.
The `metadata.event_type` in a UDM Event record is not the same as the log_type defined when ingesting data using the Ingestion API. These two attributes store different information.
The `network` section contains values from the original log event. Notice in this example that the status value from the original log was parsed from the 'result code/status' field before being written to the UDM record. Only the result_code was included in the UDM record.
The `principal` section stores the client information from the original log. The `target` section stores both the fully qualified URL and the IP address.
The `security_result` section stores one of the enum values to represent the action that was recorded in the original log.
This is the UDM record formatted as JSON. Notice that only sections that contain data are included. The `src`, `observer`, `intermediary`, `about`, and `extensions` sections are not included.
```
{
        "metadata": {
            "event_timestamp": "2020-04-28T07:40:48.129Z",
            "event_type": "NETWORK_HTTP",
            "product_name": "Squid Proxy",
            "vendor_name": "Squid"
        },
        "principal": {
            "ip": "192.168.23.4"
        },
        "target": {
            "url": "www.google.com/images/sunlogo.png",
            "ip": "203.0.113.52"
        },
        "network": {
            "http": {
                "method": "GET",
                "response_code": 200,
                "received_bytes": 904
            }
        },
        "security_result": {
            "action": "UNKNOWN_ACTION"
        }
}

```
## Steps within parser instructions
Data mapping instructions within a parser follow a common pattern, as follows:  Parse and extract data from the original log. Manipulate the extracted data. This includes using conditional logic to selectively parse values, convert data types, replace substrings in a value, convert to uppercase or lowercase, etc. Assign values to UDM fields. Output the mapped UDM record to the @output key.
### Parse and extract data from the original log
#### Set the filter statement
The `filter` statement is the first statement in the set of parsing instructions. All additional parsing instructions are contained within the `filter` statement.
```
filter {

}

```
#### Initialize variables that will store extracted values
Within the `filter` statement, initialize intermediate variables that the parser will use to store values extracted from the log.
These variables are used each time an individual log is parsed. The value in each intermediate variable will be set to one or more UDM fields later in the parsing instructions.
```
  mutate {
    replace => {
      "event.idm.read_only_udm.metadata.product_name" => "Webproxy"
      "event.idm.read_only_udm.metadata.vendor_name" => "Squid"
      "not_valid_log" => "false"
      "when" => ""
      "srcip" => ""
      "action" => ""
      "username" => ""
      "url" => ""
      "tgtip" => ""
      "method" => ""
    }
  }

```
#### Extract individual values from the log
Google SecOps provides a set of filters, based on Logstash, to extract fields from original log files. Depending on the format of the log, you use one or multiple extraction filters to extract all data from the log. If the string is:  native JSON, parser syntax is similar to the JSON filter which supports JSON formatted logs. Nested JSON is not supported. XML format, parser syntax is similar to the XML filter which supports XML formatted logs. key-value pairs, parser syntax is similar to the Kv filter which supports key-value formatted messages. CSV format, parser syntax is similar to the Csv filter which supports CSV formatted messages. all other formats, parser syntax is similar to the GROK filter with GROK built-in patterns . This uses Regex-style extraction instructions.
Google SecOps provides a subset of the capabilities available in each filter. Google SecOps also provides custom data mapping syntax not available in the filters. See the Parser syntax reference for a description of features that are supported and custom functions.
Continuing with the Squid web proxy log example, the following data extraction instruction includes a combination of Logstash Grok syntax and regular expressions.
The following extraction statement stores values in the following intermediate variables:  `when` `srcip` `action` `returnCode` `size` `method` `username` `url` `tgtip`
This example statement also uses the `overwrite` keyword to store the extracted values in each variable. If the extraction process returns an error, then the `on_error` statement sets the `not_valid_log` to `true`.
```
grok {
   match => {
     "message" => [
       "%{NUMBER:when}\\s+\\d+\\s%{SYSLOGHOST:srcip} %{WORD:action}\\/%{NUMBER:returnCode} %{NUMBER:size} %{WORD:method} (?P<url>\\S+) (?P<username>.*?) %{WORD}\\/(?P<tgtip>\\S+).*"
     ]
   }
   overwrite => ["when","srcip","action","returnCode","size","method","url","username","tgtip"]
   on_error => "not_valid_log"
}

```
### Manipulate and transform the extracted values
Google SecOps leverages the Logstash mutate filter plug-in capabilities to enable manipulation of values extracted from the original log. Google SecOps provides a subset of the capabilities available in the plug-in. See the Parser syntax for a description of features that are supported and custom functions, such as:  cast values to a different data type replace values in the string merge two arrays or append a string to an array. Strings values are converted to an array before merging. convert to either lowercase or uppercase
This section provides data transformation examples that build on the Squid web proxy log presented earlier.
#### Transform the event timestamp
All events stored as a UDM record must have an event timestamp. This example checks whether a value for the data was extracted from the log. It then uses the Grok date function to match the value to the `UNIX` time format.
```
if [when] != "" {
  date {
    match => [
      "when", "UNIX"
    ]
   }
 }

```
#### Transform the `username` value
The following example statement converts the value in the `username` variable to lowercase.
```
mutate {
   lowercase => [ "username"]
   }

```
#### Transform the `action` value
The following example evaluates the value in the `action` intermediate variable and changes the value to either ALLOW, BLOCK, or UNKNOWN_ACTION which are valid values for the `security_result.action` UDM field. The `security_result.action` UDM field is an enumerated type that stores only specific values.
```
if ([action] == "TCP_DENIED" or [action] == "TCP_MISS" or [action] == "Denied" or [action] == "denied" or [action] == "Dropped") {
      mutate {
        replace => {
          "action" => "BLOCK"
        }
      }
   } else if ([action] == "TCP_TUNNEL" or [action] == "Accessed" or [action] == "Built" or [action] == "Retrieved" or [action] == "Stored") {
     mutate {
        replace => {
          "action" => "ALLOW"
        }
     }
   } else {
      mutate {
        replace => {
          "action" => "UNKNOWN_ACTION" }
      }
   }

```
#### Transform the target IP address
The following example checks for a value in the `tgtip` intermediate variable. If found, the value is matched to an IP address pattern using a predefined Grok pattern. If there is an error matching the value to an IP address pattern, the `on_error` function sets the `not_valid_tgtip` property to `true`. If the match is successful, then the `not_valid_tgtip` property is not set.
```
if [tgtip] not in [ "","-" ] {
   grok {
     match => {
       "tgtip" => [ "%{IP:tgtip}" ]
     }
     overwrite => ["tgtip"]
     on_error => "not_valid_tgtip"
   }

```
#### Change the data type of returnCode and size
The following example casts the value in the `size` variable to `uinteger` and the value in the `returnCode` variable to `uinteger`. This is required because the `size` variable will be saved to the `network.received_bytes` UDM field which stores an `int64` data type. The `returnCode` variable will be saved to the `network.http.response_code` UDM field which stores an `int32` data type.
```
mutate {
  convert => {
    "returnCode" => "integer"
    "size" => "uinteger"
  }
}

```
### Assign values to UDM fields in an event
After values are extracted and pre-processed, assign them to fields in a UDM event record. You can assign both extracted values and static values to a UDM field.
If you populate `event.disambiguation_key`, ensure that this field is unique to each event that is generated for the given log. If two different events have the same `disambiguation_key`, this will result in unexpected behavior in the system.
The parser examples in this section build on the previous Squid web proxy log example.
#### Save the event timestamp
Every UDM event record must have a value set for the `metadata.event_timestamp` UDM field. The following example saves the event timestamp extracted from the log to the `@timestamp` built-in variable. Google Security Operations saves this to the `metadata.event_timestamp` UDM field by default.
```
mutate {
  rename => {
    "when" => "timestamp"
  }
}

```
#### Set the event type
Every UDM event record must have a value set for the `metadata.event_type` UDM field. This field is an enumerated type. The value of this field determines which additional UDM fields must be populated for the UDM record to be saved. The parsing and normalization process will fail if any of the required fields do not contain valid data.
```
replace => {
    "event.idm.read_only_udm.metadata.event_type" => "NETWORK_HTTP"
   }
}

```
#### Save the `username` and `method` values using the `replace` statement
Values in the `username` and `method` intermediate fields are strings. The following example checks whether a valid value exists and, if it does, stores the `username` value to the `principal.user.userid` UDM field and the `method` value to the `network.http.method` UDM field.
```
if [username] not in [ "-" ,"" ] {
  mutate {
    replace => {
      "event.idm.read_only_udm.principal.user.userid" => "%{username}"
    }
  }
}

if [method] != "" {
  mutate {
    replace => {
      "event.idm.read_only_udm.network.http.method" => "%{method}"
    }
  }
}

```
#### Save the `action` to the `security_result.action` UDM field
In the previous section, the value in the `action` intermediate variable was evaluated and transformed to one of the standard values for the `security_result.action` UDM field.
Both the `security_result` and `action` UDM fields store an array of items, which means that you must follow a slightly different approach when saving this value.
First, save the transformed value to an intermediary `security_result.action` field. The `security_result` field is a parent of the `action` field.
```
mutate {
   merge => {
     "security_result.action" => "action"
   }
}

```
Next, save the intermediate `security_result.action` intermediary field to the `security_result` UDM field. The `security_result` UDM field stores an array of items, so the value is appended to this field.
```
 # save the security_result field
mutate {
  merge => {
    "event.idm.read_only_udm.security_result" => "security_result"
  }
}

```
#### Store the target IP address and source IP address using the `merge` statement
Store the following values to the UDM event record:  Value in the `srcip` intermediate variable to the `principal.ip` UDM field. Value in the `tgtip` intermediate variable to the `target.ip` UDM field.
Both the `principal.ip` and `target.ip` UDM fields store an array of items, so values are appended to each field.
The following examples demonstrate different approaches to saving these values. During the transform step, the `tgtip`intermediate variable was matched to an IP address using a predefined Grok pattern. The following example statement checks whether the `not_valid_tgtip` property is true indicating that `tgtip` value could not be matched to an IP address pattern. If it is false, it saves the `tgtip` value to the `target.ip` UDM field.
```
if ![not_valid_tgtip] {
  mutate {
    merge => {
      "event.idm.read_only_udm.target.ip" => "tgtip"
    }
  }
 }

```
The `srcip` intermediate variable was not transformed. The following statement checks whether a value was extracted from the original log, and if it was, saves the value to the `principal.ip` UDM field.
```
if [srcip] != "" {
  mutate {
    merge => {
      "event.idm.read_only_udm.principal.ip" => "srcip"
    }
  }
}

```
#### Save `url`, `returnCode`, and `size` using the `rename` statement
The following example statement stores the values using the `rename` statement:  The `url` variable saved to the `target.url` UDM field. The `returnCode` intermediate variable saved to the `network.http.response_code` UDM field. The `size` intermediate variable saved to the `network.received_bytes` UDM field.
```
mutate {
  rename => {
     "url" => "event.idm.read_only_udm.target.url"
     "returnCode" => "event.idm.read_only_udm.network.http.response_code"
     "size" => "event.idm.read_only_udm.network.received_bytes"
  }
}

```
### Bind the UDM record to the output
The final statement in the data mapping instruction outputs the processed data to a UDM event record.
```
mutate {
    merge => {
      "@output" => "event"
    }
  }

```
### The full parser code
This is the full parser code example. The order of instructions does not follow the same order as previous sections of this document, but results in the same output.
```
filter {

# initialize variables
  mutate {
    replace => {
      "event.idm.read_only_udm.metadata.product_name" => "Webproxy"
      "event.idm.read_only_udm.metadata.vendor_name" => "Squid"
      "not_valid_log" => "false"
      "when" => ""
      "srcip" => ""
      "action" => ""
      "username" => ""
      "url" => ""
      "tgtip" => ""
      "method" => ""
    }
  }

  # Extract fields from the raw log.
    grok {
      match => {
        "message" => [
          "%{NUMBER:when}\\s+\\d+\\s%{SYSLOGHOST:srcip} %{WORD:action}\\/%{NUMBER:returnCode} %{NUMBER:size} %{WORD:method} (?P<url>\\S+) (?P<username>.*?) %{WORD}\\/(?P<tgtip>\\S+).*"
        ]
      }
      overwrite => ["when","srcip","action","returnCode","size","method","url","username","tgtip"]
      on_error => "not_valid_log"
    }

  # Parse event timestamp
  if [when] != "" {
    date {
      match => [
        "when", "UNIX"
      ]
     }
   }

   # Save the value in "when" to the event timestamp
   mutate {
     rename => {
       "when" => "timestamp"
     }
   }

   # Transform and save username
   if [username] not in [ "-" ,"" ] {
     mutate {
       lowercase => [ "username"]
        }
      }
     mutate {
       replace => {
         "event.idm.read_only_udm.principal.user.userid" => "%{username}"
       }
     }

if ([action] == "TCP_DENIED" or [action] == "TCP_MISS" or [action] == "Denied" or [action] == "denied" or [action] == "Dropped") {
      mutate {
        replace => {
          "action" => "BLOCK"
        }
      }
   } else if ([action] == "TCP_TUNNEL" or [action] == "Accessed" or [action] == "Built" or [action] == "Retrieved" or [action] == "Stored") {
     mutate {
        replace => {
          "action" => "ALLOW"
        }
     }
   } else {
      mutate {
        replace => {
          "action" => "UNKNOWN_ACTION" }
      }
   }

  # save transformed value to an intermediary field
   mutate {
      merge => {
        "security_result.action" => "action"
      }
   }

    # save the security_result field
    mutate {
      merge => {
        "event.idm.read_only_udm.security_result" => "security_result"
      }
    }

   # check for presence of target ip. Extract and store target IP address.
   if [tgtip] not in [ "","-" ] {
     grok {
       match => {
         "tgtip" => [ "%{IP:tgtip}" ]
       }
       overwrite => ["tgtip"]
       on_error => "not_valid_tgtip"
     }

     # store  target IP address
     if ![not_valid_tgtip] {
       mutate {
         merge => {
           "event.idm.read_only_udm.target.ip" => "tgtip"
         }
       }
     }
   }

   # convert  the returnCode and size  to integer data type
   mutate {
     convert => {
       "returnCode" => "integer"
       "size" => "uinteger"
     }
   }

   # save  url, returnCode, and size
   mutate {
     rename => {
        "url" => "event.idm.read_only_udm.target.url"
        "returnCode" => "event.idm.read_only_udm.network.http.response_code"
        "size" => "event.idm.read_only_udm.network.received_bytes"
     }

     # set the event type to NETWORK_HTTP
     replace => {
        "event.idm.read_only_udm.metadata.event_type" => "NETWORK_HTTP"
     }
   }

   # validate and set source IP address
   if [srcip] != "" {
     mutate {
       merge => {
         "event.idm.read_only_udm.principal.ip" => "srcip"
       }
     }
   }

  # save  event to @output
   mutate {
     merge => {
       "@output" => "event"
     }
   }

} #end of filter

```