# Source: https://docs.cloud.google.com/chronicle/docs/unified-data-model/udm-usage

#  UDM usage guide
This document provides the following:  Detailed descriptions of Unified Data Model (UDM) schema fields Required and optional fields for entity types Required and optional fields for each event type
For details about particular UDM fields (for example, enum numbers), refer to the Unified Data Model field list.
UDM field name formats:  For rules engine evaluation, the prefix begins with udm. For configuration-based normalizer (CBN), the prefix begins with event.idm.read_only_udm.
## Population of Event metadata
The event metadata section for UDM events stores general information about each event.
### Metadata.event_type
Purpose: Specifies the type of the event. If an event has multiple possible types, this value must specify the most specific type. Required: Yes. Encoding: Must be one of the predefined UDM event_type enumerated types. Possible values: The following lists all of the possible values for event_type within the UDM.
#### Analyst events
ANALYST_ADD_COMMENT ANALYST_UPDATE_PRIORITY ANALYST_UPDATE_REASON ANALYST_UPDATE_REPUTATION ANALYST_UPDATE_RISK_SCORE ANALYST_UPDATE_ROOT_CAUSE ANALYST_UPDATE_SEVERITY_SCORE ANALYST_UPDATE_STATUS ANALYST_UPDATE_VERDICT
#### Device events
DEVICE_CONFIG_UPDATE DEVICE_FIRMWARE_UPDATE DEVICE_PROGRAM_DOWNLOAD DEVICE_PROGRAM_UPLOAD
#### Email events
EMAIL_UNCATEGORIZED EMAIL_TRANSACTION EMAIL_URL_CLICK
#### Events that are unspecified
EVENTTYPE_UNSPECIFIED
#### File events performed on an endpoint
FILE_UNCATEGORIZED FILE_COPY (for example, copying a file to a thumb drive) FILE_CREATION FILE_DELETION FILE_MODIFICATION FILE_MOVE FILE_OPEN (for example, opening a file might indicate a security breach) FILE_READ (for example, reading a password file) FILE_SYNC
#### Events that don't fall into any other category
Events that don't fall into any other category, including uncategorized Windows events:  GENERIC_EVENT
#### Group activity events
GROUP_UNCATEGORIZED GROUP_CREATION GROUP_DELETION GROUP_MODIFICATION
#### Mutex events
MUTEX_UNCATEGORIZED MUTEX_CREATION
#### Network telemetry events
Network telemetry events, which include raw protocol payloads, such as DHCP and DNS, as well as protocol summaries for protocols such as HTTP, SMTP, and FTP and flow and connection events from NetFlow and firewalls:  NETWORK_UNCATEGORIZED NETWORK_CONNECTION (for example, network connection details from a firewall) NETWORK_DHCP NETWORK_DNS NETWORK_FLOW (for example, aggregated flow statistics from Netflow) NETWORK_FTP NETWORK_HTTP NETWORK_SMTP
#### Process events
Any events pertaining to a process such as a process launch, a process creating something malicious, a process injecting into another process, a change of a registry key, or creating a malicious file on disk:  PROCESS_UNCATEGORIZED PROCESS_INJECTION PROCESS_LAUNCH PROCESS_MODULE_LOAD PROCESS_OPEN PROCESS_PRIVILEGE_ESCALATION PROCESS_TERMINATION
#### Registry events
Use the following REGISTRY events rather than the SETTING events when dealing with Microsoft Windows-specific registry events:  REGISTRY_UNCATEGORIZED REGISTRY_CREATION REGISTRY_MODIFICATION REGISTRY_DELETION
#### Resource events
RESOURCE_CREATION RESOURCE_DELETION RESOURCE_PERMISSIONS_CHANGE RESOURCE_READ RESOURCE_WRITTEN
#### Scan-oriented events
Scan-oriented events includes on-demand scans and behavioral detections performed by endpoint security products (EDR, AV, DLP). They are used only when attaching a SecurityResult to another event type (such as PROCESS_LAUNCH).
Scan-oriented events:  SCAN_UNCATEGORIZED SCAN_FILE SCAN_HOST SCAN_NETWORK SCAN_PROCESS SCAN_PROCESS_BEHAVIORS SCAN_VULN_HOST SCAN_VULN_NETWORK
#### Scheduled tasks events (Windows Task Scheduler, cron, etc.)
SCHEDULED_TASK_UNCATEGORIZED SCHEDULED_TASK_CREATION SCHEDULED_TASK_DELETION SCHEDULED_TASK_DISABLE SCHEDULED_TASK_ENABLE SCHEDULED_TASK_MODIFICATION
#### Service events
SERVICE_UNSPECIFIED SERVICE_CREATION SERVICE_DELETION SERVICE_MODIFICATION SERVICE_START SERVICE_STOP
#### Setting events
For setting event requirements, see Settings - required fields.
Setting events, including when a system setting is changed on an endpoint:  SETTING_UNCATEGORIZED SETTING_CREATION SETTING_DELETION SETTING_MODIFICATION
#### Status messages from security products
Status messages from security products to indicate that agents are alive and to send version, fingerprint, or other types of data:  STATUS_UNCATEGORIZED STATUS_HEARTBEAT (indicates product is alive) STATUS_STARTUP STATUS_SHUTDOWN STATUS_UPDATE (software or fingerprint update)
#### System audit log events
SYSTEM_AUDIT_LOG_UNCATEGORIZED SYSTEM_AUDIT_LOG_WIPE
#### User authentication activity events
USER_UNCATEGORIZED USER_BADGE_IN (for example, when a user physically badges in to a site) USER_CHANGE_PASSWORD USER_CHANGE_PERMISSIONS USER_COMMUNICATION USER_CREATION USER_DELETION USER_LOGIN USER_LOGOUT USER_RESOURCE_ACCESS USER_RESOURCE_CREATION USER_RESOURCE_DELETION USER_RESOURCE_UPDATE_CONTENT USER_RESOURCE_UPDATE_PERMISSIONS USER_STATS
### Metadata.collected_timestamp
Purpose: Encodes the GMT timestamp when the event was collected by the vendor's local collection infrastructure. Encoding: RFC 3339, as appropriate for JSON or Proto3 timestamp format. Example:  RFC 3339: '2019-09-10T20:32:31-08:00' Proto3 format: '2012-04-23T18:25:43.511Z'
### Metadata.event_timestamp
Purpose: Encodes the GMT timestamp when the event was generated. Required: Yes Encoding: RFC 3339, as appropriate for JSON or Proto3 timestamp format. Example:  RFC 3339: 2019-09-10T20:32:31-08:00 Proto3 format: 2012-04-23T18:25:43.511Z
### Metadata.description
Purpose: Human-readable description of the event. Encoding: Alpha-numeric string, punctuation allowed, 1024 bytes maximum Example: File c:\bar\foo.exe blocked from accessing sensitive document c:\documents\earnings.docx.
### Metadata.product_event_type
Purpose: Short, descriptive, human-readable, and product-specific event name or type. Encoding: Alpha-numeric string, punctuation allowed, 64 bytes maximum. Examples:  Registry Creation Event ProcessRollUp Privilege Escalation Detected Malware blocked
### Metadata.product_log_id
Purpose: Encodes a vendor-specific event identifier to uniquely identify the event (a GUID). Users might use this identifier to search the vendor's proprietary console for the event in question. Encoding: Case-sensitive, alphanumeric string, punctuation allowed, 256 bytes maximum. Example: ABcd1234-98766
### Metadata.product_name
Purpose: Specifies the name of the product. Encoding: Case-sensitive, alphanumeric string, punctuation allowed, 256 bytes maximum. Examples:  Falcon Symantec Endpoint Protection
### Metadata.product_version
Purpose: Specifies the version of the product. Encoding: Alphanumeric string, periods and dashes allowed, 32 bytes maximum Examples:  1.2.3b 10.3:rev1
### Metadata.url_back_to_product
Purpose: URL linking to a relevant website where you can view more information about this specific event (or the general event category). Encoding: Valid RFC 3986 URL with optional parameters such as port information, etc. Must have a protocol prefix before the URL (for example, https:// or http://). Example: https://newco.altostrat.com:8080/event_info?event_id=12345
### Metadata.vendor_name
Purpose: Specifies the product vendor's name. Encoding: Case-sensitive, alphanumeric string, punctuation allowed, 256 bytes maximum Examples:  CrowdStrike Symantec
## Population of Noun metadata
In this section, the word Noun is a overarching term used to represent the entities; principal, src, target, intermediary, observer, and about. These entities have common attributes, but represent different objects in an event. For more information about entities and what each represents in an event, see Formatting log data as UDM.
### Noun.asset_id
Purpose: Vendor-specific unique device identifier (for example, a GUID that is generated when installing endpoint security software on a new device that is used to track that unique device over time). Encoding: (VendorName or VendorAbbreviation):ID where the VendorName or VendorAbbreviation is a case insensitive vendor name like `Carbon Black` or `CB` and ID is a vendor-specific customer identifier that is globally unique within their customer's environment (for example, a GUID or unique value identifying a unique device). VendorName is alphanumeric and no more than 32 characters long. ID can be a maximum of 128 characters in length and can include alphanumeric characters, dashes, and periods. Example: `CrowdStrike:0bce4259-4ada-48f3-a904-9a526b01311f` Example: `CS:0bce4259-4ada-48f3-a904-9a526b01311f`
### Noun.email
Purpose: Email address Encoding: Standard email address format. Example: johns@test.altostrat.com
### Noun.file
Purpose: Detailed file metadata. Type: Object See Population of File metadata.
### Noun.hostname
Purpose: Client hostname or domain name field. Do not include if a URL is present. Encoding: Valid RFC 1123 hostname. Examples:  userwin10 www.altostrat.com
### Noun.platform
Purpose: Platform operating system. Encoding: Enum Possible values:  LINUX MAC WINDOWS UNKNOWN_PLATFORM
### Noun.platform_patch_level
Purpose: Platform operating system patch level. Encoding: Alphanumeric string with punctuation, 64 characters maximum. Example: Build 17134.48
### Noun.platform_version
Purpose: Platform operating system version. Encoding: Alphanumeric string with punctuation, 64 characters maximum. Example: Microsoft Windows 10 version 1803
### Noun.process
Purpose: Detailed process metadata. Type: Object See Population of Process metadata.
### Noun.ip
Purpose:  Single IP address associated with a network connection. One or more IP addresses associated with a participant device at the time of the event (for example, if an EDR product knows all of the IP addresses associated with a device, it can encode all of these within IP fields).  Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII. Repeatability:  If an event is describing a specific network connection (for example, srcip:srcport > dstip:dstport), the vendor must provide only a single IP address. If an event is describing general activity occurring on a participant device but not a specific network connection, the vendor might provide all of the associated IP addresses for the device at the time of the event.  Examples:  192.168.1.2 2001:db8:1:3::1
### Noun.port
Purpose: Source or destination network port number when a specific network connection is described within an event. Encoding: Valid TCP/IP port number from 1 through 65,535.
Examples:  80 443  Note: If a port number is specified, there must be one and only one IP address specified in the same Noun.
### Noun.mac
Purpose: One or more MAC addresses associated with a device. Encoding: Valid MAC address (EUI-48) in ASCII. Repeatability: Vendor might provide all of the associated MAC addresses for the device at the time of the event. Examples:  fedc:ba98:7654:3210:fedc:ba98:7654:3210 1080:0:0:0:8:800:200c:417a 00:a0:0:0:c9:14:c8:29
### Noun.administrative_domain
Purpose: Domain that the device belongs to (for example, the Windows domain). Encoding: Valid domain name string (128 characters maximum). Example: corp.altostrat.com
### Noun.registry
Purpose: Detailed registry metadata. Type: Object See Population of Registry metadata
### Noun.url
Purpose: Standard URL Encoding: URL (RFC 3986). Must have a valid protocol prefix (for example, https:// or ftp://). Must include the full domain and path. Might include the URL's parameters. Example: https://foo.altostrat.com/bletch?a=b;c=d
### Noun.user
Purpose: Detailed user metadata. Type: Object See Population of User metadata.
## Population of Authentication metadata
### Authentication.AuthType
Purpose: Type of system an authentication event is associated with (Google Security Operations UDM). Encoding: Enumerated type. Possible values:  AUTHTYPE_UNSPECIFIED MACHINE—Machine authentication PHYSICAL—Physical authentication (for example, a badge reader) SSO TACACS—TACACS family protocol for authentication of networked systems (for example, TACACS or TACACS+) VPN
### Authentication.Authentication_Status
Purpose: Describes the authentication status of a user or specific credential. Encoding: Enumerated type. Possible values:  UNKNOWN_AUTHENTICATION_STATUS—Default authentication status ACTIVE—Authentication method is in an active state SUSPENDED—Authentication method is in a suspended or disabled state DELETED—Authentication method has been deleted NO_ACTIVE_CREDENTIALS—Authentication method has no active credentials.
### Authentication.auth_details
Purpose: Vendor-defined authentication details. Encoding: String.
### Authentication.Mechanism
Purpose: Mechanism(s) used for authentication. Encoding: Enumerated type. Possible values:  MECHANISM_UNSPECIFIED—Default authentication mechanism. BADGE_READER BATCH—Batch authentication. CACHED_INTERACTIVE—Interactive authentication using cached credentials. HARDWARE_KEY LOCAL MECHANISM_OTHER—Some other mechanism that is not defined here. NETWORK—Network authentication. NETWORK_CLEAR_TEXT—Network clear text authentication. NEW_CREDENTIALS—Authentication with new credentials. OTP REMOTE—Remote authentication REMOTE_INTERACTIVE—RDP, terminal services, Virtual Network Computing (VNC), etc. SERVICE—Service authentication. UNLOCK—Direct human-interactive unlock authentication. USERNAME_PASSWORD
## Population of DHCP metadata
The Dynamic Host Control Protocol (DHCP) metadata fields capture DHCP network management protocol log information.
### Dhcp.client_hostname
Purpose: Hostname for the client. See RFC 2132, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: String.
### Dhcp.client_identifier
Purpose: Client identifier. See RFC 2132, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: Bytes.
### Dhcp.file
Purpose: Filename for the boot image. Encoding: String.
### Dhcp.flags
Purpose: Value for the DHCP flags field. Encoding: 32-bit unsigned integer.
### Dhcp.hlen
Purpose: Hardware address length. Encoding: 32-bit unsigned integer.
### Dhcp.hops
Purpose: DHCP hop count. Encoding: 32-bit unsigned integer.
### Dhcp.htype
Purpose: Hardware address type. Encoding: 32-bit unsigned integer.
### Dhcp.lease_time_seconds
Purpose: Client-requested lease time for an IP address in seconds. See RFC 2132, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: 32-bit unsigned integer.
### Dhcp.opcode
Purpose: BOOTP op code (see section 3 of RFC 951). Encoding: Enumerated type. Possible values:  UNKNOWN_OPCODE BOOTREQUEST BOOTREPLY
### Dhcp.requested_address
Purpose: Client identifier. See RFC 2132, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII.
### Dhcp.seconds
Purpose: Seconds elapsed since the client began the address acquisition/renewal process. Encoding: 32-bit unsigned integer.
### Dhcp.sname
Purpose: Name of the server that the client has requested to boot from. Encoding: String.
### Dhcp.transaction_id
Purpose: Client transaction ID. Encoding: 32-bit unsigned integer.
### Dhcp.type
Purpose: DHCP message type. See RFC 1533 for more information. Encoding: Enumerated type. Possible values:  UNKNOWN_MESSAGE_TYPE DISCOVER OFFER REQUEST DECLINE ACK NAK RELEASE INFORM WIN_DELECTED WIN_EXPIRED
### Dhcp.chaddr
Purpose: Hardware address for the client. Encoding: MAC address.
### Dhcp.ciaddr
Purpose: IP address for the client. Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII.
### Dhcp.giaddr
Purpose: IP address for the relay agent. Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII.
### Dhcp.siaddr
Purpose: IP address for the next bootstrap server. Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII.
### Dhcp.yiaddr
Purpose: Your IP address. Encoding: Valid IPv4 or IPv6 address (RFC 5942) encoded in ASCII.
## Population of DHCP Option metadata
The DHCP option metadata fields capture the DHCP option log information.
### Option.code
Purpose: Stores the DHCP option code. See RFC 1533, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: Unsigned 32-bit integer.
### Option.data
Purpose: Stores the DHCP option data. See RFC 1533, DHCP Options and BOOTP Vendor Extensions, for more information. Encoding: Bytes.
## Population of DNS metadata
The DNS metadata fields capture information related to DNS request and response packets. They have a one-to-one correspondence to the data found in DNS request and response datagrams.
### Dns.authoritative
Purpose: Set to true for authoritative DNS servers. Encoding: Boolean.
### Dns.id
Purpose: Stores the DNS query identifier. Encoding: 32-bit integer.
### Dns.response
Purpose: Set to true if the event is a DNS response. Encoding: Boolean.
### Dns.opcode
Purpose: Stores the DNS OpCode used to specify the type of DNS query (standard, inverse, server status, etc.). Encoding: 32-bit integer.
### Dns.recursion_available
Purpose: Set to true if a recursive DNS lookup is available. Encoding: Boolean.
### Dns.recursion_desired
Purpose: Set to true if a recursive DNS lookup is requested. Encoding: Boolean.
### Dns.response_code
Purpose: Stores the DNS response code as defined by RFC 1035, Domain Names - Implementation and Specification. Encoding: 32-bit integer.
### Dns.truncated
Purpose: Set to true if this is a truncated DNS response. Encoding: Boolean.
### Dns.questions
Purpose: Stores the domain protocol message questions. See Population of DNS Question metadata.
### Dns.answers
Purpose: Stores the answer to the domain name query. See Population of DNS Resource Record metadata.
### Dns.authority
Purpose: Stores the domain name servers that verified the answer to the domain name query. See Population of DNS Resource Record metadata.
### Dns.additional
Purpose: Stores the additional domain name servers that can be used to verify the answer to the domain. See Population of DNS Resource Record metadata.
## Population of DNS Question metadata
The DNS question metadata fields capture the information contained within the question section of a domain protocol message.
### Question.name
Purpose: Stores the domain name. Encoding: String.
### Question.class
Purpose: Stores the code specifying the class of the query. Encoding: 32-bit integer.
### Question.type
Purpose: Stores the code specifying the type of the query. Encoding: 32-bit integer.
## Population of DNS Resource Record metadata
The DNS resource record metadata fields capture the information contained within the resource record of a domain protocol message.
### ResourceRecord.binary_data
Purpose: Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. This field must only be used if the response data returned by the DNS server contains non-UTF8 data. Otherwise, place the DNS response in the data field below. This type of information must be stored here rather than in ResourceRecord.data.
Encoding: Bytes. Note: This field is not specified in RFC 1035 (unlike the other DNS resource record fields), but has been defined by Google SecOps for the UDM.
### ResourceRecord.class
Purpose: Stores the code specifying the class of the resource record. Encoding: 32-bit integer.
### ResourceRecord.data
Purpose: Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. For example, the data field could return the IP address of the machine that the domain name refers to. If the resource record is for a different type or class, it might contain another domain name (when one domain name is redirected to another domain name). Data must be stored just as it is in the DNS response. Encoding: String.
### ResourceRecord.name
Purpose: Stores the name of the owner of the resource record. Encoding: String.
### ResourceRecord.ttl
Purpose: Stores the time interval for which the resource record can be cached before the source of the information should again be queried. Encoding: 32-bit integer.
### ResourceRecord.type
Purpose: Stores the code specifying the type of the resource record. Encoding: 32-bit integer.
## Population of Email metadata
Most of the Email Metadata fields capture the email addresses included in the message header and should conform to the standard email address format (local-mailbox@domain) as defined in RFC 5322. For example, frank@email.example.com.
### Email.from
Purpose: Stores the from email address. Encoding: String.
### Email.reply_to
Purpose: Stores the reply_to email address. Encoding: String.
### Email.to
Purpose: Stores the to email addresses. Encoding: String.
### Email.cc
Purpose: Stores the cc email addresses. Encoding: String.
### Email.bcc
Purpose: Stores the bcc email addresses. Encoding: String.
### Email.mail_id
Purpose: Stores the mail (or message) id. Encoding: String. Example: 192544.132632@email.example.com
### Email.subject
Purpose: Stores the email subject line. Encoding: String. Example: "Please read this message."
## Population of Extensions metadata
Event types with first-class metadata that are not already categorized by the Google SecOps UDM.
### Extensions.auth
Purpose: Extension to the authentication metadata. Encoding: String. Examples:  Sandbox metadata (all behaviors exhibited by a file, for example, FireEye). Network Access Control (NAC) data. LDAP details about a user (for example, role, organization, etc.).
### Extensions.auth.auth_details
Purpose: Specify the vendor specific details for the authentication type or mechanism. Authentication providers often define types such as via_mfa or via_ad that provide useful information on the authentication type. These types can still be generalized in auth.type or auth.mechanism for usability and cross dataset rule compatibility. Encoding: String. Examples: via_mfa, via_ad.
### Extensions.vulns
Purpose: Extension to the vulnerability metadata. Encoding: String. Example: Host vulnerability scan data.
## Population of File metadata
### File.file_metadata
Purpose: Metadata associated with the file. Encoding: String. Examples:  Author Revision number Version number Date last saved
### File.full_path
Purpose: Full path identifying the location of the file on the system. Encoding: String. Example: \Program Files\Custom Utilities\Test.exe
### File.md5
Purpose: MD5 hash value for the file. Encoding: String, lower-case hexadecimal. Example: 35bf623e7db9bf0d68d0dda764fd9e8c
### File.mime_type
Purpose: Multipurpose Internet Mail Extensions (MIME) type for the file. Encoding: String. Examples:  PE PDF powershell script
### File.sha1
Purpose: SHA-1 hash value for the file. Encoding: String, lower-case hexadecimal. Example: eb3520d53b45815912f2391b713011453ed8abcf
### File.sha256
Purpose: SHA-256 hash value for the file. Encoding: String, lower-case hexadecimal. Example: d7173c568b8985e61b4050f81b3fd8e75bc922d2a0843d7079c81ca4b6e36417
### File.size
Purpose: Size of the file. Encoding: 64-bit unsigned integer. Example: 342135
## Population of FTP metadata
### Ftp.command
Purpose: Stores the FTP command. Encoding: String. Examples:  binary delete get put
## Population of Group metadata
Information about an organizational group.
### Group.creation_time
Purpose: Group creation time. Encoding: RFC 3339, as appropriate for JSON or Proto3 timestamp format.
### Group.email_addresses
Purpose: Group contact information. Encoding: Email.
### Group.group_display_name
Purpose: Group display name. Encoding: String. Examples:  Finance HR Marketing
### Group.product_object_id
Purpose: Globally unique user object identifier for the product, such as an LDAP object identifier. Encoding: String.
### Group.windows_sid
Purpose: Microsoft Windows Security Identifier (SID) group attribute field. Encoding: String.
## Population of HTTP metadata
### Http.method
Purpose: Stores the HTTP request method. Encoding: String. Examples:  GET HEAD POST
### Http.referral_url
Purpose: Stores the URL for the HTTP referer. Encoding: Valid RFC 3986 URL. Example: https://www.altostrat.com
### Http.response_code
Purpose: Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. Encoding: 32-bit integer. Examples:  400 404
### Http.user_agent
Purpose: Stores the User-Agent request header that includes the application type, operating system, software vendor or software version of the requesting software user agent. Encoding: String. Examples:  Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.26 (KHTML, like Gecko) Chrome/41.0.2217.0 Safari/527.33
## Population of Location metadata
### Location.city
Purpose: Stores the name of the city. Encoding: String. Examples:  Sunnyvale Chicago Málaga
### Location.country_or_region
Purpose: Stores the name of the country or region of the world. Encoding: String. Examples:  United States United Kingdom Spain
### Location.name
Purpose: Stores the name specific to the enterprise, such as a building or campus. Encoding: String. Examples:  Campus 7B Building A2
### Location.state
Purpose: Stores the name of the state, province, or territory. Encoding: String. Examples:  California Illinois Ontario
## Population of Network metadata
### Network.application_protocol
Purpose: Indicates the network application protocol. Encoding: Enumerated type.
Possible values:  UNKNOWN_APPLICATION_PROTOCOL AFP APPC AMQP ATOM BEEP BITCOIN BIT_TORRENT CFDP CIP COAP COTP DCERPC DDS DEVICE_NET DHCP DICOM DNP3 DNS E_DONKEY ENRP FAST_TRACK FINGER FREENET FTAM GOOSE GOPHER GRPC HL7 H323 HTTP HTTPS IEC104 IRCP KADEMLIA KRB5 LDAP LPD MIME MMS MODBUS MQTT NETCONF NFS NIS NNTP NTCIP NTP OSCAR PNRP PTP QUIC RDP RELP RIP RLOGIN RPC RTMP RTP RTPS RTSP SAP SDP SIP SLP SMB SMTP SNMP SNTP SSH SSMS STYX SV TCAP TDS TOR TSP VTP WHOIS WEB_DAV X400 X500 XMPP
### Network.direction
Purpose: Indicates the direction of network traffic. Encoding: Enumerated type. Possible values:  UNKNOWN_DIRECTION INBOUND OUTBOUND BROADCAST
### Network.email
Purpose: Specifies the email address for the sender/recipient. Encoding: String. Example: jcheng@company.example.com
### Network.ip_protocol
Purpose: Indicates the IP protocol. Encoding: Enumerated type. Possible values:  UNKNOWN_IP_PROTOCOL EIGRP—Enhanced Interior Gateway Routing Protocol ESP—Encapsulating Security Payload ETHERIP—Ethernet-within-IP Encapsulation GRE—Generic Routing Encapsulation ICMP—Internet Control Message Protocol IGMP—Internet Group Management Protocol IP6IN4—IPv6 Encapsulation PIM—Protocol Independent Multicast TCP—Transmission Control Protocol UDP—User Datagram Protocol VRRP—Virtual Router Redundancy Protocol
### Network.received_bytes
Purpose: Specifies the number of bytes received. Encoding: 64-bit unsigned integer. Example: 12,453,654,768
### Network.sent_bytes
Purpose: Specifies the number of bytes sent. Encoding: 64-bit unsigned integer. Example: 7,654,876
### Network.session_duration
Purpose: Stores the network session duration, typically returned in a drop event for the session. To set the duration you can set either network.session_duration.seconds = 1, (type int64) or network.session_duration.nanos = 1 (type int32). Encoding:  32-bit integer—For seconds (network.session_duration.seconds). 64-bit integer—For nanoseconds (network.session_duration.nanos).
### Network.session_id
Purpose: Stores the network session identifier. Encoding: String. Example: SID:ANON:www.w3.org:j6oAOxCWZh/CD723LGeXlf-01:34
## Population of Process metadata
### Process.command_line
Purpose: Stores the command line string for the process. Encoding: String. Example: `c:\windows\system32\net.exe` group.
### Process.product_specific_process_id
Purpose: Stores the product specific process ID. Encoding: String. Examples: `MySQL:78778` or `CS:90512`
### Process.parent_process.product_specific_process_id
Purpose: Stores the product specific process ID for the parent process. Encoding: String. Examples: `MySQL:78778` or `CS:90512`
### Process.file
Purpose: Stores the filename of the file in use by the process. Encoding: String. Example: report.xls
### Process.parent_process
Purpose: Stores the details of the parent process. Encoding: Noun (Process)
### Process.pid
Purpose: Stores the process ID. Encoding: String. Examples:  308 2002
## Population of Registry metadata
### Registry.registry_key
Purpose: Stores the registry key associated with an application or system component. Encoding: String. Example: HKEY_LOCAL_MACHINE/SYSTEM/DriverDatabase
### Registry.registry_value_name
Purpose: Stores the name of the registry value associated with an application or system component. Encoding: String. Example: TEMP
### Registry.registry_value_data
Purpose: Stores the data associated with a registry value. Encoding: String. Example: %USERPROFILE%\Local Settings\Temp
## Population of Security Result metadata
The Security Result metadata includes details about security risks and threats that were found by a security system as well as the actions taken to mitigate those risks and threats.
### SecurityResult.about
Purpose: Provide a description of the security result. Encoding: Noun.
### SecurityResult.action
Purpose: Specify a security action. Encoding: Enumerated type. Possible values: Google SecOps UDM defines the following security actions:  ALLOW ALLOW_WITH_MODIFICATION—File or email was disinfected or rewritten and still forwarded. BLOCK QUARANTINE—Store for later analysis (does not mean block). UNKNOWN_ACTION
### SecurityResult.action_details
Purpose: Vendor-provided details of the action taken as a result of the security incident. Security actions often best translate into the more general Security_Result.action UDM field. However, you might need to write rules for the exact vendor-provided description of the action. Encoding: String. Examples: drop, block, decrypt, encrypt.
### SecurityResult.category
Purpose: Specify a security category. Encoding: Enum. Possible values: Google SecOps UDM defines the following security categories:  ACL_VIOLATION—Unauthorized access attempted, including attempted access to files, web services, processes, web objects, etc. AUTH_VIOLATION—Authentication failed, such as a bad password or bad 2-factor authentication. DATA_AT_REST—DLP: sensor data found at rest in a scan. DATA_DESTRUCTION—Attempt to destroy/delete data. DATA_EXFILTRATION—DLP: sensor data transmission, copy to thumb drive. EXPLOIT—Attempted overflows, bad protocol encodings, ROP, SQL injection, etc, both network and host-based. MAIL_PHISHING—Phishing email, chat messages, etc. MAIL_SPAM—Spam email, message, etc. MAIL_SPOOFING—Spoofed source email address, etc. NETWORK_CATEGORIZED_CONTENT NETWORK_COMMAND_AND_CONTROL—If the command and control channel is known. NETWORK_DENIAL_OF_SERVICE NETWORK_MALICIOUS—Command and control, network exploit, suspicious activity, potential reverse tunnel, etc. NETWORK_SUSPICIOUS—Non-security related, for example, the URL is linked to gambling, etc. NETWORK_RECON—Port scan detected by an IDS, probing by a web application. POLICY_VIOLATION—Security policy violation, including firewall, proxy, and HIPS rule violations or NAC block actions. SOFTWARE_MALICIOUS—Malware, spyware, rootkits, etc. SOFTWARE_PUA—Potentially unwanted app, such as adware, etc. SOFTWARE_SUSPICIOUS UNKNOWN_CATEGORY
### SecurityResult.confidence
Purpose: Specify a confidence with regards to a security event as estimated by the product. Encoding: Enum. Possible values: Google SecOps UDM defines the following product confidence categories:  UNKNOWN_CONFIDENCE LOW_CONFIDENCE MEDIUM_CONFIDENCE HIGH_CONFIDENCE
### SecurityResult.confidence_details
Purpose: Additional detail with regards to the confidence of a security event as estimated by the product vendor. Encoding: String.
### SecurityResult.priority
Purpose: Specify a priority with regards to a security event as estimated by the product vendor. Encoding: Enum. Possible values: Google SecOps UDM defines the following product priority categories:  UNKNOWN_PRIORITY LOW_PRIORITY MEDIUM_PRIORITY HIGH_PRIORITY
### SecurityResult.priority_details
Purpose: Vendor-specific information about the security result priority. Encoding: String.
### SecurityResult.rule_id
Purpose: Identifier for the security rule. Encoding: String. Examples:  08123 5d2b44d0-5ef6-40f5-a704-47d61d3babbe
### SecurityResult.rule_name
Purpose: Name of the security rule. Encoding: String. Example: BlockInboundToOracle.
### SecurityResult.severity
Purpose: Severity of a security event as estimated by the product vendor using values defined by the Google SecOps UDM. Encoding: Enum. Possible values: Google SecOps UDM defines the following product severities:  UNKNOWN_SEVERITY—Non-malicious INFORMATIONAL—Non-malicious ERROR—Non-malicious LOW—Malicious MEDIUM—Malicious HIGH—Malicious
### SecurityResult.severity_details
Purpose: Severity for a security event as estimated by the product vendor. Encoding: String.
### SecurityResult.threat_name
Purpose: Name of the security threat. Encoding: String. Examples:  W32/File-A Slammer
### SecurityResult.url_back_to_product
Purpose: URL to direct you to the source product console for this security event. Encoding: String.
## Population of User metadata
### User.email_addresses
Purpose: Stores the email addresses for the user. Encoding: Repeated String. Example: johnlocke@company.example.com
### User.employee_id
Purpose: Stores the human resources employee ID for the user. Encoding: String. Example: 11223344.
### User.first_name
Purpose: Stores the first name for the user. Encoding: String. Example: John.
### User.middle_name
Purpose: Stores the middle name for the user. Encoding: String. Example: Anthony.
### User.last_name
Purpose: Stores the last name for the user. Encoding: String. Example: Locke.
### User.group_identifiers
Purpose: Stores the group ID(s) (a GUID, LDAP OID, or similar) associated with a user. Encoding: Repeated String. Example: admin-users.
### User.phone_numbers
Purpose: Stores the phone numbers for the user. Encoding: Repeated String. Example: 800-555-0101
### User.title
Purpose: Stores the job title for the user. Encoding: String. Example: Customer Relationship Manager.
### User.user_display_name
Purpose: Stores the display name for the user. Encoding: String. Example: John Locke.
### User.userid
Purpose: Stores the user ID. Encoding: String. Example: jlocke.
### User.windows_sid
Purpose: Stores the Microsoft Windows security identifier (SID) associated with a user. Encoding: String. Example: S-1-5-21-1180649209-123456789-3582944384-1064
## Population of Vulnerability metadata
### Vulnerability.about
Purpose: If the vulnerability is about a specific noun (for example, executable), add it here. Encoding: Noun. See Population of Noun metadata Example: executable.
### Vulnerability.cvss_base_score
Purpose: Base score for Common Vulnerability Scoring System (CVSS). Encoding: Floating-point. Range: 0.0 through 10.0 Example: 8.5
### Vulnerability.cvss_vector
Purpose: Vector for the CVSS properties of the vulnerability. A CVSS score is composed of the following metrics:  Attack Vector (AV) Access Complexity (AC) Authentication (Au) Confidentiality Impact (C) Integrity Impact (I) Availability Impact (A)
For more information, see https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator.
Encoding: String.
Example: AV:L/AC:H/Au:N/C:N/I:P/A:C
### Vulnerability.cvss_version
Purpose: CVSS version for the vulnerability score or vector. Encoding: String. Example: 3.1
### Vulnerability.description
Purpose: Description of the vulnerability. Encoding: String.
### Vulnerability.first_found
Purpose: Products that maintain a history of vulnerability scans should populate first_found with the time the vulnerability for this asset was first detected. Encoding: String.
### Vulnerability.last_found
Purpose: Products that maintain a history of vulnerability scans should populate last_found with the time the vulnerability for this asset was most recently detected. Encoding: String.
### Vulnerability.name
Purpose: Name of the vulnerability. Encoding: String. Example: Unsupported OS Version detected.
### Vulnerability.scan_end_time
Purpose: If the vulnerability was discovered during an asset scan, populate this field with the time the scan ended. Leave this field empty if the end time is not available or not applicable. Encoding: String.
### Vulnerability.scan_start_time
Purpose: If the vulnerability was discovered during an asset scan, populate this field with the time the scan started. Leave this field empty if the start time is not available or not applicable. Encoding: String.
### Vulnerability.severity
Purpose: Severity of the vulnerability. Encoding: Enumerated type. Possible values:  UNKNOWN_SEVERITY LOW MEDIUM HIGH
### Vulnerability.severity_details
Purpose: Vendor specific severity details. Encoding: String.
## Population of alert metadata
Caution: These fields are deprecated. Use YARA-L detection rule alerts for alert metadata. For more information, see Feature deprecations.
### idm.is_significant
Purpose: Specifies whether to display the alert in Enterprise Insights. Encoding: Boolean.
### idm.is_alert
Purpose: Identifies whether the event is an alert. Encoding: Boolean.
## Required and optional fields for entity types
Entity type Entity-specific requirements     `IP_ADDRESS`   `entity.ip` must contain at least one valid IP address.     `FILE`   `entity.file` must be present and contain at least one field.     `DOMAIN_NAME`   `entity.hostname` must be present and represent a valid hostname. `Optional`: If `entity.domain.whois_server` is populated, the `entity.domain` message must have no more than 50 fields set.     `URL`   `entity.url` must be present and not empty.     `MUTEX`   `entity.resource` must be present. `entity.resource.resource_type` must be `MUTEX`. `entity.resource.name` must be present and not empty.     `USER`   `entity.user` must be present. `entity.user` must have at least one email address specified.     `RESOURCE`   `entity.resource` must be present. `entity.resource.resource_type` must be either `MUTEX` or `STORAGE_OBJECT`.  If `resource_type` is `MUTEX`: See `MUTEX` requirements above. If `resource_type` is `STORAGE_OBJECT`:  `entity.resource.resource_subtype` must be present and not empty. At least one of the following must be present and not empty: `entity.registry.registry_key` `entity.registry.registry_value_data` `entity.registry.registry_value_name`      `CIDR_BLOCK`   `entity.network.ip_subnet_range` must be present and include a valid CIDR in the following format: `ip_address/prefix_length`.
## Required and optional fields for each event type
This section describes the required and optional fields that should be populated for each UDM event type.
For details about particular UDM fields (for example, enum numbers), refer to the Unified Data Model field list.
### EMAIL_TRANSACTION
Required fields:  metadata: Include the required fields. principal: Populate with information about the machine that the email message originated from (for example, the IP address of the sender). network.email: Email sender or recipient information.
Optional fields:  about: URLs, IPs, domains, and any file attachments embedded in the email body. securityResult.about: Bad URLs, IPs, and files embedded within the email body. principal: If there is client machine data on who sent the email, populate the server details in principal (for example, the client process, port numbers, username, etc.). target: If there is destination email server data, populate the server details in target (for example, the IP address). intermediary: If there is mail server data or mail proxy data, populate the server details in intermediary.
Notes:  Never populate principal.email or target.email. Only populate the email field in security_result.about or network.email. Top level security results generally have a noun set (optional for spam).
### FILE_CREATION, FILE_DELETION, FILE_MODIFICATION, FILE_READ, and FILE_OPEN
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. (Optional) Populate principal.process with information about the process accessing the file.  target:  If the file is remote (for example SMB share), the target must include at least one machine identifier for the target machine, otherwise all machine identifiers must be blank. Populate target.file with information about the file.
Optional fields:  security_result: Describe the malicious activity detected. principal.user: Populate if user information is available about the process.
### FILE_COPY
Required fields:  metadata: Include the required fields as described. principal:  At least one machine identifier. (Optional) Populate principal.process with information about the process performing the file copy operation.  src:  Populate src.file with information about the source file. If the file is remote (for example SMB share), src must include at least one machine identifier for the source machine storing the source file.  target:  Populate target.file with information about the target file. If the file is remote (for example SMB share), the target field must include at least one machine identifier for the target machine that holds the target file.
Optional fields:  security_result: Describe the malicious activity detected. principal.user: Populate if user information is available about the process.
### MUTEX_CREATION
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. Populate principal.process with information about the process creating the mutex.  target:  Populate target.resource. Populate target.resource.type with MUTEX. Populate target.resource.name with the name of the mutex created.
Optional fields:  security_result: Describe the malicious activity detected. principal.user: Populate if user information is available about the process.
##### UDM example for MUTEX_CREATION
The following example illustrates how an event of type MUTEX_CREATION would be formatted for the Google SecOps UDM:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: MUTEX_CREATION
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "test.altostrat.com"
  process {
    pid: "0xc45"
    file {
      full_path: "C:\\Windows\\regedit.exe"
    }
  }
}
target {
  resource {
    type: "MUTEX"
    name: "test-mutex"
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device and process details. target: Information about the mutex.
### NETWORK_CONNECTION
Required fields:  metadata: event_timestamp principal: Include detail about the machine that initiated the network connection (for example, source). target: Include details about the target machine if different from the principal machine. network: Capture details about the network connection (ports, protocol, etc.).
Optional fields:  principal.process and target.process: Include process information associated with the principal and target of the network connection (if available). principal.user and target.user: Include user information associated with the principal and target of the network connection (if available).  Note: For all network events, if the principal or target has a port specified, the ip and mac fields must include only one value each (if available), that is the IP address and MAC associated with the port. Otherwise, if no port is specified, you can specify any number of IP and MAC addresses associated with the device at the time of the event (no particular order is required).
### NETWORK_HTTP
The NETWORK_HTTP event type represents an HTTP network connection from a principal to a target web server.
Required fields:  metadata: Include the required fields. target: Represents the web server. Include device information and an optional port number.  If a target port number is available, specify only one IP address in addition to the port number associated with that network connection (although multiple other machine identifiers could be provided for the target). For `target.url`, populate with the URL accessed.
Optional fields:  principal: Represents the client initiating the web request. Include at least one machine identifier (for example, hostname, IP, MAC, proprietary asset identifier) or a user identifier (for example, username).  If a specific network connection is described and a client port number is available, specify only one IP address along with the port number associated with that network connection (although other machine identifiers could be provided to better describe the participant device). If no source port is available, you could specify any and all IP and MAC addresses, asset identifiers, and hostname values describing the principal device.  network: Include details of the network connection. You must populate the following fields:  network.ip_protocol network.application_protocol  about: Represents other entities found in the HTTP transaction (for example, an uploaded or downloaded file). intermediary: Represents a proxy server (if different from the principal or target). metadata: Populate the other metadata fields. network: Populate other network fields. network.email: If the HTTP network connection originated from a URL that appeared in an email message, populate network.email with the details. network.http: If the HTTP network connection method is present, populate `network.http.method`. observer: Represents a passive sniffer (if present). security_result: Add one or more items to the security_result field to represent the malicious activity detected.
##### UDM example for NETWORK_HTTP
The following example illustrates how a Sophos antivirus event of type NETWORK_HTTP would be converted to the Google SecOps UDM format.
The following is the original Sophos antivirus event:
```
date=2013-08-07 time=13:27:41 timezone="GMT" device_name="CC500ia" device_id= C070123456-ABCDE log_id=030906208001 log_type="Anti-Virus" log_component="HTTP" log_subtype="Virus" status="" priority=Critical fw_rule_id=0 user_name="john.smith" iap=7 av_policy_name="" virus="TR/ElderadoB.A.78" url="altostrat.fr/img/logo.gif" domainname="altostrat.fr" src_ip=10.10.2.10 src_port=60671 src_country_code= dst_ip=203.0.113.31 dst_port=80 dst_country_code=FRA

```
Here is how you would format the same information in Proto3 using the Google SecOps UDM syntax:
```
metadata {
  event_timestamp: "2013-08-07T13:27:41+00:00"
  event_type: NETWORK_HTTP
  product_name: "Sophos Antivirus"
  product_log_id: "030906208001"
}

principal {
  hostname: "CC500ia"
  asset_id: "Sophos.AV:C070123456-ABCDE"
  ip: "10.10.2.10"
  port: 60671
  user {  userid: "john.smith" }
}

target {
  hostname: "altostrat.fr"
  ip: "203.0.113.31"
  port: 80
  url: "altostrat.fr/img/logo.gif"
}

network {
  ip_protocol: TCP
 }

security_result {
  about {
    url: "altostrat.fr/img/logo.gif"
    category: SOFTWARE_MALICIOUS
    category_details: "Virus"
    threat_name: "TR/ElderadoB.A.78"
    severity: HIGH                   # Google Security Operations-normalized severity
    severity_details: "Critical"    # Vendor-specific severity string
  }
}

additional { "dst_country_code" : "FRA", "iap" : "7" "fw_rule_id" : "0" }

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Security device that detected the event. target: Device that received the malicious software. network: Network information about the malicious host. security_result: Security details about the malicious software. additional: Vendor information outside the scope of the UDM.
### PROCESS_INJECTION, PROCESS_LAUNCH, PROCESS_OPEN, PROCESS_TERMINATION, PROCESS_UNCATEGORIZED
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. For process injection and process termination events, if available, principal.process must include information about the process initiating the action (for example, for a process launch event, principal.process must include details about the parent process if available).  target:  target.process: Includes information about the process that is being injected, opened, launched, or terminated. If the target process is remote, target must include at least one machine identifier for the target machine (for example, an IP address, MAC, hostname, or third-party asset identifier).
Optional fields:  security_result: Describe the malicious activity detected. principal.user and target.user: Populate the initiating process (principal) and the target process if the user information is available.
##### UDM example for PROCESS_LAUNCH
The following example illustrates how you would format a PROCESS_LAUNCH event using the Google SecOps UDM syntax:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: PROCESS_LAUNCH
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "altostrat.com"
}
target {
  process {
    pid: "0xc45"
    file {
      full_path: "C:\\Windows\\regedit.exe"
    }
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device details. target: Process details.
### PROCESS_MODULE_LOAD
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. principal.process: Process loading the module.  target:  target.process: Includes information about the process. target.process.file: Module loaded (for example, the DLL or shared object).
Optional fields:  security_result: Describe the malicious activity detected. principal.user: Populate if user information is available about the process.
##### UDM example for PROCESS_MODULE_LOAD
The following example illustrates how you would format a PROCESS_MODULE_LOAD event using the Google SecOps UDM syntax:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: PROCESS_MODULE_LOAD
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "example.com"
  process {
    pid: "0x123"
  }
}
target {
  process {
    pid: "0xc45"
    file {
      full_path: "C:\\Windows\\regedit.exe"
    }
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Details about the device and the process loading the module. target: Process and module details.
### PROCESS_PRIVILEGE_ESCALATION
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. principal.process: Process loading the module. principal.user: User loading the module.
Optional fields:  security_result: Describe the malicious activity detected.
##### UDM example for PROCESS_PRIVILEGE_ESCALATION
The following example illustrates how you would format a PROCESS_PRIVILEGE_ESCALATION event using the Google SecOps UDM syntax:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: PROCESS_PRIVILEGE_ESCALATION
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "example.com"
  process {
    pid: "0x123"
  }
  user {
    userid: "test"
    windows_sid: "ABCDEFGH-123456789-1111111-1000"
  }
}
target {
  process {
    pid: "0xc45"
    file {
      full_path: "C:\\Windows\\regedit.exe"
    }
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Details about the device, the user, and the process loading the module. target: Process and module details.
### REGISTRY_CREATION, REGISTRY_MODIFICATION, REGISTRY_DELETION
Required fields:  metadata: Include the required fields. principal:  At least one machine identifier. If a user-mode process performs the registry modification, principal.process must include information about the process modifying the registry. If a kernel process performs the registry modification, the principal must not include process information.  target:  target.registry: If the target registry is remote, target must include at least one identifier for the target machine (for example, an IP address, MAC, hostname, or third party asset identifier). target.registry.registry_key: All registry events must include the affected registry key.
Optional fields:  security_result: Describe the malicious activity detected. For example, a bad registry key. principal.user: Populate if user information is available about the process.
##### UDM example for REGISTRY_MODIFICATION
The following example illustrates how you would format a REGISTRY_MODIFICATION event in Proto3 using the Google SecOps UDM syntax:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: REGISTRY_MODIFICATION
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "test-win"
  user {
    userid: "test"
    windows_sid: "ABCDEFGH-123456789-1111111-1000"
  }
  process {
    pid: "0xc45"
    file {
      full_path: "C:\\Windows\\regedit.exe"
    }
  }
}
target {
  registry {
    registry_key: "\\REGISTRY\\USER\\TEST_USER\\Control Panel\\PowerCfg\\PowerPolicy"
    registry_value_name: "Description"
    registry_value_data: "For extending battery life."
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device, user, and process details. target: Registry entry affected by the modification.
### SCAN_FILE, SCAN_HOST, SCAN_PROCESS, SCAN_VULN_HOST, SCAN_VULN_NETWORK
Required fields:  metadata: event_timestamp and background information about the event. observer: Capture information about the scanner itself. If the scanner is remote, the machine details must be captured by the observer field. For a local scanner, leave empty. target: Capture information about the machine that holds the object being scanned. If a file is being scanned, target.file must capture information about the scanned file. If a process is being scanned, target.process must capture information about the scanned process. extensions: For SCAN_VULN_HOST and SCAN_VULN_NETWORK, define the vulnerability using the extensions.vuln field.
Optional fields:  principal: Represents the device initiating the connection and includes at least one machine identifier (for example, hostname, IP address, MAC address, proprietary asset identifier) or a user identifier. target: User detail about the target object (for example, file creator or process owner) should be captured in target.user. security_result: Describe the malicious activity detected.
##### UDM example for SCAN_HOST
The following example illustrates how an event of type SCAN_HOST would be formatted for the Google SecOps UDM:
```
metadata: {
  event_timestamp: {
    seconds: 1571386978
  }
  event_type: SCAN_HOST
  vendor_name: "vendor"
  product_name: "product"
  product_version: "1.0"
}
target: {
  hostname: "testHost"
  asset_id: "asset"
  ip: "192.168.200.200"
}
observer: {
  hostname: "testObserver"
  ip: "192.168.100.100"
}
security_result: {
  severity: LOW
  confidence: HIGH_CONFIDENCE
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. target: Device which received the malicious software. observer: Device which observes and reports on the event in question. security_result: Security details about the malicious software.
##### UDM example for SCAN_VULN_HOST
The following example illustrates how an event of type SCAN_VULN_HOST would be formatted for the Google SecOps UDM:
```
metadata: {
  event_timestamp: "2025-05-09T12:59:52.45298Z",
  event_type: 18005,
  product_name: "TestProduct",
  vendor_name: "TestVendor"
  },
principal {
  asset_id: "TEST:Mwl8ABcd",
  ip: "127.0.0.3",
  hostname: "TEST-Localhost",
  mac: ["02:00:00:00:00:01"]
  },
extensions: {
  vulns: {
    vulnerabilities: [
      {
      cve_id: "CVE-6l9VxQmz",
      vendor_vulnerability_id: "TEST:7gmCmFWX",
      name: "CVE pA7DzwPU",
      severity: 2,
      vendor: "TestVendor",
      last_found: "2025-05-09T14:59:52.45300Z",
      first_found: "2025-05-09T13:59:52.45300Z"
       }
      ]
    }
  }

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device that received the malicious software. extensions: Vulnerability details.
### SCHEDULED_TASK_CREATION, SCHEDULED_TASK_DELETION, SCHEDULED_TASK_DISABLE, SCHEDULED_TASK_ENABLE, SCHEDULED_TASK_MODIFICATION, SCHEDULED_TASK_UNCATEGORIZED
Required fields:  principal: For all SCHEDULED_TASK events, principal must include a machine identifier and a user identifier. target: Target must include a valid resource and a resource type defined as "TASK".
Optional fields:  security_result: Describe the malicious activity detected.
##### UDM example for SCHEDULED_TASK_CREATION
The following example illustrates how an event of type SCHEDULED_TASK_CREATION could be formatted for the Google SecOps UDM:
```
metadata: {
  event_timestamp: {
    seconds: 1577577998
  }
  event_type: SCHEDULED_TASK_CREATION
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal: {
  hostname: "fake-host.altostrat.com"
  user: {
    userid: "TestUser"
    windows_sid: "AB123CDE"
  }
  process {
    pid: "1234"
  }
}
target: {
  resource: {
    type: "TASK"
    name: "\\Adobe Acrobat Update Task"
  }
}
intermediary: {
  hostname: "fake-intermediary.altostrat.com"
}
security_result: {
  rule_name: "EventID: 6789"
  summary: "A scheduled task was created."
  severity: INFORMATIONAL
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device that scheduled the suspicious task. target: Software targeted by the suspicious task. intermediary: Intermediary involved with the suspicious task. security_result: Security details about the suspicious task.
### SETTING_UNCATEGORIZED, SETTING_CREATION, SETTING_MODIFICATION, SETTING_DELETION
Required fields:  principal: Must be present, non-empty, and include a machine identifier. target: Must be present, non-empty, and include a resource with its type specified as SETTING
##### UDM example for event type SETTING_MODIFICATION
The following example illustrates how an event of type SETTING_MODIFICATION would be formatted for the Google SecOps UDM:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: SETTING_MODIFICATION
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "test.win.com"
}
target {
  resource {
    type: "SETTING"
    name: "test-setting"
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Information about the device on which the setting modification occurred. target: Resource details.
### SERVICE_UNSPECIFIED, SERVICE_CREATION, SERVICE_DELETION, SERVICE_START, SERVICE_STOP
Required fields:  target: Include the user identifier and specify either process or application. principal: Include at least one machine identifier (IP or MAC ADDRESS, hostname, or asset identifier).
##### UDM example for SERVICE_UNSPECIFIED
The following example illustrates how an event of type SERVICE_UNSPECIFIED would be formatted for the Google SecOps UDM:
```
metadata: {
 event_timestamp: {
   seconds: 1595656745
   nanos: 832000000
    }
 event_type: SERVICE_UNSPECIFIED
   vendor_name: "Preempt"
   product_name: "PREEMPT_AUTH"
   product_event_type: "SERVICE_ACCESS"
   description: "Remote Procedures (RPC)"
   }
 principal: {
   hostname: "XXX-YYY-ZZZ"
   ip: "10.10.10.10"
   }
 target: {
   hostname: "TestHost"
   user: {
      userid: "ORG\\User"
      user_display_name: "user name"
   }
 application: "application.name"
   resource: {
      type: "Service Type"
      name: "RPC"
   }
 }

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device and location details. target: Hostname and user identifier. application: Application name and resource type.
### STATUS_HEARTBEAT, STATUS_STARTUP, STATUS_SHUTDOWN, STATUS_UPDATE
Required fields:  metadata: Include the required fields. principal: At least one machine identifier (IP or MAC ADDRESS, hostname, or asset identifier).
##### UDM example for STATUS_HEARTBEAT
The following example illustrates how an event of type STATUS_HEARTBEAT would be formatted for the Google SecOps UDM:
```
metadata: {
  event_timestamp: {
    seconds: 1588180305
  }
  event_type: STATUS_HEARTBEAT
  vendor_name: "DMP"
  product_name: "ENTRE"
}
principal: {
  hostname: "testHost"
  location: {
    name: "Building 1"
  }
}
intermediary: {
  ip: "8.8.8.8"
}
security_result: {
  summary: "Event - Locked"
  description: "description"
  severity: LOW
  severity_details: "INFO"
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device and location details. intermediary: Device IP address. security_result: Security result details.
### SYSTEM_AUDIT_LOG_UNCATEGORIZED, SYSTEM_AUDIT_LOG_WIPE
Required fields:  principal: Include a user identifier for the user who performed the operation on the log and a machine identifier for the machine where the log is or was (in the case of wiping) stored.
##### UDM example for SYSTEM_AUDIT_LOG_WIPE
The following example illustrates how an event of type SYSTEM_AUDIT_LOG_WIPE would be formatted for the Google SecOps UDM:
```
metadata {
  event_timestamp: "2020-01-01T13:27:41+00:00"
  event_type: SYSTEM_AUDIT_LOG_WIPE
  vendor_name: "Microsoft"
  product_name: "Windows"
}
principal {
  hostname: "altostrat.com"
  user {
    userid: "test"
    windows_sid: "ABCDEFGH-123456789-1111111-1000"
  }
}

```
As shown in this example, the event has been divided into the following UDM categories:  metadata: Background information about the event. principal: Device and user details.
### USER_CHANGE_PASSWORD, USER_CHANGE_PERMISSIONS
Required fields:  metadata: Include the required fields. principal: If the user account is modified from a remote location, populate principal with information about the machine from where the user modification originated. target: Populate target.user with information about the user that has been modified. intermediary: For SSO logins, intermediary must include at least one machine identifier for the SSO server if available.
### USER_COMMUNICATION
Required fields:  principal: Populate the principal.user field with details associated with user-initiated (sender) communication, such as a chat message in Google Chat or Slack, a video or voice conference in Zoom or Google Meet, or a VoIP connection.
Optional fields:  target: (Recommended) Populate the target.user field with information about the target user (receiver) of the cloud communication resource. Populate the target.application field with information about the target cloud communication application.
### USER_CREATION, USER_DELETION
Required fields:  metadata: event_timestamp. principal: Include information about the machine where the request to create or delete the user originated from. For a local user creation or deletion, principal must include at least one machine identifier for the originating machine. target: Location where the user is being created. Must also include user information (for example, target.user).
Optional fields:  principal: User and process details for the machine where the user creation or deletion request was initiated. target: Information about the target machine (if different than the principal machine).
### USER_LOGIN, USER_LOGOUT
Required fields:  metadata: Include the required fields. principal: For remote user activity (for example, remote login), populate principal with information about the machine originating the user activity. For local user activity (for example, local login), don't set principal. target: Populate target.user with information about the user that has logged on or logged off. If principal is not set (for example, local login), target must also include at least one machine identifier identifying the target machine. For machine to machine user activity (for example, remote login, SSO, Cloud Service, VPN), target must include information on either the target application, target machine, or target VPN server. intermediary: For SSO logins, intermediary must include at least one machine identifier for the SSO server if available. network and network.http: If the login occurs over HTTP, you must place all available details in network.ip_protocol, network.application_protocol, and network.http. authentication extension: Must identify the type of authentication system that the event is related to (for example, machine, SSO, or VPN) and the mechanism employed (username and password, OTP, etc.). security_result: Add a security_result field to represent the login status if it fails. Specify security_result.category with the AUTH_VIOLATION value if authentication fails.
### USER_RESOURCE_ACCESS
Required fields:  principal: Populate the principal.user field with details about attempts to access a cloud resource (for example, a Salesforce case, Office365 calendar, Google Doc, or ServiceNow ticket). target: Populate the target.resource field with information about the target cloud resource.
Optional fields:  target.application: (Recommended) Populate the target.application field with information about the target cloud application.
### USER_RESOURCE_CREATION, USER_RESOURCE_DELETION
Required fields:  principal: Populate the principal.user field with details associated with the user created within a cloud resource (for example, a Salesforce case, Office 365 calendar, Google Doc, or ServiceNow ticket). target: Populate the target.resource field with information about the target cloud resource.
Optional fields:  target.application: (Recommended) Populate the target.application field with information about the target cloud application.
### USER_RESOURCE_UPDATE_CONTENT
Required fields:  principal: Populate the principal.user field with details associated with the user whose content was updated within a cloud resource (for example, a Salesforce case, Office365 calendar, Google Doc, or ServiceNow ticket). target: Populate the target.resource field with information about the target cloud resource.
Optional fields:  target.application: (Recommended) Populate the target.application field with information about the target cloud application.
### USER_RESOURCE_UPDATE_PERMISSIONS
Required fields:  principal: Populate the principal.user field with details associated with the user whose permissions were updated within a cloud resource (for example, a Salesforce case, Office 365 calendar, Google Doc, or ServiceNow ticket). target: Populate the target.resource field with information about the target cloud resource.
Optional fields:  target.application: (Recommended) Populate the target.application field with information about the target cloud application.
### USER_UNCATEGORIZED
Required fields:  metadata: event_timestamp principal: Include information about the machine where the request to create or delete the user originated from. For a local user creation or deletion, principal must include at least one machine identifier for the originating machine. target: Location where the user is being created. Must also include user information (for example, target.user).
Optional fields:  principal: User and process details for the machine where the user creation or deletion request was initiated. target: Information about the target machine (if different than the principal machine).        Send feedback