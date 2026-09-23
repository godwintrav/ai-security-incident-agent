# Network Security

## Purpose

Network security investigation involves understanding communications between systems and identifying activity that is unusual, suspicious, or potentially malicious.

For this project, network evidence helps the investigation agent correlate hosts, users, processes, destinations, and timing.

## Common Network Evidence

Useful evidence includes:

- Network flow logs
- Firewall logs
- Proxy logs
- DNS logs
- Source IP
- Destination IP
- Source and destination ports
- Protocol
- Domain
- URL
- Timestamp
- Connection frequency
- Data volume
- Associated host or user
- Responsible process, when available

## Normal vs Suspicious Activity

Network activity should be interpreted in context.

A connection can be unusual because:

- The destination is new for the host
- The port is unexpected
- The connection occurs at an unusual time
- The connection frequency changes
- The destination is associated with known suspicious infrastructure
- The volume of transferred data is unusual

Unusual activity is not automatically malicious.

## Network Investigation Approach

### 1. Identify the Communication

Determine:

- Source
- Destination
- Port
- Protocol
- Time
- Frequency
- Data volume

### 2. Establish Context

Determine whether the communication is expected for:

- The host
- The application
- The user
- The environment
- The destination

### 3. Correlate Endpoint Evidence

Where available, identify the process responsible for the connection and correlate its activity with:

- Process creation
- File activity
- Authentication
- DNS queries
- Endpoint alerts

### 4. Investigate Related Activity

Search for other systems communicating with the same destination or showing related indicators.

## Network Indicators

Potential IOCs include:

- IP addresses
- Domains
- URLs
- Ports
- DNS names

The value should be recorded together with the evidence that makes it relevant.

## Potential Activity Categories

Evidence may support investigation of:

- Suspicious communication
- Scanning
- Lateral movement
- Command-and-control behavior
- Possible data transfer or exfiltration

These should not be asserted without supporting evidence.

## MITRE ATT&CK Concepts

MITRE ATT&CK includes network-related techniques under several tactics. For example, System Network Connections Discovery (T1049) describes obtaining information about network connections to or from systems.

Network Sniffing (T1040) describes passively monitoring network traffic and may expose authentication material or network information.

## Investigation Questions

- Who initiated the connection?
- What was the destination?
- Was the destination expected?
- What process generated the connection?
- How often did it occur?
- Was there unusual data transfer?
- Did other systems communicate with the same destination?
- Are there related DNS, endpoint, or authentication events?

## Important Principle

Do not conclude that a connection is malicious solely because it is unfamiliar or externally hosted.

Network findings should be evidence-backed and should distinguish observation from assessment.

## Sources

- MITRE ATT&CK — System Network Connections Discovery (T1049)
- MITRE ATT&CK — Network Sniffing (T1040)
- MITRE ATT&CK — Discovery (TA0007)
- NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations
