# MITRE ATT&CK — Suspicious Network Activity

## Purpose

This document contains MITRE ATT&CK techniques relevant to investigating unusual or potentially malicious network activity.

Network behavior should be interpreted using host, application, user, timing, and destination context.

---

## T1049 — System Network Connections Discovery

### Description

Adversaries may attempt to obtain information about network connections from a system.

### Investigation Relevance

Consider this technique when endpoint evidence indicates commands or processes inspecting active network connections.

### Potential Evidence

- Network connection listings
- Command execution
- Process activity
- Endpoint telemetry
- User context

### Potential IOCs

- Process names
- Command lines
- Hostnames

---

## T1040 — Network Sniffing

### Description

Adversaries may attempt to capture network traffic to obtain information transmitted across networks.

### Investigation Relevance

Consider this technique when evidence indicates unauthorized network traffic capture or sniffing.

### Potential Evidence

- Packet capture activity
- Network monitoring processes
- Suspicious tools
- Interface configuration
- Endpoint telemetry

### Potential IOCs

- Process names
- File hashes
- File paths
- Hostnames

---

## T1071 — Application Layer Protocol

### Description

Adversaries may communicate with systems using application-layer protocols to blend command-and-control traffic into normal network traffic.

### Relevant Sub-techniques

Examples include:

- T1071.001 — Web Protocols
- T1071.002 — File Transfer Protocols
- T1071.003 — Mail Protocols
- T1071.004 — DNS

### Investigation Relevance

Consider this technique when suspicious network connections use common application protocols but display unusual destinations, frequency, timing, or content.

### Potential Evidence

- DNS logs
- Proxy logs
- Firewall logs
- Network flows
- Destination domains
- Connection frequency
- Endpoint process information

### Potential IOCs

- IP addresses
- Domains
- URLs
- Ports

---

## T1095 — Non-Application Layer Protocol

### Description

Adversaries may use non-application-layer protocols to communicate with systems.

### Investigation Relevance

Consider this technique when network traffic uses unexpected protocols or patterns that do not correspond to normal application-layer communication.

### Potential Evidence

- Network flow logs
- Firewall logs
- Packet data
- Source/destination information
- Endpoint process information

### Potential IOCs

- IP addresses
- Ports
- Protocols
- Hostnames

---

## T1041 — Exfiltration Over C2 Channel

### Description

Adversaries may steal data over an existing command-and-control channel.

### Investigation Relevance

Consider this technique when evidence suggests that data was transferred to an external destination through an established suspicious communication channel.

### Potential Evidence

- Network flows
- Data-transfer volumes
- Destination information
- Process activity
- File access
- Proxy logs

### Potential IOCs

- Destination IP addresses
- Domains
- URLs
- Hostnames

---

## T1021 — Remote Services

### Description

Adversaries may use legitimate remote services to access systems.

### Relevant Sub-techniques

Examples include:

- T1021.001 — Remote Services: RDP
- T1021.002 — SMB/Windows Admin Shares
- T1021.004 — SSH
- T1021.005 — VNC

### Investigation Relevance

Consider this technique when suspicious remote access or lateral movement is observed.

### Potential Evidence

- Authentication logs
- Remote-session logs
- Source and destination hosts
- Source IP
- Account information
- Process activity

### Potential IOCs

- Source IP addresses
- Usernames
- Hostnames
- Destination systems

---

## Investigation Guidance

Network investigation should correlate:

```text
Source
  ↓
Destination
  ↓
Protocol / Port
  ↓
Time / Frequency
  ↓
Responsible Host
  ↓
Responsible Process
  ↓
Related Endpoint Activity
```

An unfamiliar external connection is not automatically malicious.

The investigation should distinguish:

1. Observed network activity
2. Unusual network activity
3. Suspicious network activity
4. Activity supported by threat intelligence or correlated evidence
5. Confirmed malicious behavior

## Related Tactics

- Discovery
- Command and Control
- Lateral Movement
- Exfiltration

## Sources

MITRE ATT&CK Enterprise techniques:

- T1049 — System Network Connections Discovery
- T1040 — Network Sniffing
- T1071 — Application Layer Protocol
- T1095 — Non-Application Layer Protocol
- T1041 — Exfiltration Over C2 Channel
- T1021 — Remote Services
