# Suspicious Network Activity Investigation Playbook

## Objective

Determine whether observed network activity is unusual or potentially malicious, identify relevant network indicators, establish affected systems and connections, and identify evidence required for further investigation.

## When to Use

Use this playbook when an incident involves:

- Unexpected outbound connections
- Unusual inbound traffic
- Connections to suspicious domains or IP addresses
- Unusual ports or protocols
- Unexpected data transfers
- Repeated connections to an external destination
- Network activity inconsistent with normal system behavior

## Initial Evidence

Prioritize collecting:

- Network flow logs
- Firewall logs
- Proxy logs
- DNS logs
- Source IP addresses
- Destination IP addresses
- Domains
- Ports
- Protocols
- Timestamps
- Byte counts
- Associated host and user information
- Process or application responsible for the connection, when available

## Investigation Steps

### 1. Identify the connection

Determine source host, source IP, destination host, destination IP, destination domain, port, protocol, timestamp, connection frequency, and data volume.

### 2. Establish whether the activity is unusual

Compare the observed activity against available context:

- Normal traffic patterns
- Known business services
- Expected destinations
- Historical connections
- Known internal infrastructure

Unusual does not automatically mean malicious.

### 3. Extract network IOCs

Potential IOCs include IP addresses, domains, URLs, ports, and network destinations.

Record them with the evidence supporting each IOC.

### 4. Identify the responsible system or process

Where possible, determine the host generating the traffic, associated user, process or application, parent process, and related endpoint events.

### 5. Investigate destination information

Where appropriate, use available intelligence or external lookup tools to investigate IP reputation, domain reputation, known malicious infrastructure, related vulnerabilities, or historical occurrence in other incidents.

Do not treat reputation data alone as definitive proof of compromise.

### 6. Investigate related activity

Look for other hosts communicating with the same destination, DNS lookups for the same domain, repeated connections, authentication activity, process execution near the connection time, file downloads, and large or unusual data transfers.

### 7. Assess potential impact

Determine whether the evidence indicates suspicious communication, possible command-and-control activity, possible data transfer, potential scanning, or potential lateral movement.

The assessment must remain proportional to the available evidence.

### 8. Identify missing evidence

Examples include full network flow logs, DNS logs, firewall logs, endpoint process information, proxy logs, historical network activity, destination intelligence, and data-transfer details.

## Expected Outputs

The investigation should attempt to establish:

- Incident classification
- Severity
- Affected systems
- Network indicators
- Evidence-backed findings
- Potential activity category
- Missing evidence
- Recommended next investigation steps
- Confidence level

## Important Investigation Principle

An unusual network connection is not automatically malicious.

Distinguish between observed network activity, unusual activity, suspicious activity, and activity supported by additional evidence as potentially malicious.

Avoid claiming command-and-control, data exfiltration, or compromise without supporting evidence.
