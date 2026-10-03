const eventSeeds = [
  {
    source: 'Storage-Node-01', sourceIp: '192.168.1.104', category: 'Brute Force Attempt', description: 'Multiple failed authentication attempts', severity: 'HIGH', status: 'Blocked',
    detectionReason: 'Authentication failures exceeded the configured threshold within a short time window.', riskScore: 78, response: 'Credentials blocked and source rate-limited. Review the account and confirm no successful login occurred.',
  },
  {
    source: 'Cloud-Gateway-02', sourceIp: '10.0.4.52', category: 'Data Exfiltration Suspect', description: 'Unusual outbound traffic detected', severity: 'CRITICAL', status: 'Investigating',
    detectionReason: 'Outbound transfer volume and destination deviated significantly from the node baseline.', riskScore: 94, response: 'Isolate the gateway after analyst confirmation; preserve network and access logs for investigation.',
  },
  {
    source: 'Storage-Node-Alpha', sourceIp: '10.0.2.18', category: 'Backup Integrity Check', description: 'Immutable backup verification completed', severity: 'INFO', status: 'Resolved',
    detectionReason: 'Scheduled integrity verification confirmed the snapshot hash matches the trusted manifest.', riskScore: 8, response: 'No action required. Retain verification evidence in the audit log.',
  },
  {
    source: 'Workstation-04', sourceIp: '10.0.4.52', category: 'Unusual Port Scan', description: 'Multiple connection attempts detected', severity: 'MEDIUM', status: 'Monitoring',
    detectionReason: 'Sequential connection attempts were observed across protected service ports.', riskScore: 56, response: 'Continue monitoring; restrict the source if scanning persists or reaches protected nodes.',
  },
  {
    source: 'Auth-Server-01', sourceIp: '10.0.1.15', category: 'Multiple Failed Logins', description: 'Repeated authentication failures', severity: 'LOW', status: 'Resolved',
    detectionReason: 'A short burst of failed logins matched a known low-confidence authentication anomaly.', riskScore: 24, response: 'Confirm user identity and retain event context for correlation with future alerts.',
  },
  {
    source: 'Backup-Proxy-03', sourceIp: '10.0.3.27', category: 'Snapshot Policy Change', description: 'Retention policy modification detected', severity: 'HIGH', status: 'Investigating',
    detectionReason: 'A protected snapshot retention setting was modified outside the approved change window.', riskScore: 82, response: 'Validate the change request and restore the approved policy if the change is unauthorized.',
  },
  {
    source: 'Core-Firewall-01', sourceIp: '172.16.8.11', category: 'Malware Signature Match', description: 'Known malicious payload blocked at perimeter', severity: 'CRITICAL', status: 'Blocked',
    detectionReason: 'Network inspection matched a high-confidence malware signature on inbound traffic.', riskScore: 91, response: 'Verify endpoint health and search adjacent systems for the same payload fingerprint.',
  },
  {
    source: 'Recovery-Node-02', sourceIp: '10.0.2.42', category: 'Recovery Test Complete', description: 'Isolated recovery test completed successfully', severity: 'INFO', status: 'Resolved',
    detectionReason: 'Automated recovery validation completed with expected files and checksums.', riskScore: 6, response: 'Archive the recovery test result and keep the verified restore point available.',
  },
]

const timestamps = ['14:22:03', '14:15:46', '13:58:12', '13:42:58', '13:30:05', '13:18:39', '12:56:24', '12:41:09', '12:22:37', '12:04:51']

export const securityEventRecords = Array.from({ length: 1284 }, (_, index) => {
  const seed = eventSeeds[index % eventSeeds.length]
  const eventNumber = 9021 - index
  const minutesAgo = index * 7
  return {
    ...seed,
    id: `EVT-${eventNumber}`,
    timestamp: timestamps[index % timestamps.length],
    date: index < 9 ? '2026-09-26' : '2026-09-25',
    minutesAgo,
    relatedEvents: [
      `EVT-${eventNumber - 1}`,
      ...(seed.severity === 'CRITICAL' || seed.severity === 'HIGH' ? [`EVT-${eventNumber - 4}`] : []),
    ],
  }
})

export const eventSummary = [
  { label: 'Total Events', value: '1,284', support: '+8.4% from previous period', icon: 'activity', tone: 'cyan' },
  { label: 'Critical Events', value: '12', support: '3 require immediate review', icon: 'alert', tone: 'red' },
  { label: 'Unresolved', value: '37', support: '5 high-priority investigations', icon: 'clock', tone: 'amber' },
  { label: 'Events Today', value: '246', support: '18% below daily average', icon: 'calendar', tone: 'green' },
  { label: 'Monitored Nodes', value: '18', support: 'All nodes reporting normally', icon: 'nodes', tone: 'cyan' },
]

export const eventActivityByPeriod = {
  '1H': [
    { time: '14:00', events: 18, critical: 2 }, { time: '14:10', events: 28, critical: 4 }, { time: '14:20', events: 21, critical: 3 },
    { time: '14:30', events: 34, critical: 5 }, { time: '14:40', events: 25, critical: 2 }, { time: '14:50', events: 39, critical: 6 },
  ],
  '6H': [
    { time: '09:00', events: 22, critical: 2 }, { time: '10:00', events: 35, critical: 4 }, { time: '11:00', events: 27, critical: 3 },
    { time: '12:00', events: 48, critical: 8 }, { time: '13:00', events: 39, critical: 5 }, { time: '14:00', events: 55, critical: 9 },
  ],
  '24H': [
    { time: '00:00', events: 23, critical: 2 }, { time: '04:00', events: 34, critical: 3 }, { time: '08:00', events: 29, critical: 3 },
    { time: '12:00', events: 51, critical: 8 }, { time: '16:00', events: 43, critical: 6 }, { time: '20:00', events: 36, critical: 4 }, { time: '23:59', events: 28, critical: 3 },
  ],
  '7D': [
    { time: '20 Sep', events: 31, critical: 3 }, { time: '21 Sep', events: 46, critical: 6 }, { time: '22 Sep', events: 38, critical: 4 },
    { time: '23 Sep', events: 58, critical: 9 }, { time: '24 Sep', events: 42, critical: 5 }, { time: '25 Sep', events: 51, critical: 7 }, { time: '26 Sep', events: 44, critical: 5 },
  ],
}

export const eventFilterOptions = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  categories: [...new Set(eventSeeds.map(({ category }) => category))],
  statuses: ['Investigating', 'Monitoring', 'Blocked', 'Resolved'],
  sources: [...new Set(eventSeeds.map(({ source }) => source))],
}
