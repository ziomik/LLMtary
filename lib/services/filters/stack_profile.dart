import '../../utils/json_parser.dart';

/// Capability axes of a target's technology stack that matter for deciding
/// whether a finding is applicable (part 4, contextual pre-validation filter).
///
/// Only the axes needed to drop categorically-foreign findings are modelled.
/// The "present-expected" services (web, mail, ssh) are tracked too so the
/// classifier can recognise them as applicable, but the drop logic keys off
/// the FOREIGN axes being ABSENT.
enum StackAxis {
  windowsAd, // Windows / Active Directory / Kerberos / LDAP DC / WinRM / SMB-domain
  orchestration, // Docker API / Kubernetes / etcd
  cloud, // AWS / GCP / Azure managed services (IAM, IMDS, S3, Lambda, ...)
  elasticsearch,
  icsModbus, // industrial control / Modbus / SCADA
  smb, // SMB/445 specifically
  web,
  mail, // SMTP/POP3/IMAP (e.g. mailcow)
  ssh,
  database,
  javaMiddleware, // Java app servers / RMI / IIOP / JMX / deserialization / AMF
  messageBroker, // ActiveMQ / RabbitMQ / Kafka / AMQP / STOMP / JMS
}

/// A deterministic, grounded summary of a target's stack, built ONLY from real
/// recon observations (device JSON). Reused by the applicability filter.
///
/// Mirrors the detection style already used by the `_has*` predicates in
/// vulnerability_analyzer (open_ports port/service/banner + full-text), kept
/// self-contained here so the filter is a pure, independently testable unit.
class StackProfile {
  final Set<StackAxis> present;

  /// Lower-cased OS string if known ('linux', 'windows', ...), else ''.
  final String os;

  /// Rough count of distinct evidence used to build the profile (open ports +
  /// detected technologies).
  final int signalStrength;

  /// Number of open ports that carried a service/banner/version fingerprint
  /// (e.g. from nmap -sV). Bare port numbers do NOT count.
  final int fingerprintedPorts;

  /// Number of detected web technologies (headers/CNAME/tech list).
  final int technologyCount;

  const StackProfile({
    required this.present,
    required this.os,
    required this.signalStrength,
    this.fingerprintedPorts = 0,
    this.technologyCount = 0,
  });

  bool has(StackAxis axis) => present.contains(axis);

  /// Whether the profile has enough signal to justify a categorical hard-drop.
  ///
  /// Requires actual SERVICE-LEVEL evidence (fingerprinted ports or detected
  /// technologies), not bare port numbers: a service may sit on a non-standard
  /// port, so "the standard port wasn't seen" is NOT sufficient grounds to
  /// conclude a platform is absent. A ports-only scan (no -sV) ⇒ not solid ⇒
  /// the filter stays permissive (deprioritize, never hard-drop).
  bool get solid => fingerprintedPorts >= 1 || technologyCount >= 1;

  // ---- detection tables (lower-case) ----
  // SMB (445/139, nmap `microsoft-ds` / `netbios-ssn`) is NOT evidence of Active
  // Directory: Samba on Linux and standalone Windows hosts expose it too. It only
  // marks the [StackAxis.smb] axis. Field case (southfront.press, Linux + Samba):
  // 445 open made AD "present", so 13 HIGH Kerberos/AD findings anchored only on
  // "port 445/tcp open" were judged applicable and survived the filter.
  static const _winAdPorts = {88, 389, 636, 464, 3268, 3269, 5985, 5986};
  static const _winAdServices = {'kerberos', 'ldap', 'msrpc', 'winrm', 'ldaps'};
  static const _winAdKeywords = [
    'active directory', 'kerberos', 'domain controller', 'winrm', 'netlogon'
  ];

  static const _orchPorts = {2375, 2376, 2379, 2380, 6443, 10250, 10255, 8001};
  static const _orchServices = {'docker', 'kubernetes', 'kubelet', 'etcd'};
  static const _orchKeywords = ['docker', 'kubernetes', 'kubelet', 'etcd', 'k8s', 'containerd'];

  static const _cloudKeywords = [
    's3.amazonaws', 'amazonaws.com', 'cloudfront', 'ec2', 'azureedge', 'azurefd',
    'azurewebsites', 'googleusercontent', 'appspot', 'gcp', 'cloudflare', 'fastly',
    'wpenginepowered', 'netlify', 'vercel'
  ];

  static const _esPorts = {9200, 9300};
  static const _esServices = {'elasticsearch', 'kibana'};
  static const _esKeywords = ['elasticsearch', 'kibana'];

  static const _icsPorts = {502, 44818, 2222, 47808, 102, 20000, 2404, 4840};
  static const _icsServices = {'modbus', 'dnp3', 'bacnet', 's7comm', 'enip', 'opc', 'iec104'};
  static const _icsKeywords = ['modbus', 'scada', 'plc', 'industrial control', 'ics'];

  static const _smbPorts = {445, 139};
  static const _smbServices = {'smb', 'microsoft-ds', 'netbios-ssn'};

  static const _webPorts = {80, 443, 8080, 8443, 8000, 8888};
  static const _webServices = {'http', 'https', 'http-proxy', 'http-alt'};

  static const _mailPorts = {25, 110, 143, 465, 587, 993, 995};
  static const _mailServices = {'smtp', 'pop3', 'imap', 'submission', 'smtps', 'imaps', 'pop3s'};

  static const _dbPorts = {3306, 5432, 1433, 27017, 6379, 5984};
  static const _dbServices = {'mysql', 'postgresql', 'ms-sql', 'mssql', 'mongodb', 'redis', 'couchdb'};

  static const _javaPorts = {1099, 1098, 7001, 8686, 8009, 9990, 4848, 8161};
  static const _javaServices = {'rmiregistry', 'java-rmi', 'jmx', 'jboss', 'weblogic', 'ajp13'};
  static const _javaKeywords = [
    'jboss', 'weblogic', 'websphere', 'glassfish', 'coldfusion', 'java rmi', 'rmiregistry'
  ];

  static const _brokerPorts = {61616, 5672, 9092, 61613, 1883, 15672, 5671, 8883};
  static const _brokerServices = {'amqp', 'kafka', 'activemq', 'rabbitmq', 'stomp', 'mqtt'};
  static const _brokerKeywords = ['activemq', 'rabbitmq', 'kafka', 'amqp'];

  /// Build a profile from a device JSON string (same shape the recon pipeline
  /// stores and the analyzer consumes).
  static StackProfile fromDeviceJson(String deviceJson) {
    final d = JsonParser.tryParseJson(deviceJson);
    if (d == null) {
      return const StackProfile(present: {}, os: '', signalStrength: 0);
    }
    return fromDeviceMap(d);
  }

  static StackProfile fromDeviceMap(Map<String, dynamic> d) {
    final present = <StackAxis>{};
    final ports = (d['open_ports'] as List?) ?? const [];
    final fullText = d.toString().toLowerCase();

    int portCount = 0;
    int fingerprinted = 0;
    for (final raw in ports) {
      if (raw is! Map) continue;
      portCount++;
      final port = raw['port'] is int
          ? raw['port'] as int
          : int.tryParse(raw['port']?.toString() ?? '') ?? 0;
      final service = (raw['service'] ?? '').toString().toLowerCase();
      final banner = (raw['banner'] ?? raw['version'] ?? raw['product'] ?? '')
          .toString()
          .toLowerCase();
      if (service.isNotEmpty || banner.isNotEmpty) fingerprinted++;

      // Service FINGERPRINT (nmap -sV service name or banner) is the PRIMARY
      // signal and is port-independent — Kerberos on a non-standard port is
      // still detected via its service/banner. The standard port is only a
      // weak additional hint, never the sole condition.
      void mark(StackAxis axis, Set<int> p, Set<String> s) {
        if (s.any((x) => service.contains(x) || banner.contains(x)) ||
            p.contains(port)) {
          present.add(axis);
        }
      }

      mark(StackAxis.windowsAd, _winAdPorts, _winAdServices);
      mark(StackAxis.orchestration, _orchPorts, _orchServices);
      mark(StackAxis.elasticsearch, _esPorts, _esServices);
      mark(StackAxis.icsModbus, _icsPorts, _icsServices);
      mark(StackAxis.smb, _smbPorts, _smbServices);
      mark(StackAxis.web, _webPorts, _webServices);
      mark(StackAxis.mail, _mailPorts, _mailServices);
      mark(StackAxis.database, _dbPorts, _dbServices);
      mark(StackAxis.javaMiddleware, _javaPorts, _javaServices);
      mark(StackAxis.messageBroker, _brokerPorts, _brokerServices);
      if (_javaKeywords.any(banner.contains)) present.add(StackAxis.javaMiddleware);
      if (_brokerKeywords.any(banner.contains)) present.add(StackAxis.messageBroker);
      if (port == 22 || service.contains('ssh')) present.add(StackAxis.ssh);

      // banner-based orchestration/es hints
      if (_orchKeywords.any(banner.contains)) present.add(StackAxis.orchestration);
      if (_esKeywords.any(banner.contains)) present.add(StackAxis.elasticsearch);
    }

    // Full-text (headers, CNAME, technologies, hostname) signals.
    final techs = (d['technologies'] ?? '').toString().toLowerCase();
    final haystack = '$fullText $techs';
    if (_winAdKeywords.any(haystack.contains)) present.add(StackAxis.windowsAd);
    if (_orchKeywords.any(haystack.contains)) present.add(StackAxis.orchestration);
    if (_cloudKeywords.any(haystack.contains)) present.add(StackAxis.cloud);
    if (_esKeywords.any(haystack.contains)) present.add(StackAxis.elasticsearch);
    if (_icsKeywords.any(haystack.contains)) present.add(StackAxis.icsModbus);
    if (_javaKeywords.any(haystack.contains)) present.add(StackAxis.javaMiddleware);
    if (_brokerKeywords.any(haystack.contains)) present.add(StackAxis.messageBroker);

    // technologies strings also imply web stack
    final techCount = techs.isEmpty ? 0 : techs.split(RegExp(r'[,\s]+')).where((x) => x.isNotEmpty).length;

    var os = (d['os'] ?? d['osName'] ?? '').toString().toLowerCase().trim();
    // Keep only a coarse token.
    if (os.contains('linux')) {
      os = 'linux';
    } else if (os.contains('windows')) {
      os = 'windows';
    }

    return StackProfile(
      present: present,
      os: os,
      signalStrength: portCount + techCount,
      fingerprintedPorts: fingerprinted,
      technologyCount: techCount,
    );
  }
}
