import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/filters/stack_profile.dart';
import 'package:llmtary/services/filters/applicability_filter.dart';
import 'package:llmtary/services/vulnerability_analyzer.dart';

/// A southfront.press-like stack: WordPress + nginx + PHP + mailcow on Linux.
const _southfrontDevice = '''
{
  "os": "Linux",
  "open_ports": [
    {"port": 80, "service": "http"},
    {"port": 443, "service": "https", "product": "nginx 1.29.1"},
    {"port": 22, "service": "ssh"},
    {"port": 25, "service": "smtp"},
    {"port": 587, "service": "submission"},
    {"port": 993, "service": "imaps"},
    {"port": 995, "service": "pop3s"}
  ],
  "technologies": "wordpress, php, nginx"
}
''';

// Real foreign-platform templates from the southfront.press dump (LOW noise).
const _foreignLowFindings = [
  'AS-REP Roasting over internet-facing Kerberos',
  'DCSync over internet-facing Kerberos',
  'WinRM / WMI Lateral Movement over internet-facing Kerberos',
  'Kerberoasting over internet-facing Kerberos',
  'Pass-the-Hash over internet-facing Kerberos',
  'LDAP Null Bind on Internet-Facing DC',
  'Netlogon Authentication Bypass over internet-facing Kerberos',
  'Password Spraying over Internet-Facing Kerberos',
  'Docker API Exposed Without Authentication',
  'Exposed Docker API',
  'Publicly Accessible Kubernetes API Server',
  'Privileged Pods or Containers',
  'Unauthenticated Elasticsearch Access',
  'Accesso non autenticato a Elasticsearch',
  'IMDSv1 Exposure',
  'Overprivileged IAM Role',
  'Publicly Exposed Function URLs',
  'Externally Exposed Modbus Protocol',
  'Industrial Control System Protocol Detected — Safety Advisory',
  'Externally Exposed Port 445 (SMB)',
  'Externally Exposed SMB Service',
];

// Real applicable findings (the 6 HIGH live here) — must NEVER be dropped.
const _applicableFindings = [
  'WordPress XML-RPC Credential Attack',
  'WordPress Plugin/Theme Vulnerabilities',
  'WordPress Login Form Brute Force',
  'Application Configuration File Exposure: PHP wp-config.php',
  'Weak SSL/TLS Cipher Suites',
  'HTTP Security Headers: Missing Content-Security-Policy',
  'Host Header Injection via Password Reset',
  'Username Enumeration',
  'Missing Account Lockout Policy',
  'Password Spray Attack Surface', // generic — NOT the Kerberos one
  'Potential SSRF Vulnerability',
  'Email Security Records',
  'Externally Exposed POP3 Service', // TRAP: mailcow really exposes POP3
  'Externally Exposed Service: SSH',
];

void main() {
  late StackProfile southfront;

  setUp(() {
    southfront = StackProfile.fromDeviceJson(_southfrontDevice);
  });

  group('StackProfile.fromDeviceJson (southfront-like)', () {
    test('detects present axes and marks foreign ones absent', () {
      expect(southfront.has(StackAxis.web), isTrue);
      expect(southfront.has(StackAxis.mail), isTrue);
      expect(southfront.has(StackAxis.ssh), isTrue);
      expect(southfront.os, 'linux');
      expect(southfront.solid, isTrue);

      expect(southfront.has(StackAxis.windowsAd), isFalse);
      expect(southfront.has(StackAxis.orchestration), isFalse);
      expect(southfront.has(StackAxis.cloud), isFalse);
      expect(southfront.has(StackAxis.elasticsearch), isFalse);
      expect(southfront.has(StackAxis.icsModbus), isFalse);
      expect(southfront.has(StackAxis.smb), isFalse);
    });
  });

  group('ApplicabilityFilter — southfront projection', () {
    test('every foreign LOW template is dropped', () {
      for (final f in _foreignLowFindings) {
        final o = ApplicabilityFilter.decide(
            text: f, confidence: 'LOW', stack: southfront);
        expect(o.decision, FilterDecision.drop, reason: 'should drop: $f');
        expect(o.applicability, Applicability.inapplicableCategorical);
      }
    });

    test('every applicable finding is kept (incl. the POP3 trap)', () {
      for (final f in _applicableFindings) {
        final o = ApplicabilityFilter.decide(
            text: f, confidence: 'LOW', stack: southfront);
        expect(o.decision, FilterDecision.keep, reason: 'should keep: $f');
      }
    });

    test('generic password spray kept, Kerberos password spray dropped', () {
      expect(
          ApplicabilityFilter.decide(
                  text: 'Password Spray Attack Surface',
                  confidence: 'LOW',
                  stack: southfront)
              .decision,
          FilterDecision.keep);
      expect(
          ApplicabilityFilter.decide(
                  text: 'Password Spraying over Internet-Facing Kerberos',
                  confidence: 'LOW',
                  stack: southfront)
              .decision,
          FilterDecision.drop);
    });
  });

  group('confidence policy', () {
    test('HIGH categorical is kept and flagged as a contradiction', () {
      final o = ApplicabilityFilter.decide(
          text: 'DCSync over internet-facing Kerberos',
          confidence: 'HIGH',
          stack: southfront);
      expect(o.decision, FilterDecision.keep);
      expect(o.contradiction, isTrue);
    });

    test('MEDIUM categorical is deprioritized, not dropped', () {
      final o = ApplicabilityFilter.decide(
          text: 'Exposed Docker API', confidence: 'MEDIUM', stack: southfront);
      expect(o.decision, FilterDecision.deprioritize);
    });
  });

  group('thin-stack permissiveness', () {
    test('categorical becomes uncertain when stack signal is thin', () {
      final thin = StackProfile.fromDeviceJson('{"open_ports": []}');
      expect(thin.solid, isFalse);
      final o = ApplicabilityFilter.decide(
          text: 'DCSync over internet-facing Kerberos',
          confidence: 'LOW',
          stack: thin);
      // Not dropped — thin recon must not hard-drop.
      expect(o.decision, FilterDecision.deprioritize);
      expect(o.applicability, Applicability.uncertain);
    });
  });

  group('VulnerabilityAnalyzer.applyContextualFilter wiring', () {
    Vulnerability vuln(String problem, String conf) => Vulnerability(
          problem: problem,
          description: '',
          severity: 'MEDIUM',
          confidence: conf,
          evidence: '',
          recommendation: '',
        );

    test('drops foreign LOW, keeps applicable, POP3 trap, and HIGH foreign', () {
      final analyzer = VulnerabilityAnalyzer();
      final vulns = [
        vuln('DCSync over internet-facing Kerberos', 'LOW'), // dropped
        vuln('WordPress XML-RPC Credential Attack', 'LOW'), // kept
        vuln('Externally Exposed POP3 Service', 'LOW'), // kept (trap)
        vuln('Exposed Docker API', 'HIGH'), // kept (contradiction, never dropped)
      ];
      final kept =
          analyzer.applyContextualFilter(vulns, _southfrontDevice).map((v) => v.problem).toSet();
      expect(kept, isNot(contains('DCSync over internet-facing Kerberos')));
      expect(kept, contains('WordPress XML-RPC Credential Attack'));
      expect(kept, contains('Externally Exposed POP3 Service'));
      expect(kept, contains('Exposed Docker API'));
      expect(kept.length, 3);
    });
  });

  // The filter is GENERIC/capability-driven, NOT tuned for southfront: the SAME
  // finding flips verdict based on what recon actually detected. A finding that
  // is foreign (dropped) on WordPress+mail is APPLICABLE (kept) on a target
  // whose stack really has that platform.
  group('genericity — capability-driven, symmetric across any target', () {
    test('real AD target keeps the Kerberos finding that southfront dropped', () {
      final ad = StackProfile.fromDeviceJson('''
        {"os": "Windows", "open_ports": [
          {"port": 88, "service": "kerberos"},
          {"port": 389, "service": "ldap"},
          {"port": 445, "service": "microsoft-ds"},
          {"port": 3268, "service": "ldap"}
        ]}''');
      expect(ad.has(StackAxis.windowsAd), isTrue);
      // Kept here (AD present); it was dropped on the WordPress+mail stack.
      expect(
          ApplicabilityFilter.decide(
                  text: 'DCSync over internet-facing Kerberos',
                  confidence: 'LOW',
                  stack: ad)
              .decision,
          FilterDecision.keep);
      // And a cloud finding with no cloud on this AD box is still dropped.
      expect(
          ApplicabilityFilter.decide(
                  text: 'Overprivileged IAM Role', confidence: 'LOW', stack: ad)
              .decision,
          FilterDecision.drop);
    });

    test('real cloud target keeps the AWS/IAM finding', () {
      final cloud = StackProfile.fromDeviceJson('''
        {"os": "Linux", "open_ports": [{"port": 443, "service": "https"}],
         "technologies": "aws ec2",
         "hostname": "ec2-1-2-3-4.compute.amazonaws.com"}''');
      expect(cloud.has(StackAxis.cloud), isTrue);
      expect(
          ApplicabilityFilter.decide(
                  text: 'Overprivileged IAM Role', confidence: 'LOW', stack: cloud)
              .decision,
          FilterDecision.keep);
    });

    test('real Kubernetes target keeps the K8s finding', () {
      final orch = StackProfile.fromDeviceJson('''
        {"os": "Linux", "open_ports": [
          {"port": 6443, "service": "kubernetes"},
          {"port": 2375, "service": "docker"}
        ]}''');
      expect(orch.has(StackAxis.orchestration), isTrue);
      expect(
          ApplicabilityFilter.decide(
                  text: 'Publicly Accessible Kubernetes API Server',
                  confidence: 'LOW',
                  stack: orch)
              .decision,
          FilterDecision.keep);
    });
  });

  // Service FINGERPRINT is primary, port number is only a weak hint: a service
  // on a non-standard port is still detected; a ports-only scan (no -sV) must
  // not hard-drop, because "standard port absent" doesn't prove the service is.
  group('fingerprint primary, port weak hint', () {
    test('Kerberos on a NON-standard port is detected by service name', () {
      final ad = StackProfile.fromDeviceJson(
          '{"os":"Linux","open_ports":[{"port":2088,"service":"kerberos-sec"}]}');
      expect(ad.has(StackAxis.windowsAd), isTrue);
      expect(
          ApplicabilityFilter.decide(
                  text: 'Kerberoasting over internet-facing Kerberos',
                  confidence: 'LOW',
                  stack: ad)
              .decision,
          FilterDecision.keep);
    });

    test('platform detected from a banner even with a generic service field', () {
      final ad = StackProfile.fromDeviceJson(
          '{"os":"Linux","open_ports":[{"port":12345,"service":"unknown",'
          '"banner":"Microsoft Windows Active Directory LDAP"}]}');
      expect(ad.has(StackAxis.windowsAd), isTrue);
    });

    test('bare ports-only scan is not solid → deprioritize, never hard-drop', () {
      // Open ports with NO service/banner (no -sV). Even without the standard
      // AD ports, we must not conclude AD is absent.
      final bare = StackProfile.fromDeviceJson(
          '{"os":"Linux","open_ports":[{"port":443},{"port":8080},{"port":9999}]}');
      expect(bare.solid, isFalse);
      final o = ApplicabilityFilter.decide(
          text: 'DCSync over internet-facing Kerberos',
          confidence: 'LOW',
          stack: bare);
      expect(o.decision, FilterDecision.deprioritize);
      expect(o.applicability, Applicability.uncertain);
    });
  });
}
