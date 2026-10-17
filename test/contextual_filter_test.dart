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
}
