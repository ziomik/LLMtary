import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/actions/pentest_action.dart';
import 'package:llmtary/services/actions/action_schema.dart';
import 'package:llmtary/services/actions/action_executor.dart';
import 'package:llmtary/services/actions/session_state.dart';

void main() {
  group('PentestAction.fromJson', () {
    test('parses recon_scan with profile and ports', () {
      final a = PentestAction.fromJson({
        'action': 'recon_scan',
        'target': '10.0.0.5',
        'profile': 'full',
        'ports': [80, 443, 70000, 'x'], // 70000 and 'x' dropped
      });
      expect(a, isA<ReconScan>());
      final r = a as ReconScan;
      expect(r.target, '10.0.0.5');
      expect(r.profile, ReconProfile.full);
      expect(r.ports, [80, 443]);
    });

    test('recon_scan defaults profile to quick on unknown value', () {
      final r = PentestAction.fromJson({
            'action': 'recon_scan',
            'target': 'host.example',
            'profile': 'bogus',
          }) as ReconScan;
      expect(r.profile, ReconProfile.quick);
      expect(r.ports, isNull);
    });

    test('parses service_probe', () {
      final p = PentestAction.fromJson({
            'action': 'service_probe',
            'target': '10.0.0.5',
            'port': 443,
            'probe': 'tls',
          }) as ServiceProbe;
      expect(p.port, 443);
      expect(p.probe, ProbeKind.tls);
    });

    test('parses conclude', () {
      final c = PentestAction.fromJson({
            'action': 'conclude',
            'reason': 'nothing here',
            'host_useful': false,
          }) as ConcludeAction;
      expect(c.hostUseful, false);
      expect(c.reason, 'nothing here');
    });

    test('returns null for unknown action / missing fields / bad port', () {
      expect(PentestAction.fromJson({'action': 'nope'}), isNull);
      expect(PentestAction.fromJson({'action': 'recon_scan'}), isNull);
      expect(
          PentestAction.fromJson(
              {'action': 'service_probe', 'target': 'x', 'port': 0}),
          isNull);
      expect(
          PentestAction.fromJson(
              {'action': 'service_probe', 'target': 'x', 'port': 99999}),
          isNull);
    });

    test('round-trips through toJson', () {
      final orig = ReconScan(
          target: '1.2.3.4', profile: ReconProfile.script, ports: [22]);
      final back = PentestAction.fromJson(orig.toJson()) as ReconScan;
      expect(back.target, orig.target);
      expect(back.profile, orig.profile);
      expect(back.ports, orig.ports);
    });
  });

  group('ActionExecutor.sanitizeTarget', () {
    test('accepts valid IPv4, hostname, IPv6', () {
      expect(ActionExecutor.sanitizeTarget('192.168.1.10'), '192.168.1.10');
      expect(ActionExecutor.sanitizeTarget('host.example.com'),
          'host.example.com');
      expect(ActionExecutor.sanitizeTarget('fe80::1'), 'fe80::1');
    });

    test('rejects shell metacharacters and injection attempts', () {
      for (final bad in [
        '10.0.0.1; rm -rf /',
        r'$(whoami)',
        '10.0.0.1 && cat /etc/passwd',
        '`id`',
        'a|b',
        'host name',
        '10.0.0.1/24#',
        "'quoted'",
      ]) {
        expect(ActionExecutor.sanitizeTarget(bad), isNull, reason: bad);
      }
    });
  });

  group('ActionExecutor.toCommand', () {
    test('recon profiles map to deterministic nmap commands', () {
      expect(
          ActionExecutor.toCommand(
                  ReconScan(target: '10.0.0.5', profile: ReconProfile.quick))!
              .command,
          'nmap -Pn -T4 --top-ports 1000 10.0.0.5');
      expect(
          ActionExecutor.toCommand(
                  ReconScan(target: '10.0.0.5', profile: ReconProfile.full))!
              .command,
          'nmap -Pn -T4 -p- 10.0.0.5');
      expect(
          ActionExecutor.toCommand(
                  ReconScan(target: '10.0.0.5', profile: ReconProfile.udp))!
              .command,
          'nmap -Pn -sU -T4 --top-ports 100 10.0.0.5');
    });

    test('explicit ports override profile selection and are sorted', () {
      final cmd = ActionExecutor.toCommand(ReconScan(
              target: '10.0.0.5',
              profile: ReconProfile.quick,
              ports: [443, 22, 80]))!
          .command;
      expect(cmd, 'nmap -Pn -T4 -p 22,80,443 10.0.0.5');
    });

    test('service probes map to fixed templates', () {
      expect(
          ActionExecutor.toCommand(ServiceProbe(
                  target: 'h.example', port: 8080, probe: ProbeKind.http))!
              .command,
          'curl -sS -m 15 -i http://h.example:8080/');
      expect(
          ActionExecutor.toCommand(ServiceProbe(
                  target: 'h.example', port: 22, probe: ProbeKind.ssh))!
              .tool,
          'nmap');
    });

    test('conclude yields no command', () {
      expect(
          ActionExecutor.toCommand(
              ConcludeAction(reason: 'done', hostUseful: true)),
          isNull);
    });

    test('unsafe target yields no command (falls back)', () {
      expect(
          ActionExecutor.toCommand(ReconScan(
              target: '10.0.0.1; rm -rf /', profile: ReconProfile.quick)),
          isNull);
    });
  });

  group('ActionExecutor.observe', () {
    test('parses open ports from nmap output', () {
      final obs = ActionExecutor.observe(
        ReconScan(target: '10.0.0.5', profile: ReconProfile.quick),
        {
          'exitCode': 0,
          'output': '22/tcp   open  ssh\n80/tcp   open  http\n'
              '443/tcp  closed https\n',
        },
      );
      expect(obs.success, true);
      expect(obs.data['open_ports'], [22, 80]);
      expect(obs.summary, contains('22, 80'));
    });

    test('no open ports => unsuccessful observation', () {
      final obs = ActionExecutor.observe(
        ReconScan(target: '10.0.0.5', profile: ReconProfile.quick),
        {'exitCode': 0, 'output': 'Host seems down'},
      );
      expect(obs.success, false);
    });
  });

  group('SessionState', () {
    test('signature is stable and order-independent for ports', () {
      final a = ReconScan(
          target: 't', profile: ReconProfile.quick, ports: [80, 22]);
      final b = ReconScan(
          target: 't', profile: ReconProfile.quick, ports: [22, 80]);
      expect(SessionState.signatureOf(a), SessionState.signatureOf(b));
    });

    test('dedup via markTried/alreadyTried', () {
      final s = SessionState(target: 't', goal: 'g');
      final a = ServiceProbe(target: 't', port: 80, probe: ProbeKind.http);
      expect(s.alreadyTried(a), false);
      s.markTried(a);
      expect(s.alreadyTried(a), true);
    });

    test('digest is bounded to the most recent observations', () {
      final s = SessionState(target: 't', goal: 'g');
      for (var i = 0; i < 30; i++) {
        s.record(Observation(
            actionKind: ActionKind.serviceProbe,
            target: 't',
            success: true,
            summary: 'obs$i'));
      }
      final d = s.digest(maxObservations: 5);
      expect(d, contains('obs29'));
      expect(d, isNot(contains('obs20')));
    });
  });

  group('ActionSchemas', () {
    test('planner schema enum reflects ActionKind wire values', () {
      final schema = ActionSchemas.plannerAction;
      final actionEnum = ((schema['properties']
          as Map)['action'] as Map)['enum'] as List;
      expect(actionEnum, containsAll(['recon_scan', 'service_probe', 'conclude']));
      expect((schema['required'] as List), contains('action'));
    });
  });
}
