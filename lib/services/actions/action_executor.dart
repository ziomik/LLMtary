import '../command_executor.dart';
import 'pentest_action.dart';
import 'session_state.dart';

/// A deterministic command derived from a typed action, ready for the existing
/// execution path (`CommandExecutor.executeCommand`).
class PlannedCommand {
  /// The concrete shell command.
  final String command;

  /// Primary tool name (for the recon loop's availability check), e.g. `nmap`.
  final String tool;

  /// Human-readable purpose, shown in progress/logs.
  final String purpose;

  const PlannedCommand(
      {required this.command, required this.tool, required this.purpose});
}

/// Maps typed actions → deterministic commands, and execution results →
/// typed observations (part 4 executor).
///
/// The whole point of this layer is that the model never writes a shell line.
/// A [PentestAction] is built only from validated primitives: the target is
/// regex-validated and rejected if it contains any shell metacharacter; ports
/// are integers; profile/probe are enums. The command template is fixed in
/// CODE per (kind, profile/probe). Therefore a derived command cannot carry an
/// injected payload. [CommandExecutor]'s own Tier-2 validation still runs as a
/// backstop downstream.
class ActionExecutor {
  ActionExecutor._();

  /// Conservative host matcher: IPv4, bracketed/plain IPv6 hextets, or a DNS
  /// hostname. Deliberately excludes spaces and every shell metacharacter.
  static final RegExp _targetPattern = RegExp(
    r'^(?:'
    r'\d{1,3}(?:\.\d{1,3}){3}' // IPv4
    r'|\[?[0-9A-Fa-f:]+\]?' // IPv6 (optionally bracketed)
    r'|[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}\.)*[A-Za-z0-9][A-Za-z0-9\-]{0,62}' // hostname
    r')$',
  );

  /// Any character that could break out of a single argument. If a target
  /// contains one, we refuse to build a command (→ caller falls back).
  static final RegExp _shellMeta = RegExp(r'''[\s;&|`$><(){}\[\]'"\\!*?~#]''');

  /// Validate a target string for safe interpolation into a command template.
  /// Returns the target unchanged if safe, otherwise `null`.
  static String? sanitizeTarget(String target) {
    final t = target.trim();
    if (t.isEmpty || t.length > 253) return null;
    if (_shellMeta.hasMatch(t)) return null;
    // IPv6 may legitimately contain ':' which _shellMeta does not reject.
    if (!_targetPattern.hasMatch(t)) return null;
    return t;
  }

  /// Derive the concrete command for an action.
  ///
  /// Returns `null` when the action cannot/should not be turned into a command
  /// (e.g. [ConcludeAction], or an unsafe/unknown target) so the caller can
  /// fall back to the free-text path with no regression.
  static PlannedCommand? toCommand(PentestAction action) {
    switch (action) {
      case ReconScan(:final target, :final profile, :final ports):
        final t = sanitizeTarget(target);
        if (t == null) return null;
        return _reconCommand(t, profile, ports);
      case ServiceProbe(:final target, :final port, :final probe):
        final t = sanitizeTarget(target);
        if (t == null) return null;
        return _probeCommand(t, port, probe);
      case ConcludeAction():
        return null;
    }
  }

  static PlannedCommand _reconCommand(
      String target, ReconProfile profile, List<int>? ports) {
    // Explicit port set overrides the profile's port selection.
    final portArg = (ports != null && ports.isNotEmpty)
        ? '-p ${(List<int>.from(ports)..sort()).join(',')} '
        : '';
    switch (profile) {
      case ReconProfile.quick:
        final sel = portArg.isNotEmpty ? portArg : '--top-ports 1000 ';
        return PlannedCommand(
          command: 'nmap -Pn -T4 $sel$target',
          tool: 'nmap',
          purpose: 'Quick TCP port scan of $target',
        );
      case ReconProfile.full:
        final sel = portArg.isNotEmpty ? portArg : '-p- ';
        return PlannedCommand(
          command: 'nmap -Pn -T4 $sel$target',
          tool: 'nmap',
          purpose: 'Full TCP port scan of $target',
        );
      case ReconProfile.udp:
        final sel = portArg.isNotEmpty ? portArg : '--top-ports 100 ';
        return PlannedCommand(
          command: 'nmap -Pn -sU -T4 $sel$target',
          tool: 'nmap',
          purpose: 'UDP port scan of $target',
        );
      case ReconProfile.script:
        final sel = portArg.isNotEmpty ? portArg : '--top-ports 1000 ';
        return PlannedCommand(
          command: 'nmap -Pn -sV -sC -T4 $sel$target',
          tool: 'nmap',
          purpose: 'Service/version + default-script scan of $target',
        );
    }
  }

  static PlannedCommand _probeCommand(String target, int port, ProbeKind probe) {
    switch (probe) {
      case ProbeKind.http:
        return PlannedCommand(
          command: 'curl -sS -m 15 -i http://$target:$port/',
          tool: 'curl',
          purpose: 'HTTP probe of $target:$port',
        );
      case ProbeKind.tls:
        return PlannedCommand(
          command:
              'nmap -Pn -p $port --script ssl-enum-ciphers,ssl-cert $target',
          tool: 'nmap',
          purpose: 'TLS/cipher probe of $target:$port',
        );
      case ProbeKind.smb:
        return PlannedCommand(
          command:
              'nmap -Pn -p $port --script smb-os-discovery,smb-protocols $target',
          tool: 'nmap',
          purpose: 'SMB probe of $target:$port',
        );
      case ProbeKind.dns:
        return PlannedCommand(
          command: 'nmap -Pn -p $port --script dns-nsid $target',
          tool: 'nmap',
          purpose: 'DNS probe of $target:$port',
        );
      case ProbeKind.ssh:
        return PlannedCommand(
          command:
              'nmap -Pn -p $port --script ssh2-enum-algos,ssh-hostkey $target',
          tool: 'nmap',
          purpose: 'SSH probe of $target:$port',
        );
      case ProbeKind.generic:
        return PlannedCommand(
          command: 'nmap -Pn -sV -p $port $target',
          tool: 'nmap',
          purpose: 'Service/version probe of $target:$port',
        );
    }
  }

  /// Build a typed [Observation] from an execution result map
  /// (`{output, exitCode}` as returned by [CommandExecutor.executeCommand]).
  ///
  /// Parsing is deliberately light in v1 — a success flag + one-line summary +
  /// (for recon) the set of open ports detected from nmap output. Richer typed
  /// parsing per action kind is a follow-up.
  static Observation observe(
      PentestAction action, Map<String, dynamic> execResult) {
    final output = (execResult['output'] as String? ?? '').trim();
    final exitCode = execResult['exitCode'] is int
        ? execResult['exitCode'] as int
        : int.tryParse('${execResult['exitCode']}') ?? -1;
    final timedOut = output.contains('Command timed out');
    final success = exitCode == 0 && !timedOut && output.isNotEmpty;

    switch (action) {
      case ReconScan(:final target, :final profile):
        final openPorts = _parseOpenPorts(output);
        return Observation(
          actionKind: action.kind,
          target: target,
          success: success && openPorts.isNotEmpty,
          summary: openPorts.isNotEmpty
              ? '${profile.wire} scan → open ports: ${openPorts.join(', ')}'
              : '${profile.wire} scan → no open ports found'
                  '${timedOut ? ' (timed out)' : ''}',
          data: openPorts.isEmpty ? null : {'open_ports': openPorts},
        );
      case ServiceProbe(:final target, :final port, :final probe):
        return Observation(
          actionKind: action.kind,
          target: target,
          port: port,
          success: success,
          summary: '${probe.wire} probe of $target:$port → '
              '${timedOut ? 'timed out' : success ? 'response received' : 'no useful response (exit $exitCode)'}',
        );
      case ConcludeAction(:final reason, :final hostUseful):
        return Observation(
          actionKind: action.kind,
          target: '',
          success: true,
          summary: 'concluded: $reason (useful=$hostUseful)',
        );
    }
  }

  /// Extract open TCP/UDP port numbers from nmap-style output lines such as
  /// `22/tcp   open  ssh`.
  static List<int> _parseOpenPorts(String output) {
    final ports = <int>[];
    final re = RegExp(r'^(\d{1,5})/(?:tcp|udp)\s+open', multiLine: true);
    for (final m in re.allMatches(output)) {
      final p = int.tryParse(m.group(1)!);
      if (p != null && p >= 1 && p <= 65535 && !ports.contains(p)) {
        ports.add(p);
      }
    }
    return ports;
  }
}
