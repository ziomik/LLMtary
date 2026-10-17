import 'pentest_action.dart';

/// A typed observation produced by executing one action (part 2b/4).
///
/// Instead of re-deriving "what did I already see" from a growing wall of
/// command output each iteration, the executor emits a structured observation
/// the planner can read compactly.
class Observation {
  final ActionKind actionKind;
  final String target;
  final int? port;
  final bool success;

  /// One-line human summary (shown to the planner).
  final String summary;

  /// Type-specific parsed data (e.g. open ports, detected service). Kept small.
  final Map<String, dynamic> data;

  final DateTime at;

  Observation({
    required this.actionKind,
    required this.target,
    this.port,
    required this.success,
    required this.summary,
    Map<String, dynamic>? data,
    DateTime? at,
  })  : data = data ?? const {},
        at = at ?? DateTime.now();

  Map<String, dynamic> toJson() => {
        'action': actionKind.wire,
        'target': target,
        if (port != null) 'port': port,
        'success': success,
        'summary': summary,
        if (data.isNotEmpty) 'data': data,
      };
}

/// In-memory typed state carried across planner iterations for a single
/// target (part 2b). v1 is intentionally in-memory only; persistence (to
/// resume a session) is a documented follow-up.
///
/// The planner receives [digest] (a compact, bounded text view) instead of the
/// raw output history, and the set of already-[triedSignatures] so it does not
/// re-propose an action it has already run.
class SessionState {
  final String target;
  final String goal;
  final List<Observation> observations = [];

  /// Signatures of actions already attempted, for dedup of effort.
  final Set<String> triedSignatures = {};

  SessionState({required this.target, required this.goal});

  /// Stable signature of an action for dedup. Deterministic: same action ⇒
  /// same signature.
  static String signatureOf(PentestAction action) {
    switch (action) {
      case ReconScan(:final target, :final profile, :final ports):
        final p = (ports == null || ports.isEmpty)
            ? ''
            : (List<int>.from(ports)..sort()).join(',');
        return 'recon_scan:$target:${profile.wire}:$p';
      case ServiceProbe(:final target, :final port, :final probe):
        return 'service_probe:$target:$port:${probe.wire}';
      case ConcludeAction():
        return 'conclude';
    }
  }

  /// Whether this exact action has already been attempted this session.
  bool alreadyTried(PentestAction action) =>
      triedSignatures.contains(signatureOf(action));

  /// Record that an action was chosen/attempted (before or without a result).
  void markTried(PentestAction action) {
    triedSignatures.add(signatureOf(action));
  }

  /// Record a typed observation from an executed action.
  void record(Observation obs) => observations.add(obs);

  /// Compact, bounded view of session state for the planner prompt. Only the
  /// most recent [maxObservations] observations are included so the prompt
  /// stays small regardless of session length.
  String digest({int maxObservations = 12}) {
    final b = StringBuffer();
    b.writeln('TARGET: $target');
    b.writeln('GOAL: $goal');
    if (observations.isEmpty) {
      b.writeln('OBSERVATIONS: none yet');
    } else {
      b.writeln('OBSERVATIONS (most recent last):');
      final start = observations.length > maxObservations
          ? observations.length - maxObservations
          : 0;
      for (var i = start; i < observations.length; i++) {
        final o = observations[i];
        final mark = o.success ? 'ok' : 'fail';
        b.writeln('- [$mark] ${o.summary}');
      }
    }
    if (triedSignatures.isNotEmpty) {
      b.writeln('ALREADY TRIED (do not repeat): ${triedSignatures.join('; ')}');
    }
    return b.toString().trimRight();
  }
}
