import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Part 3: auto-tuning of per-tool thresholds from the collected metrics
/// (command_metrics.jsonl, written in part 2a).
///
/// Today the idle-output watchdog uses a single constant idle timeout (150s)
/// for every tool. Some tools are legitimately quiet much longer than others;
/// a fixed value either false-kills the slow ones or waits too long on the
/// fast ones. Once we have enough samples for a tool, we can pick a per-tool
/// idle timeout from its own observed behaviour.
///
/// Gating and safety (deliberately conservative):
/// - **Enough samples**: a tool is auto-tuned only once it has at least
///   [minSamples] records (default 20). Below that → the caller's default.
/// - **Clamped**: the tuned value is clamped to [[minSeconds], [maxSeconds]],
///   so a pathological distribution can never produce an absurd timeout.
/// - **Manual override wins**: an explicit per-tool override (operator set)
///   always takes precedence over both the tuned value and the default.
/// - **Pure core**: [tunedIdleTimeouts] is a pure function of the metric rows,
///   unit-tested; the stateful loader is a thin cache around it.
class AutoTuner {
  AutoTuner._();
  static final AutoTuner instance = AutoTuner._();

  static const int defaultMinSamples = 20;
  static const int defaultMinSeconds = 90;
  static const int defaultMaxSeconds = 600;

  /// Operator overrides (tool → idle timeout seconds). Set from settings; these
  /// win over everything. Empty by default.
  Map<String, int> overrides = <String, int>{};

  /// Cached tuned values (tool → idle timeout seconds), refreshed from the
  /// metrics log by [refresh]. Empty until the first successful refresh, so the
  /// watchdog keeps using its constant default until data accumulates.
  Map<String, int> _tuned = <String, int>{};

  bool _refreshing = false;
  DateTime _lastRefresh = DateTime.fromMillisecondsSinceEpoch(0);

  /// Synchronous lookup used on the command hot-path: override, else tuned,
  /// else the caller's [defaultSec]. Never does I/O.
  int idleTimeoutSecondsFor(String tool, {required int defaultSec}) {
    return overrides[tool] ?? _tuned[tool] ?? defaultSec;
  }

  /// Fire-and-forget, throttled reload of the tuned map from the metrics log.
  /// Safe to call opportunistically (e.g. before running a command); it never
  /// throws and skips if a refresh ran within [minInterval].
  Future<void> maybeRefresh({
    Duration minInterval = const Duration(minutes: 5),
    int minSamples = defaultMinSamples,
  }) async {
    if (_refreshing) return;
    if (DateTime.now().difference(_lastRefresh) < minInterval) return;
    _refreshing = true;
    try {
      final appDir = await getApplicationSupportDirectory();
      final file = File(p.join(appDir.path, 'command_metrics.jsonl'));
      if (!await file.exists()) return;
      final rows = <Map<String, dynamic>>[];
      for (final line in await file.readAsLines()) {
        if (line.trim().isEmpty) continue;
        try {
          final d = jsonDecode(line);
          if (d is Map<String, dynamic>) rows.add(d);
        } catch (_) {
          // skip malformed line
        }
      }
      _tuned = tunedIdleTimeouts(rows, minSamples: minSamples, overrides: overrides);
      _lastRefresh = DateTime.now();
    } catch (_) {
      // tuning is best-effort; never block or fail a command
    } finally {
      _refreshing = false;
    }
  }

  /// Pure: compute per-tool idle timeout (seconds) from metric rows.
  ///
  /// For each tool with >= [minSamples] rows, the tuned timeout is
  /// `clamp(ceil(p95(successful durationMs) / 1000 * 1.5), minSeconds, maxSeconds)`:
  /// a tool that legitimately runs up to ~p95 seconds (eventually producing
  /// output) should tolerate a comparable stretch of silence before being
  /// idle-killed. Tools without enough samples are omitted (caller keeps its
  /// default). A manual [overrides] entry is emitted as-is (clamped), regardless
  /// of sample count.
  static Map<String, int> tunedIdleTimeouts(
    List<Map<String, dynamic>> rows, {
    int minSamples = defaultMinSamples,
    int minSeconds = defaultMinSeconds,
    int maxSeconds = defaultMaxSeconds,
    Map<String, int> overrides = const <String, int>{},
  }) {
    final byTool = <String, List<int>>{}; // tool → successful durationsMs
    final counts = <String, int>{};
    for (final r in rows) {
      final tool = (r['tool'] as String?)?.trim();
      if (tool == null || tool.isEmpty) continue;
      counts[tool] = (counts[tool] ?? 0) + 1;
      if (r['outcome'] == 'ok') {
        final d = r['durationMs'];
        if (d is int && d >= 0) {
          byTool.putIfAbsent(tool, () => <int>[]).add(d);
        }
      }
    }

    int clamp(int v) => v < minSeconds ? minSeconds : (v > maxSeconds ? maxSeconds : v);

    final out = <String, int>{};
    // manual overrides first (win regardless of samples), clamped
    overrides.forEach((tool, sec) => out[tool] = clamp(sec));

    counts.forEach((tool, n) {
      if (out.containsKey(tool)) return; // override already decided
      if (n < minSamples) return; // not enough data → caller default
      final durs = byTool[tool] ?? const <int>[];
      if (durs.isEmpty) return; // no successful runs to learn from
      final p95ms = _percentile(durs, 0.95);
      final tunedSec = (p95ms / 1000 * 1.5).ceil();
      out[tool] = clamp(tunedSec);
    });
    return out;
  }

  /// Nearest-rank percentile (0..1) of a list of ints. Pure.
  static int _percentile(List<int> values, double q) {
    if (values.isEmpty) return 0;
    final sorted = [...values]..sort();
    final rank = (q * sorted.length).ceil().clamp(1, sorted.length);
    return sorted[rank - 1];
  }
}
