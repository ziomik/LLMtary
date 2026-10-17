import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/auto_tuner.dart';

List<Map<String, dynamic>> rows(String tool, int n, {String outcome = 'ok', int durationMs = 200000}) =>
    List.generate(n, (_) => {'tool': tool, 'outcome': outcome, 'durationMs': durationMs});

void main() {
  group('AutoTuner.tunedIdleTimeouts (gated per-tool auto-tuning)', () {
    test('a tool below minSamples is omitted (caller keeps its default)', () {
      final out = AutoTuner.tunedIdleTimeouts(rows('nmap', 5), minSamples: 20);
      expect(out.containsKey('nmap'), isFalse);
    });

    test('enough samples: tuned ~= ceil(p95s * 1.5), clamped', () {
      // 25 successful runs of 200s → p95 = 200000ms → 200*1.5 = 300s (within [90,600])
      final out = AutoTuner.tunedIdleTimeouts(rows('nmap', 25), minSamples: 20);
      expect(out['nmap'], 300);
    });

    test('clamped to max for very long tools', () {
      final out = AutoTuner.tunedIdleTimeouts(rows('slowtool', 25, durationMs: 100000000),
          minSamples: 20, maxSeconds: 600);
      expect(out['slowtool'], 600);
    });

    test('clamped to min for very fast tools', () {
      final out = AutoTuner.tunedIdleTimeouts(rows('fast', 25, durationMs: 1000),
          minSamples: 20, minSeconds: 90);
      expect(out['fast'], 90);
    });

    test('manual override wins regardless of sample count and is clamped', () {
      final out = AutoTuner.tunedIdleTimeouts(
        rows('nmap', 3),
        minSamples: 20,
        overrides: {'nmap': 420, 'huge': 99999},
      );
      expect(out['nmap'], 420); // emitted despite only 3 samples
      expect(out['huge'], 600); // clamped to max
    });

    test('a tool with samples but no successful runs is omitted', () {
      final out = AutoTuner.tunedIdleTimeouts(rows('failer', 25, outcome: 'error'), minSamples: 20);
      expect(out.containsKey('failer'), isFalse);
    });
  });
}
