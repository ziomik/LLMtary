import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/command_executor.dart';

void main() {
  group('CommandExecutor.killCategory (per-tool kill-rate stats for auto-tuning)', () {
    test('idle-timeout reason maps to idle', () {
      expect(
        CommandExecutor.killCategory('idle-timeout: no output for 150s (likely network-hung)'),
        'idle',
      );
    });

    test('repetitive-output reason maps to repetitive', () {
      expect(
        CommandExecutor.killCategory('Repetitive output detected (50+ identical lines)'),
        'repetitive',
      );
    });

    test('output-cap reason maps to output-cap', () {
      expect(CommandExecutor.killCategory('Output exceeded 512KB limit'), 'output-cap');
    });

    test('anything else maps to other', () {
      expect(CommandExecutor.killCategory('some unexpected reason'), 'other');
    });
  });
}
