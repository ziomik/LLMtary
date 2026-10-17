import 'dart:async';

import '../../models/llm_settings.dart';
import '../../utils/json_parser.dart';
import '../llm_service.dart';
import 'action_executor.dart';
import 'action_schema.dart';
import 'pentest_action.dart';
import 'session_state.dart';

/// Result of one planner step: a loop-compatible decision map plus the typed
/// action that produced it (so the caller can record a typed observation).
class PlannerDecision {
  /// Shaped like the free-text loop's decision map so the recon loop can
  /// consume it unchanged: `{'action': 'COMMAND', 'command', 'tool',
  /// 'purpose'}` or `{'action': 'CONCLUDE', 'host_useful', 'conclude_reason'}`.
  final Map<String, dynamic> decision;

  /// The typed action chosen (for observation recording / dedup).
  final PentestAction action;

  const PlannerDecision(this.decision, this.action);
}

/// Part 4 planner: asks the model for a TYPED recon action (schema-constrained)
/// and turns it into a deterministic command via [ActionExecutor].
///
/// Returns `null` on any failure (LLM/timeout/parse error, unknown action kind,
/// or an action that cannot be safely turned into a command) so the recon loop
/// falls back to its existing free-text path with no regression.
class ReconPlanner {
  ReconPlanner._();

  /// Pick the next recon action given the current [state].
  static Future<PlannerDecision?> decide({
    required LLMService llmService,
    required LLMSettings settings,
    required SessionState state,
    required Duration timeout,
  }) async {
    final prompt = '''
You are selecting the NEXT reconnaissance action for a penetration test.

${state.digest()}

${ActionSchemas.actionMenu}

Return ONLY the JSON object for your chosen action.''';

    String raw;
    try {
      raw = await llmService
          .sendMessage(settings, prompt,
              responseSchema: ActionSchemas.plannerAction,
              onTokensUsed: null)
          .timeout(timeout);
    } catch (_) {
      return null; // timeout / provider error → fall back
    }

    final parsed = JsonParser.tryParseJson(raw);
    if (parsed == null) return null;

    final action = PentestAction.fromJson(parsed);
    if (action == null) return null;

    switch (action) {
      case ConcludeAction(:final reason, :final hostUseful):
        state.markTried(action);
        return PlannerDecision({
          'action': 'CONCLUDE',
          'host_useful': hostUseful,
          'conclude_reason': reason,
        }, action);
      case ReconScan():
      case ServiceProbe():
        final planned = ActionExecutor.toCommand(action);
        if (planned == null) return null; // unsafe/unknown target → fall back
        state.markTried(action);
        return PlannerDecision({
          'action': 'COMMAND',
          'command': planned.command,
          'tool': planned.tool,
          'purpose': planned.purpose,
        }, action);
    }
  }
}
