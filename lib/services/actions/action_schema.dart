import 'pentest_action.dart';

/// JSON schema for the planner's typed-action output (part 4).
///
/// Reuses the exact-schema mechanism from part 1 ([LlmSchemas] +
/// `LLMService.sendMessage(responseSchema: ...)`): instead of asking the model
/// for a free-text command we hand it this schema, which pins `action` to the
/// closed [ActionKind] enum and types every param. A 14B local model can then
/// only SELECT an action and fill typed fields — it cannot emit an arbitrary
/// shell line.
///
/// The schema is intentionally FLAT (one object, all params optional except
/// `action`) rather than a nested `oneOf` per variant: small models handle a
/// flat object far more reliably, and [PentestAction.fromJson] already reads
/// only the fields relevant to the chosen kind.
class ActionSchemas {
  ActionSchemas._();

  /// Enum of action wire-values, derived from [ActionKind] so the schema and
  /// the parser can never drift apart.
  static List<String> get _actionEnum =>
      ActionKind.values.map((k) => k.wire).toList();

  static List<String> get _profileEnum =>
      ReconProfile.values.map((p) => p.wire).toList();

  static List<String> get _probeEnum =>
      ProbeKind.values.map((p) => p.wire).toList();

  /// The planner response schema.
  static Map<String, dynamic> get plannerAction => {
        'type': 'object',
        'properties': {
          'thought': {'type': 'string'},
          'action': {'type': 'string', 'enum': _actionEnum},
          // recon_scan / service_probe
          'target': {'type': 'string'},
          // recon_scan
          'profile': {'type': 'string', 'enum': _profileEnum},
          'ports': {
            'type': 'array',
            'items': {'type': 'integer'},
          },
          // service_probe
          'port': {'type': 'integer'},
          'probe': {'type': 'string', 'enum': _probeEnum},
          // conclude
          'reason': {'type': 'string'},
          'host_useful': {'type': 'boolean'},
        },
        'required': ['action'],
        'additionalProperties': true,
      };

  /// Human-readable description of the action menu, injected into the planner
  /// prompt so the model knows what each action does and which params it takes.
  static String get actionMenu => '''
Choose ONE action and return it as JSON matching the schema. Do NOT write raw shell commands — pick an action kind and fill its typed fields:

- "recon_scan": discover ports/services. Fields: target (required), profile (one of: quick, full, udp, script), ports (optional integer list to scan only those ports).
- "service_probe": probe ONE known-open port. Fields: target (required), port (required integer), probe (one of: http, tls, smb, dns, ssh, generic).
- "conclude": stop recon. Fields: reason (string), host_useful (boolean — true if the host has a useful attack surface).

Pick "conclude" with host_useful=false when the target is unreachable or has no useful surface.''';
}
