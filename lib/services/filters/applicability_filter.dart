import 'stack_profile.dart';

/// Whether a finding is applicable to the detected stack.
enum Applicability {
  /// The finding's platform is present (or no foreign-platform signature matched).
  applicable,

  /// A foreign-platform signature matched but the stack signal is too thin to
  /// be sure the platform is truly absent — stay permissive.
  uncertain,

  /// A foreign-platform signature matched, the required platform is absent, and
  /// the stack signal is solid → the finding cannot be true on this target.
  inapplicableCategorical,
}

/// What to do with a finding before active validation.
enum FilterDecision { keep, deprioritize, drop }

class ApplicabilityResult {
  final Applicability verdict;
  final StackAxis? requiredAxis;
  final String reason;
  const ApplicabilityResult(this.verdict, this.requiredAxis, this.reason);
}

class FilterOutcome {
  final FilterDecision decision;
  final Applicability applicability;
  final StackAxis? requiredAxis;

  /// True when a HIGH-confidence finding is categorically foreign — a
  /// contradiction worth logging (recon under-detected, or analyzer
  /// over-confident). Never dropped; surfaced instead.
  final bool contradiction;
  final String reason;

  const FilterOutcome({
    required this.decision,
    required this.applicability,
    required this.requiredAxis,
    required this.contradiction,
    required this.reason,
  });
}

/// One foreign-platform signature: finding-text [keywords] ⇒ [axis] required.
class _Signature {
  final List<String> keywords;
  final StackAxis axis;
  const _Signature(this.keywords, this.axis);
}

/// Contextual applicability classifier (part 4, Level A/B).
///
/// Deterministic. Matches explicit PLATFORM qualifiers in the finding text
/// against the detected [StackProfile] and decides whether a finding is worth
/// (actively) validating. The default is ALWAYS [Applicability.applicable]:
/// a finding is only ever flagged foreign when it carries an explicit
/// platform keyword whose axis is categorically absent. Never-listed vuln
/// classes (WordPress, TLS, headers, SSRF, IDOR, mail/SSH services, ...) fall
/// through to applicable and are never dropped.
///
/// Calibrated on the real southfront.press finding set (WordPress + nginx +
/// PHP + mailcow): the foreign templates (Kerberos/AD, Docker/K8s,
/// Elasticsearch, AWS/cloud, Modbus/ICS, SMB) carry explicit platform tokens.
class ApplicabilityFilter {
  ApplicabilityFilter._();

  /// Order matters: first match wins. Most-specific (AD/Kerberos) first.
  static const List<_Signature> _signatures = [
    _Signature([
      'kerberos', 'active directory', 'internet-facing dc', ' on dc',
      'dcsync', 'kerberoast', 'as-rep', 'pass-the-hash', 'winrm', ' wmi ',
      'netlogon', 'rbcd', 'unconstrained delegation', 'constrained delegation',
      'laps credential', 'shadow credential', 'smb relay', 'print spooler',
      'ldap null bind', 'dacl', 'adcs', 'ad cs', 'adc certificate',
      'certificate services', 'ntlm relay', 'golden ticket', 'silver ticket',
    ], StackAxis.windowsAd),
    _Signature([
      'docker api', 'docker', 'kubernetes', 'k8s', 'kubelet', 'etcd',
      'privileged pod', 'privileged container',
    ], StackAxis.orchestration),
    _Signature([
      'imds', 'iam role', 'execution role', 'function url', 'lambda',
      ' ec2', ' aws', 'gcp ', 'azure', 'publicly accessible storage',
      'storage bucket', 's3 bucket', 'blob storage', 'instance metadata',
    ], StackAxis.cloud),
    _Signature(['elasticsearch', 'kibana'], StackAxis.elasticsearch),
    _Signature([
      'modbus', 'industrial control', 'scada', 'port 502', ' plc ', ' ics ',
    ], StackAxis.icsModbus),
    _Signature([
      'port 445', 'smb service', 'externally exposed smb', 'microsoft-ds',
      'netbios',
    ], StackAxis.smb),
    _Signature([
      ' rmi', 'iiop', 'jndi', 'jboss', 'weblogic', 'websphere', 'coldfusion',
      'java deserialization', 'java serialization', 'action message format', ' amf ',
    ], StackAxis.javaMiddleware),
    _Signature([
      'activemq', 'rabbitmq', 'kafka', 'amqp', 'message broker', ' jms ', 'stomp',
    ], StackAxis.messageBroker),
  ];

  /// Classify a finding's text against the stack.
  static ApplicabilityResult classify(String findingText, StackProfile stack) {
    final text = ' ${findingText.toLowerCase()} ';
    for (final sig in _signatures) {
      if (sig.keywords.any(text.contains)) {
        if (stack.has(sig.axis)) {
          return ApplicabilityResult(Applicability.applicable, sig.axis,
              'platform ${sig.axis.name} present');
        }
        if (stack.solid) {
          return ApplicabilityResult(Applicability.inapplicableCategorical,
              sig.axis, 'platform ${sig.axis.name} absent on a solidly-detected stack');
        }
        return ApplicabilityResult(Applicability.uncertain, sig.axis,
            'platform ${sig.axis.name} not detected but stack signal is thin');
      }
    }
    return const ApplicabilityResult(
        Applicability.applicable, null, 'no foreign-platform signature');
  }

  /// Decide keep/deprioritize/drop combining applicability with confidence.
  ///
  /// Policy (conservative): HARD DROP only a LOW-confidence, categorically
  /// inapplicable finding. HIGH is never dropped (contradiction logged).
  /// MEDIUM categorical and LOW uncertain are deprioritized. Everything else
  /// is kept.
  static FilterOutcome decide({
    required String text,
    required String confidence,
    required StackProfile stack,
    bool dropHighCategorical = false,
  }) {
    final c = classify(text, stack);
    final conf = confidence.toUpperCase();

    switch (c.verdict) {
      case Applicability.inapplicableCategorical:
        // Field evidence (southfront): the model assigns HIGH/CRITICAL confidence to
        // categorically-impossible findings (K8s/RMI/IAM on a WordPress+PHP+mail host).
        // On a SOLID stack that model confidence is itself a hallucination signal, so
        // when dropHighCategorical is on we drop regardless of confidence — but we flag
        // a high-confidence drop as a contradiction and log it, so nothing is lost silently.
        final isHigh = conf == 'HIGH';
        if (dropHighCategorical) {
          return FilterOutcome(
            decision: FilterDecision.drop,
            applicability: c.verdict,
            requiredAxis: c.requiredAxis,
            contradiction: isHigh,
            reason: '${isHigh ? 'HIGH-confidence but ' : '$conf-confidence and '}'
                '${c.reason} — dropped (dropHighCategorical)',
          );
        }
        if (isHigh) {
          return FilterOutcome(
            decision: FilterDecision.keep,
            applicability: c.verdict,
            requiredAxis: c.requiredAxis,
            contradiction: true,
            reason: 'HIGH-confidence but ${c.reason} — kept, contradiction logged',
          );
        }
        if (conf == 'LOW') {
          return FilterOutcome(
            decision: FilterDecision.drop,
            applicability: c.verdict,
            requiredAxis: c.requiredAxis,
            contradiction: false,
            reason: 'LOW-confidence and ${c.reason}',
          );
        }
        return FilterOutcome(
          decision: FilterDecision.deprioritize,
          applicability: c.verdict,
          requiredAxis: c.requiredAxis,
          contradiction: false,
          reason: '$conf-confidence and ${c.reason}',
        );
      case Applicability.uncertain:
        return FilterOutcome(
          decision: conf == 'LOW' ? FilterDecision.deprioritize : FilterDecision.keep,
          applicability: c.verdict,
          requiredAxis: c.requiredAxis,
          contradiction: false,
          reason: c.reason,
        );
      case Applicability.applicable:
        return FilterOutcome(
          decision: FilterDecision.keep,
          applicability: c.verdict,
          requiredAxis: c.requiredAxis,
          contradiction: false,
          reason: c.reason,
        );
    }
  }
}
