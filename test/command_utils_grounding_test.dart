import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/utils/command_utils.dart';

void main() {
  group('CommandUtils.quoteGroundedIn (evidence_quote grounding)', () {
    test('exact substring is grounded', () {
      expect(
        CommandUtils.quoteGroundedIn('Elasticsearch 7.10.2', 'service: Elasticsearch 7.10.2 open'),
        isTrue,
      );
    });

    test('whitespace reflow is tolerated (the 54-findings bug)', () {
      // The model copied the quote with collapsed/extra whitespace and a newline
      // where the source had a single space: a raw .contains() returned false and
      // sent the finding to LOW. quoteGroundedIn must still ground it.
      const haystack = 'ssh-2.0-openssh_8.2p1  ubuntu-4ubuntu0.5\nport 22 open';
      expect(CommandUtils.quoteGroundedIn('OpenSSH_8.2p1 Ubuntu-4ubuntu0.5', haystack), isTrue);
      expect(CommandUtils.quoteGroundedIn('ssh-2.0-openssh_8.2p1\nUbuntu-4ubuntu0.5', haystack),
          isTrue);
    });

    test('case-insensitive by default (recon grounding)', () {
      expect(CommandUtils.quoteGroundedIn('elasticsearch', 'Open: Elasticsearch cluster'), isTrue);
    });

    test('case-sensitive mode preserves literal proof (exploit path)', () {
      expect(
        CommandUtils.quoteGroundedIn('uid=0(root)', 'result: uid=0(root)  groups=0(root)',
            caseSensitive: true),
        isTrue,
      );
      // A different case is NOT accepted as exploit proof.
      expect(
        CommandUtils.quoteGroundedIn('UID=0(ROOT)', 'result: uid=0(root)', caseSensitive: true),
        isFalse,
      );
    });

    test('genuinely absent content is not grounded (no false grounding)', () {
      expect(
        CommandUtils.quoteGroundedIn('CVE-2021-44228 log4j', 'only an nginx banner here'),
        isFalse,
      );
    });

    test('empty quote is never grounded', () {
      expect(CommandUtils.quoteGroundedIn('', 'anything'), isFalse);
      expect(CommandUtils.quoteGroundedIn('   \n ', 'anything'), isFalse);
    });
  });
}
