"""vaultgates.init_rc: the Android init tokenizer (init/tokenizer.cpp)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from vaultgates.init_rc import display, init_lines  # noqa: E402


def lines(text):
    return [(number, args) for number, args, _raw in init_lines(text)]


class TokenizerTest(unittest.TestCase):
    def test_backslash_newline_continues_the_line(self):
        text = "on boot\n    start \\\n        adbd\nservice x /bin/x\n"
        self.assertEqual(lines(text), [(1, ["on", "boot"]), (2, ["start", "adbd"]),
                                       (4, ["service", "x", "/bin/x"])])

    def test_crlf_continuation(self):
        self.assertEqual(lines("start \\\r\n  adbd\r\n"), [(1, ["start", "adbd"])])

    def test_display_joins_continuations_with_one_space(self):
        (_number, _args, raw), = init_lines("    start \\\n        adbd\n")
        self.assertEqual(display(raw), "    start  adbd")

    def test_section_keywords_at_any_indentation(self):
        text = "service vaultd /system/bin/true\n    oneshot\n  on boot\n    start adbd\n"
        self.assertEqual([args[0] for _n, args in lines(text)], ["service", "oneshot", "on", "start"])

    def test_quotes_group_and_join(self):
        self.assertEqual(lines('"start" ad bd\n'), [(1, ["start", "ad", "bd"])])
        self.assertEqual(lines('setprop a "b c"\n'), [(1, ["setprop", "a", "b c"])])
        self.assertEqual(lines('st"ar"t adbd\n'), [(1, ["start", "adbd"])])

    def test_quoted_newline_counts_lines(self):
        self.assertEqual(lines('write /x "a\nb"\nstart adbd\n'),
                         [(1, ["write", "/x", "a\nb"]), (3, ["start", "adbd"])])

    def test_comments_only_at_token_start(self):
        self.assertEqual(lines("# start adbd\nstart adbd # trailing\nwrite a#b c\n"),
                         [(2, ["start", "adbd"]), (3, ["write", "a#b", "c"])])

    def test_escapes(self):
        self.assertEqual(lines(r"write /x a\tb\\c\q" + "\n"), [(1, ["write", "/x", "a\tb\\cq"])])

    def test_unterminated_quote_ends_the_file(self):
        self.assertEqual(lines('on boot\nstart "adbd\nstart adbd\n'), [(1, ["on", "boot"])])

    def test_blank_and_whitespace_lines_yield_nothing(self):
        self.assertEqual(lines("\n  \t\n\r\n"), [])


if __name__ == "__main__":
    unittest.main()
