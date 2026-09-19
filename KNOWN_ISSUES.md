# Known issues

## Ambiguous underscore escapes

Upstream pull request 33 made underscores legal unescaped characters. The
existing `unescape()` function still interprets an underscore followed by two
hexadecimal digits as an encoded byte. Consequently, values such as
`ascii_letters_123` do not round-trip through `unescape(escape(value))`.

This currently affects the `cryptfile-convert` command, which unescapes service
and username values. Reverting underscore handling directly could make entries
written after upstream pull request 33 unreachable because escaping contributes
to both INI identifiers and authenticated associated data.

A correction needs a separately reviewed compatibility design covering vaults
written before and after that change, literal underscore-plus-hex identifiers,
service and username lookup, authenticated associated data, and conversion
across all supported AES modes. The Python 3.13/3.14 modernization deliberately
does not change this on-disk behavior.

## Password validation in optimized mode

The existing encrypted backends use `assert` statements for parts of master
password and decrypted-data validation. Python removes assertions when it runs
with optimization enabled (for example, `python -O`), so these checks should be
replaced by explicit validation in a focused security change.

That correction needs review of exception behavior and compatibility with
existing callers and vault files. The Python 3.13/3.14 modernization documents
the issue but deliberately leaves the cryptographic implementation unchanged.
