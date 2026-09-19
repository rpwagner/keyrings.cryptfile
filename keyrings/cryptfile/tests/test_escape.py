import pytest

from keyrings.cryptfile.escape import escape, unescape


@pytest.mark.parametrize(
    'value',
    [
        'ascii_letters_name',
        'service name/with punctuation',
        'Unicode ☃ café',
    ],
)
def test_escape_round_trip(value):
    assert unescape(escape(value)) == value
