import json

import pytest
import tempus_ddb

from tempus_github_app.permit_context import authorization_from_verified
from tempus_github_app.strict_json import loads


def test_unique_keys_match_the_stdlib():
    raw = '{"a":[1,{"b":true}],"c":null}'
    assert loads(raw) == json.loads(raw)
    assert loads(raw.encode()) == json.loads(raw)


def test_repeated_keys_are_rejected_at_any_depth():
    samples = [
        '{"amount":"9999.00","amount":"25.00"}',
        '{"a":{"b":1,"b":2}}',
        '{"a":[{"k":1,"k":1}]}',
        '{"a":1,"\\u0061":2}',
    ]
    for raw in samples:
        with pytest.raises(json.JSONDecodeError, match="DUPLICATE_JSON_KEY"):
            loads(raw)


def test_same_key_in_sibling_objects_is_accepted():
    assert loads('[{"k":1},{"k":2}]') == [{"k": 1}, {"k": 2}]


# Same documents as tempus-ddb src/strict_json.rs on desarrollo:
# parses_like_serde_json_when_keys_are_unique, rejects_repeated_keys_at_any_depth,
# and same_key_in_sibling_objects_is_fine_and_trailing_data_is_rejected.
# serde_json keeps the last duplicate; the strict parser fails closed with
# DUPLICATE_JSON_KEY and does not return that collapsed value.
_CORE_UNIQUE = '{"a":[1,-2,3.5,"x",null,true],"b":{"c":{}}}'
_CORE_DUPLICATES = (
    ('{"amount":"9999.00","amount":"25.00"}', {"amount": "25.00"}),
    ('{"a":{"b":1,"b":2}}', {"a": {"b": 2}}),
    ('{"a":[{"k":1,"k":1}]}', {"a": [{"k": 1}]}),
    ('{"a":1,"\\u0061":2}', {"a": 2}),
)


def test_parity_with_core_accepts_unique_keys():
    assert loads(_CORE_UNIQUE) == json.loads(_CORE_UNIQUE)


@pytest.mark.parametrize(("raw", "last_key_wins"), _CORE_DUPLICATES)
def test_parity_with_core_rejects_duplicate_keys_fail_closed(raw, last_key_wins):
    assert json.loads(raw) == last_key_wins
    with pytest.raises(json.JSONDecodeError, match="DUPLICATE_JSON_KEY") as caught:
        loads(raw)
    assert caught.value.msg.startswith("DUPLICATE_JSON_KEY")
    assert "appears more than once" in caught.value.msg


def test_parity_with_core_siblings_ok_trailing_data_is_not_a_duplicate_key():
    assert loads('[{"k":1},{"k":2}]') == [{"k": 1}, {"k": 2}]
    with pytest.raises(json.JSONDecodeError) as trailing:
        loads('{"k":1} {"k":2}')
    assert "DUPLICATE_JSON_KEY" not in str(trailing.value)
    with pytest.raises(json.JSONDecodeError) as incomplete:
        loads("{")
    assert "DUPLICATE_JSON_KEY" not in str(incomplete.value)


def test_core_parser_is_used_when_exposed(monkeypatch):
    def strict_loads(text):
        return {"via": "core", "text": text}

    monkeypatch.setattr(tempus_ddb, "strict_loads", strict_loads, raising=False)
    assert loads('{"a": 1}') == {"via": "core", "text": '{"a": 1}'}


def test_verified_authorization_object_is_reused():
    verified = {"expires_at": 10, "authorization_id": "a", "agent_id": "b"}
    assert authorization_from_verified(verified) is verified
    assert authorization_from_verified(json.dumps(verified)) == verified
