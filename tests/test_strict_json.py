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


def test_core_parser_is_used_when_exposed(monkeypatch):
    def strict_loads(text):
        return {"via": "core", "text": text}

    monkeypatch.setattr(tempus_ddb, "strict_loads", strict_loads, raising=False)
    assert loads('{"a": 1}') == {"via": "core", "text": '{"a": 1}'}


def test_verified_authorization_object_is_reused():
    verified = {"expires_at": 10, "authorization_id": "a", "agent_id": "b"}
    assert authorization_from_verified(verified) is verified
    assert authorization_from_verified(json.dumps(verified)) == verified
