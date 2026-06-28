from backend.core.ai_reviewer import _critical_path_complete


def test_critical_path_requires_value_destination_and_binding():
    packet = {"evidence": {"unguarded": ["swap"]}}
    assert not _critical_path_complete(
        {
            "value_moves": "USDC",
            "value_to": "recipient",
            "destination_control": "unknown",
            "attacker_control_binding": {"variable": "recipient"},
            "critical_path_complete": True,
        },
        packet,
    )
    assert _critical_path_complete(
        {
            "value_moves": "USDC",
            "value_to": "recipient",
            "destination_control": "attacker_controlled",
            "attacker_control_binding": {"variable": "recipient"},
            "critical_path_complete": True,
        },
        packet,
    )


def test_poc_plus_unauthorized_path_can_complete_critical_path():
    packet = {"evidence": {"poc_passed": True, "unguarded": ["withdraw"]}}
    assert _critical_path_complete({"critical_path_complete": True}, packet)
