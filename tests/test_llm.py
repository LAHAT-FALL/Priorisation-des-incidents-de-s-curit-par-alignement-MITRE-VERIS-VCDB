from modules.llm import build_prompt


def test_prompt_build() -> None:
    p = build_prompt("inc1", ["T1190"], ["T1190"], ["action_x"], "note")
    assert "Incident: inc1" in p and "note" in p
