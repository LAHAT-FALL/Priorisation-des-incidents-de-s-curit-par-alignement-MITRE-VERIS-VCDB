from modules.alerts import extract_tech_ids_universal


def test_extract_basic() -> None:
    obj = {"rule":{"mitre":{"id":["T1190","T1059.001"]}}}
    tids = extract_tech_ids_universal(obj)
    assert "T1190" in tids and "T1059_001" in tids
