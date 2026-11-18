import json


def evaluate(record: dict, rule: dict) -> dict:
    weights = json.loads(rule["weights"])
    controls = {key: None for key in weights}
    applicable = set(weights)
    platform = record["platform"]

    def combine(values):
        return (
            False
            if False in values
            else (True if values and all(value is True for value in values) else None)
        )

    def not_zero(value):
        return value > 0 if isinstance(value, (int, float)) else None

    trustworthy = [entry for entry in record["evidence"] if entry["verified_integrity"]]
    for item in trustworthy:
        data = item["payload"]
        if item["module"] == "windows":
            controls["antivirus"] = combine([data.get("defender_antivirus"), data.get("defender_realtime")])
            states = [
                entry.get("ProtectionStatus")
                for entry in (data.get("bitlocker") or [])
                if isinstance(entry, dict)
            ]
            controls["encryption"] = combine(
                [True if state in (1, "On") else False if state in (0, "Off") else None for state in states]
            )
            fw = [entry.get("Enabled") for entry in (data.get("firewall") or []) if isinstance(entry, dict)]
            controls["configuration"] = combine(
                [combine(fw), not_zero(data.get("uac")), not_zero(data.get("screen_lock_seconds"))]
            )
        elif item["module"] in ("android", "ios"):
            values = {
                key: {"pass": True, "fail": False}.get(entry["state"])
                for key, entry in data["checks"].items()
            }
            controls["os"] = values.get("support")
            controls["updates"] = values.get("os_updates")
            controls["encryption"] = values.get("storage_encryption")
            controls["antivirus"] = values.get("play_protect")
            smartphone = (
                ("screen_lock", "unknown_sources", "usb_debugging")
                if platform == "android"
                else ("passcode", "security_config")
            )
            controls["configuration"] = combine([values.get(key) for key in smartphone])
    if platform == "ios":
        applicable -= {"antivirus", "encryption"}
    if platform in {"usb", "other"}:
        applicable.clear()
    state = [entry["status"] for entry in record["findings"] if entry["category"] == "vulnerable_software"]
    if state:
        controls["mitigation"] = (
            True if all(item in ("resolved", "false_positive") for item in state) else False
        )
    covered = sum(weights[key] for key in applicable if controls[key] is not None)
    available = sum(weights[key] for key in applicable)
    coverage = round(100 * covered / available) if available else 0
    minimum = int(rule["minimum_coverage"])
    score = (
        round(100 * sum(weights[key] for key in applicable if controls[key] is True) / covered)
        if covered and coverage >= minimum
        else None
    )
    labels = [
        (90, "Sangat baik"),
        (75, "Baik"),
        (60, "Memerlukan perbaikan"),
        (40, "Lemah"),
        (0, "Sangat lemah"),
    ]
    category = (
        next(label for threshold, label in labels if score >= threshold)
        if score is not None
        else "Cakupan tidak memadai"
    )
    return {
        "platform": platform,
        "coverage": coverage,
        "score": score,
        "category": category,
        "rule_version": rule["version"],
        "minimum": minimum,
        "controls": {
            key: {
                "weight": weight,
                "state": "not_applicable"
                if key not in applicable
                else ("pass" if controls[key] is True else ("fail" if controls[key] is False else "unknown")),
            }
            for key, weight in weights.items()
        },
    }
