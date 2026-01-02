def _to_int(v):
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except Exception:
        return None

def diagnose_policy(effective_policy: dict, requirements: dict) -> dict:
    checks = []
    failed = []

    for key, rule in requirements.items():
        op = rule["op"]
        expected = rule["value"]

        actual_raw = effective_policy.get(key)
        actual = _to_int(actual_raw)

        if actual is None:
            ok = False
            reason = "미설정(None)"
        else:
            if op == ">=":
                ok = actual >= expected
            elif op == "<=":
                ok = actual <= expected
            elif op == "==":
                ok = actual == expected
            else:
                ok = False
            reason = "" if ok else f"기준 불만족: {actual} {op} {expected} 아님"

        if not ok:
            failed.append(key)

        checks.append({
            "key": key,
            "actual_raw": actual_raw,
            "actual": actual,
            "expected": f"{op} {expected}",
            "ok": ok,
            "reason": reason,
        })

    return {
        "is_vulnerable": len(failed) > 0,
        "failed_keys": failed,
        "checks": checks,
    }