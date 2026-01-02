def parse_pam_entries(lines: list[str]) -> list[dict]:
    out: list[dict] = []

    for i, line in enumerate(lines or []):
        raw = line
        parts = line.split()
        if len(parts) < 3:
            continue

        ptype = parts[0]

        j = 1
        if parts[j].startswith("["):
            control_parts = [parts[j]]
            j += 1
            while j < len(parts) and not control_parts[-1].endswith("]"):
                control_parts.append(parts[j])
                j += 1
            control = " ".join(control_parts)
        else:
            control = parts[j]
            j += 1

        if j >= len(parts):
            continue
        module = parts[j]
        j += 1

        args = parts[j:]

        options = pam_args_to_options(args)

        out.append({
            "idx": i,
            "ptype": ptype,
            "control": control,
            "module": module,
            "args": args,
            "options": options,
            "raw": raw,
        })

    return out

def pam_args_to_options(args: list[str]) -> dict[str, str | bool]:
    opts: dict[str, str | bool] = {}
    for a in args:
        if "=" in a:
            k, v = a.split("=", 1)
            opts[k] = v
        else:
            opts[a] = True
    return opts