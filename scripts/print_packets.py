#!/usr/bin/env python3
"""Print labeling packets for one rule in compact, judgeable form."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
pkts = [json.loads(l) for l in (ROOT / "results" / "labeling_packets.jsonl").read_text().splitlines()]

rule = sys.argv[1]
sel = [p for p in pkts if p["rule"] == rule]
print(f"### {rule}: {len(sel)} packets")
for p in sel:
    f = p["file"].split("/", 1)[1].replace(".yaml", "")
    head = f'{p["sample_id"]} [{p["group"]}] {f} :: {p["kind"]}/{p["name"]}'
    if p.get("not_found"):
        print(head + " :: NOT_FOUND")
        continue
    if "secret" in p:
        print(head + f' :: type={p["secret"]["type"]} values={p["secret"]["values"]}')
        continue
    if "rbac_rules" in p:
        print(head + f' :: {json.dumps(p["rbac_rules"])}')
        continue
    if "roleRef" in p:
        subs = ",".join(f'{s.get("kind")}:{s.get("name")}' for s in (p.get("subjects") or []))
        print(head + f' :: roleRef={p["roleRef"]} subjects={subs}')
        continue
    pod_sc = p.get("pod_sc") or {}
    parts = [f'ns={p.get("ns")}', f'sa={p.get("sa")}']
    if rule == "SA_TOKEN_AUTOMOUNTED":
        parts += [f'pod_auto={p.get("pod_automount")}', f'sa_auto={p.get("sa_automount")}']
    if rule.startswith("HOST"):
        parts.append(f'host={p.get("host")}')
    if rule == "SEC_NO_SECCOMP":
        parts.append(f'ann={p.get("annotations")} pod_seccomp={pod_sc.get("seccompProfile")}')
    for c in p.get("containers") or []:
        sc = c.get("sc") or {}
        if rule == "SEC_PRIVILEGED":
            focus = f'priv={sc.get("privileged")}'
        elif rule == "SEC_APE_NOT_DISABLED":
            focus = f'ape={sc.get("allowPrivilegeEscalation")} pod_ape={pod_sc.get("allowPrivilegeEscalation")}'
        elif rule in ("SEC_ROOT_NOT_PREVENTED", "SEC_RUN_AS_ROOT_EXPLICIT"):
            focus = (f'rnr={sc.get("runAsNonRoot")} user={sc.get("runAsUser")} '
                     f'pod_rnr={pod_sc.get("runAsNonRoot")} pod_user={pod_sc.get("runAsUser")}')
        elif rule == "SEC_NO_SECCOMP":
            focus = f'seccomp={sc.get("seccompProfile")}'
        elif rule.startswith("SEC_CAP") or rule == "SEC_DANGEROUS_CAPABILITY":
            focus = f'caps={json.dumps(sc.get("capabilities"))}'
        elif rule.startswith("RES"):
            focus = f'res={json.dumps(c.get("resources"))}'
        elif rule.startswith("REL"):
            focus = f'probes={c["probes"]}'
        elif rule.startswith("IMG"):
            focus = ""
        elif rule == "SECRET_LITERAL_ENV":
            focus = f'env={json.dumps(c["env_values"])}'
        else:
            focus = f'sc={json.dumps(sc)} res={json.dumps(c.get("resources"))}'
        print(head + " :: " + " ".join(parts) + f' :: {c["name"]} img={c["image"]} {focus}')
