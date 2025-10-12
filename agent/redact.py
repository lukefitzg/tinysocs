def scrub(findings):
    def mask_ip(v):
        if isinstance(v,str) and v.count(".")==3:
            parts=v.split("."); return ".".join(parts[:2]+["x","x"])
        return v
    out=[]
    for f in findings:
        f2=dict(f)
        ev=f2.get("evidence") or {}
        ev["ip"] = mask_ip(ev.get("ip"))
        f2["evidence"]=ev
        out.append(f2)
    return out
