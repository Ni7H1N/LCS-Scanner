# Very small Dockerfile parser: return lines and instructions
def parse(content: str):
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith('#')]
    instrs = []
    for l in lines:
        parts = l.split(None, 1)
        if parts:
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ''
            instrs.append({'cmd': cmd, 'arg': arg})
    return {'instructions': instrs, 'raw': content}
