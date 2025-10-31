import yaml
def parse(content: str):
    try:
        data = list(yaml.safe_load_all(content))
        return {'docs': data}
    except Exception:
        return {'raw': content}
