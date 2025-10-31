import re
def search_regex(pattern, text):
    return re.search(pattern, text, flags=re.IGNORECASE) is not None

def find_all_regex(pattern, text):
    import re
    return re.findall(pattern, text, flags=re.IGNORECASE)
