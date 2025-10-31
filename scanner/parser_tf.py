# Minimal Terraform parser (very small): returns raw text in this simple project
def parse(content: str):
    # For this lightweight scanner we don't build a full AST; just return content
    return {'content': content}
