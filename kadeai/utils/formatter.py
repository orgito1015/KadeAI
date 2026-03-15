"""Output formatting helpers for KadeAI."""


def separator(char="─", width=55) -> str:
    return char * width


def section(title: str) -> str:
    return f"\n{separator()}\n  {title}\n{separator()}\n"


def bullet_list(items: list, indent=2) -> str:
    prefix = " " * indent
    return "\n".join(f"{prefix}• {item}" for item in items)
