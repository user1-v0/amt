"""Caps that keep one decompiled file from crowding out the rest."""

MAX_CLASS_CHARS = 20_000
MAX_NATIVE_BYTES = 8 * 1024 * 1024
MAX_FUNCTIONS_PER_LIB = 30
MAX_FUNCTION_CHARS = 8_000
MAX_PACK_CHARS = 800_000
EXCERPT_CHARS = 1_500
MAX_FRAMEWORK_FILES = 25
MAX_FRAMEWORK_CHARS = 200_000
MAX_FRAMEWORK_READ = 2 * 1024 * 1024
PAGE_CHARS = 8_000
MAX_ZIP_MEMBERS = 500
MAX_EXTRACT_BYTES = 1024 * 1024 * 1024
MAX_QUOTE_CHARS = 500


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n...[truncated]", True


def select_names(names: list[str], limit: int) -> list[str]:
    chosen: list[str] = []
    for name in names:
        if not name or name in chosen:
            continue
        chosen.append(name)
        if len(chosen) >= limit:
            break
    return chosen
