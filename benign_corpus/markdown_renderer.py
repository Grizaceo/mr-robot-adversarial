"""Renders markdown with an allow-listed HTML sanitizer (no script execution)."""
import bleach
import markdown


ALLOWED_TAGS = [
    "p", "br", "strong", "em", "ul", "ol", "li", "code", "pre",
    "h1", "h2", "h3", "h4", "blockquote", "a",
]
ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}


def render(md_source: str) -> str:
    raw_html = markdown.markdown(md_source, extensions=["fenced_code"])
    return bleach.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
