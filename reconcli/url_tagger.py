TAG_PATTERNS = {
    "admin": ["admin", "dashboard", "panel", "manage"],
    "upload": ["upload", "file", "media"],
    "api": ["api", "/v1/", "/v2/"],
    "debug": ["debug", "dev", "sandbox"],
    "legacy": ["old", "legacy", "v0", "backup"],
}


def tag_urls(urls):
    tagged = []
    for url in urls:
        tags = []
        for tag, patterns in TAG_PATTERNS.items():
            if any(p in url.lower() for p in patterns):
                tags.append(tag)
        tagged.append((url, tags))
    return tagged
