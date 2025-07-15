import re


class Tag:
    def __init__(self, attrs):
        self.attrs = attrs

    def __getitem__(self, key):
        return self.attrs.get(key)

    def get(self, key):
        return self.attrs.get(key)


class BeautifulSoup:
    def __init__(self, html, parser):  # pylint: disable=unused-argument
        self.html = html

    def find_all(self, name=None, href=False):
        if name == "a":
            pattern = r"href=['\"]([^'\"]+)['\"]"
            links = re.findall(pattern, self.html)
            tags = [Tag({"href": link}) for link in links]
            if href:
                return tags
            return tags
        if name == "img":
            pattern = r"src=['\"]([^'\"]+)['\"]"
            sources = re.findall(pattern, self.html)
            return [Tag({"src": src}) for src in sources]
        return []
