class RequestException(Exception):
    pass


class Session:
    def __init__(self):
        self.proxies = {}
        self.headers = {}

    def get(self, url, timeout=10):  # simple stub
        raise RequestException("network disabled")
