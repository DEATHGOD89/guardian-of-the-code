import re

class RegexHelper:
    _cache = {}

    @classmethod
    def compile(cls, pattern):
        if pattern not in cls._cache:
            cls._cache[pattern] = re.compile(pattern)
        return cls._cache[pattern]
