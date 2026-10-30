from collections.abc import Sequence
from dataclasses import dataclass

from app.application.ports import InvalidRequest, ProductNameIndex
from app.domain.product import Alias, NameKey, ascii_words, name_key

CANDIDATE_LIMIT = 20


@dataclass(frozen=True)
class ProductCandidate:
    label: str
    keys: tuple[NameKey, ...]
    spellings: tuple[str, ...]
    cve_count: int
    from_alias: bool


class SearchProducts:
    def __init__(self, index: ProductNameIndex, aliases: Sequence[Alias]) -> None:
        self._index = index
        self._aliases = aliases

    def run(self, call: str) -> list[ProductCandidate]:
        query_key = name_key(call)
        if not query_key:
            raise InvalidRequest("呼び名には英数字か、かなか、漢字を入れる")
        for key in dict.fromkeys([query_key, *ascii_words(call)]):
            candidates = self._candidates(key)
            if candidates:
                return candidates
        return []

    def _candidates(self, query_key: str) -> list[ProductCandidate]:
        aliases = [alias for alias in self._aliases if alias.answers_to(query_key)]
        counts = self._index.cve_counts({key for alias in aliases for key in alias.keys})
        candidates: list[ProductCandidate] = []
        for alias in aliases:
            known = tuple(key for key in alias.keys if key in counts)
            if known:
                total = sum(counts[key] for key in known)
                candidates.append(ProductCandidate(alias.name, known, (), total, from_alias=True))
        covered = {key for candidate in candidates for key in candidate.keys}
        names = self._index.search(query_key, CANDIDATE_LIMIT + len(covered))
        found = [
            ProductCandidate(
                name.spellings[0], (name.key,), name.spellings, name.cve_count, from_alias=False
            )
            for name in names
            if name.key not in covered
        ]
        return candidates + found[:CANDIDATE_LIMIT]
