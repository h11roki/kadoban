from dataclasses import dataclass

from app.application.ports import AliasBook, InvalidRequest, ProductNameIndex
from app.domain.product import NameKey, ascii_part, name_key

CANDIDATE_LIMIT = 20


@dataclass(frozen=True)
class ProductCandidate:
    label: str
    keys: tuple[NameKey, ...]
    spellings: tuple[str, ...]
    cve_count: int
    from_alias: bool


class SearchProducts:
    def __init__(self, index: ProductNameIndex, aliases: AliasBook) -> None:
        self._index = index
        self._aliases = aliases

    def run(self, call: str) -> list[ProductCandidate]:
        query_key = name_key(call)
        if not query_key:
            raise InvalidRequest("呼び名には英数字か、かなか、漢字を入れる")
        candidates: list[ProductCandidate] = []
        for alias in self._aliases.answering_to(query_key):
            counts = self._index.cve_counts(alias.keys)
            known = tuple(key for key in alias.keys if key in counts)
            if known:
                candidates.append(
                    ProductCandidate(alias.name, known, (), sum(counts.values()), from_alias=True)
                )
        covered = {key for candidate in candidates for key in candidate.keys}
        limit = CANDIDATE_LIMIT + len(covered)
        names = self._index.search(query_key, limit)
        if not names and not candidates and ascii_part(query_key) not in ("", query_key):
            names = self._index.search(ascii_part(query_key), limit)
        candidates += [
            ProductCandidate(
                name.spellings[0], (name.key,), name.spellings, name.cve_count, from_alias=False
            )
            for name in names
            if name.key not in covered
        ][:CANDIDATE_LIMIT]
        return candidates
