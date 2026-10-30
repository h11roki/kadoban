from collections.abc import Callable
from datetime import datetime

from app.application.ports import InvalidRequest, ProductLedger, ProductNameIndex
from app.domain.product import Product


class RegisterProduct:
    def __init__(
        self, index: ProductNameIndex, ledger: ProductLedger, now: Callable[[], datetime]
    ) -> None:
        self._index = index
        self._ledger = ledger
        self._now = now

    def run(self, product: Product) -> int:
        known = self._index.cve_counts(product.keys)
        unknown = [str(key) for key in product.keys if key not in known]
        if unknown:
            raise InvalidRequest(
                f"写した脆弱性情報に無い名前の鍵: {', '.join(unknown)}。product search で探す"
            )
        return self._ledger.add(product, registered_at=self._now())
