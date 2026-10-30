from app.application.ports import ProductLedger
from app.domain.product import RegisteredProduct, company_name


class ListProducts:
    def __init__(self, ledger: ProductLedger) -> None:
        self._ledger = ledger

    def run(self, company: str) -> list[RegisteredProduct]:
        return self._ledger.products(company_name(company))
