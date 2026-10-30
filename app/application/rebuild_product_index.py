from app.application.ports import AdvisoryStore


class RebuildProductIndex:
    def __init__(self, store: AdvisoryStore) -> None:
        self._store = store

    def run(self) -> None:
        self._store.rebuild_product_names()
