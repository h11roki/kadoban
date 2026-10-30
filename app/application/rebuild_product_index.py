from app.application.ports import ProductNameIndex


class RebuildProductIndex:
    def __init__(self, index: ProductNameIndex) -> None:
        self._index = index

    def run(self) -> None:
        self._index.rebuild()
