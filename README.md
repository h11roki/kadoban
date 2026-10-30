# kadoban

中小企業が使っている製品と版を登録すると、自社に該当する脆弱性だけを「該当 / 非該当 / 要確認」に分け、14 日の期限と、兼任の情報システム担当者がその日に動ける一手を届ける CLI。対応の記録は SCS 評価制度 ★3 の証跡として出す。あとで、外から見える資産の発見(受動的な収集と、同意を得た能動的な観測)を足す。

設計判断は `docs/adr/` にある。

## 状態

フェーズ 1(製品台帳と脆弱性情報)の途中。CISA KEV を手元の SQLite に取り込める。

## 使い方

```sh
uv sync
uv run alembic upgrade head
uv run python -m app.presentation.cli advisories sync
```

DB は `data/kadoban.db` にできる。置き場は環境変数 `DATA_DIR` で変えられる。

## 開発

- Python 3.13 と uv を使う
- `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest` で CI と同じ確認をする

## 開発ルール

- コメントは原則書かない。経緯や日付はコミットメッセージに書く
- 1か所でしか使わない短い処理は関数に切り出さない
- 変更は小さな単位で行う
- 設計判断は実装より先に ADR に書く
