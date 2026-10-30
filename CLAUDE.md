# kadoban

中小企業が登録した製品と版から、自社に該当する脆弱性だけを判定して一手を届け、対応の記録を SCS 評価制度 ★3 の証跡にする CLI。設計判断は `docs/adr/`、コードの規約は README の「開発ルール」にある。

## コマンド

- `uv sync`
- `uv run ruff check . && uv run ruff format --check . && uv run mypy`(CI と同じ)

## 構成と依存の向き

`app` は4層。依存は presentation → application → domain の一方向で、infrastructure は application のポート(Protocol)を実装する。

- domain: エンティティと純粋ロジック。標準ライブラリ以外を import しない
- application: ユースケースとポート(`ports.py`)。ポートは差し替え先が実在するものだけ
- infrastructure: 脆弱性情報の取り込み、DB、LLM、メールの実装
- presentation: CLI。合成ルートとして infrastructure の実装を組み立て、application のポートの型として渡す

## 進め方

- フェーズ順: 0 方針、1 製品台帳と脆弱性情報、2 評価データと runner、3 LLM、4 届けると追う、5 受動的な資産の発見、6 能動的な観測、7 画面
- 新しい設計判断は先に ADR を書き、`docs/adr/README.md` の一覧を更新する
- Python 3.13、mypy strict。コメントは書かず、経緯はコミットメッセージに書く
