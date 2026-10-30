# kadoban

中小企業が登録した製品と版から、自社に該当する脆弱性だけを判定して一手を届け、対応の記録を SCS 評価制度 ★3 の証跡にする CLI。設計判断は `docs/adr/`、コードの規約は README の「開発ルール」にある。

## コマンド

- `uv sync`
- `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest`(CI と同じ。DB の結合テストは一時ディレクトリの SQLite に migration を流して使う)
- `uv run alembic upgrade head` で DB を作る、または最新の形にする(`--sql` を付けると DB につながず SQL だけを出す)。DB は `KADOBAN_DATA_DIR`(既定はリポジトリ直下の `data`。どこから実行しても同じ場所。相対パスを書くと実行した場所から数えるので、変えるときは絶対パスで書く。git 管理外)の `kadoban.db`。表を変えたら `uv run alembic revision --autogenerate --rev-id <次の4桁> -m "<内容>"` で `migrations/versions/` に作る(ruff の hook で整形される)
- `uv run python -m app.presentation.cli advisories sync` で CISA KEV を取り込む。公開日時(`dateReleased`)が手元より新しければ表をまるごと入れ替え、同じなら何もせず、古ければ(CDN の古い写しなど)入れ替えない。比べることと入れ替えることは 1 つの取引で行い、DB の部品が「入れ替えた / 同じ / 手元より古い」を返す。一覧が空か、同じ CVE が 2 度載っていれば入れ替えずに 1 で終わる(ADR 0004)。`KADOBAN_HTTP_TIMEOUT_SECONDS`(既定 60)は、つなぐ、1 回読む、1 回書くのそれぞれの待ちの上限で、取得全体の上限ではない。リダイレクトはたどる

## 構成と依存の向き

`app` は4層。依存は presentation → application → domain の一方向で、infrastructure は application のポート(Protocol)を実装する。

- domain: エンティティと純粋ロジック。標準ライブラリ以外を import しない
- application: ユースケースとポート(`ports.py`)。ポートは差し替え先が実在するものだけ(取り込み元と手元の DB。テストではフェイクに替える)
- infrastructure: 脆弱性情報の取り込み、DB、LLM、メールの実装
- presentation: CLI(`presentation/cli.py`、typer)。合成ルートとして infrastructure の実装を組み立て、application のポートの型として渡す

設定は `app/settings.py`(pydantic-settings、頭に `KADOBAN_` の付いた環境変数から読む)。DB は SQLAlchemy Core の表(`infrastructure/db/tables.py`)と Alembic(`migrations/`)。SQLite の取引は SQLAlchemy が始め(`infrastructure/db/engine.py`)、書く取引だけを実行の設定 `TAKE_WRITE_LOCK` で `BEGIN IMMEDIATE` にして、同時に走る取り込みが読んでから書くまでの間に割り込まないようにする。読むだけの取引は `BEGIN` で、書いている最中でも読める。取り込み元が失敗したか形が変わったときは infrastructure が、取り込み元の一覧が空か同じ ID が重なっているときはユースケースが `AdvisorySourceError` を投げる(空や重なりで表を壊さないのは取り込み元によらない決まりなので、ユースケースが確かめる)。手元の DB を読めないか書けないとき(置き場を作れない、migration を流していない、壊れている、保存した値が読めない)は infrastructure が `ReplicaError` に変える。どちらも `application/ports.py` にあり、CLI が文を出して 1 で終わる。設定の値が正しくないときも CLI が文を出して 1 で終わる。

## 決まっていること(詳細は ADR)

- 登録した製品の該当判定から始め、LLM の前に評価基盤を作り、外から見える資産の発見は後で足す(ADR 0001)
- 該当判定は該当 / 非該当 / 要確認の 3 つ。範囲が構造化されていて構成の条件が無いものはコードで決め(版が分からなければ要確認)、範囲が文だけのもの、版の読み替えが要るもの、構成の条件があるものを LLM が根拠つきで判定する。該当を非該当とする誤りを最も重くし、迷ったら要確認にする(ADR 0002)
- 版の範囲は NVD、悪用の事実は CISA KEV から取り込み、手元の SQLite に写したものだけで照合する。日本語の情報はフェーズ 2 から JVN iPedia で取り、戻っていなければ JVN 本体を読む(ADR 0003)
- NVD は年ごとの一括ファイルで全件を写し、毎日は更新分のファイルを入れる。CVE ごとに元の JSON を圧縮して持ち、NVD と採番機関の版の範囲を出どころつきで表に展開する。KEV は毎日取り、公開日時が新しければ表をまるごと入れ替える(ADR 0004)

## 進め方

- フェーズ順: 0 方針、1 製品台帳と脆弱性情報、2 評価データと runner、3 LLM、4 届けると追う、5 受動的な資産の発見、6 能動的な観測、7 画面
- 新しい設計判断は先に ADR を書き、`docs/adr/README.md` の一覧を更新する
- Python 3.13、mypy strict。コメントは書かず、経緯はコミットメッセージに書く
