# Terraform Module と Provider の違い、および Module で実施可能なセキュリティ対策

本リポジトリの SBOM 検証 (README.md) は主に Provider を対象にした。
本書は Module と Provider の供給元リスクの違いを整理し、Module 側で現実的に取れる対策をまとめる。
調査時点は 2026-10-21。

## 1. Module と Provider の違い

### 1.1 性質の違い

| 観点 | Provider | Module |
|---|---|---|
| 実体 | Go でビルドされたバイナリ (プラグイン) | HCL のソースコード一式 |
| 実行タイミング | `terraform init` でダウンロードされ、plan / apply 時にプロセスとして起動する | plan / apply 時に設定として評価される。`local-exec` や `external` データソースを含めば任意コマンドが動く |
| 取得元 | Terraform Registry (registry.terraform.io)、プライベートレジストリ、ローカルミラー | Registry、Git (タグ / ブランチ / SHA)、HTTP アーカイブ、S3 / GCS、ローカルパス |
| 内容の可読性 | 低い。バイナリを逆解析するか、ソースリポジトリを信頼するしかない | 高い。取得後の `.terraform/modules/` をそのまま読める |
| 推移的依存 | Provider が他の Provider を引き込むことはない | Module は入れ子 Module と `required_providers` を引き込める。利用者が意図しない Provider バイナリが入る経路になる |

### 1.2 ロックファイルによる保護の違い

| 観点 | Provider | Module |
|---|---|---|
| `.terraform.lock.hcl` への記録 | あり。バージョンと `h1:` / `zh:` ハッシュが固定される | なし。`.terraform/modules/modules.json` にインストール結果が残るだけで、ロックではない |
| バージョンの再解決 | ロック済みバージョンが使われる。変更には `terraform init -upgrade` が必要 | 制約を満たす最新版が毎回選ばれる。OpenTofu も同じ挙動 |
| 内容の完全性検証 | ハッシュ照合で、同じバージョンの中身が差し替わると init が失敗する | なし。同じバージョン番号で別の内容が配信されても検出されない |
| 固定の手段 | 標準機能で十分 | Git ソースをコミット SHA で指定するか、tofulock のような外部ツールが必要 |

Coder レジストリ侵害 (2026-08-31) はこの差が顕在化した事例で、配布経路が乗っ取られ、同じバージョン番号のまま改変 Module が配信された。
バージョン固定も過去のソースレビューも検出には役立たず、利用者が取れた手段は公表後のネットワークログでの IOC 照合だった。

### 1.3 脆弱性・SBOM ツールの対応状況

| 観点 | Provider | Module |
|---|---|---|
| Syft | 検出するが purl 無し (purl-spec に `terraform` 型が未定義) | 非検出 |
| Trivy fs / sbom | 非検出。自前 CycloneDX を `pkg:golang` で与えれば照合可能 | 非検出。`pkg:generic` で SBOM に記録はできるが照合対象外 |
| Trivy config (misconfig) | 対象外 | ダウンロード済み Module も既定でスキャンされる |
| GitHub Dependency graph | `pkg:golang` purl で ecosystem GO として表示 | `pkg:generic` で ecosystem UNKNOWN として表示 |
| Dependabot alerts | `pkg:golang` なら仕組みは動くが GHSA 側の登録がほぼ無い | 照合されない |
| Dependabot version updates | `package-ecosystem: terraform` で更新 PR | 同左 (Registry Module のみ) |
| Renovate | `required_providers` と lock file 保守 | Registry Module と Git タグ参照 Module |
| アドバイザリ DB | GHSA / OSV に Terraform エコシステム無し。Go として登録された Provider のアドバイザリが少数 | 無し |

要約すると、Provider は「中身は見えないが同一性は保証される」、Module は「中身は見えるが同一性は保証されない」。
既知脆弱性の照合はどちらも実質的に機能しないため、Module では静的解析と固定、Provider では namespace の確認と HashiCorp bulletin の追跡が中心になる。

## 2. Module で実施可能なセキュリティ対策

目的別に、標準機能で済むもの、外部ツールが要るもの、運用で補うものを分けて記す。

### 2.1 インベントリ (何をどのバージョンで使っているか把握する)

侵害が公表されたときに「どのワークスペースがどの Module バージョンを使っているか」を即答できることが、照合先 DB の無い Module では脆弱性照合の代替になる。

- `terraform modules` (Terraform 1.10 以降) で解決済み Module を一覧する
- `.terraform/modules/modules.json` を読む。本リポジトリの `scripts/tflock2cdx.sh` はこれを CycloneDX に変換する。取得には `terraform get` が必要
- `terraform-config-inspect --json` で init 前の宣言ベースの一覧を取る。`--after-init` で解決後も読める
- Dependency graph に `pkg:generic` で送れば GitHub 上で名前とバージョンを可視化できる (本リポジトリの `.github/workflows/dependency-submission.yml`)
- 注意: ロックファイルベースの読み取りでは Module は拾えない。Provider と別経路で集める

### 2.2 バージョン追従

- Dependabot version updates: `dependabot.yml` に `package-ecosystem: terraform` を設定する。Registry Module と Provider の更新 PR が出る。Dependency graph とは無関係に動く
- Renovate: terraform manager が Registry Module、Git タグ参照 Module、`required_providers`、`required_version`、lock file 保守を扱う。Git ソースを多用するなら Renovate のほうが広い
- 更新 PR は CI 通過だけでマージしない。ソース差分 (Registry なら元リポジトリのタグ間 diff) をレビューする

### 2.3 完全性 (改変・差し替えの検出)

標準機能では保護されない領域で、Module 対策の中で最も優先度が高い。

- Git ソースをコミット SHA で固定する (`source = "git::https://...//path?ref=<sha>"`)。タグ移動や再公開を回避できる唯一の暗号学的保証。Registry の検索性と SemVer 解決は失う
- tofulock (実験段階) で Module 用ロックファイルを作る。Git は SHA、Registry は制約からバージョン、そのバージョンのコミットへ解決して固定し、CI の `verify` でドリフトを検出する。入れ子 Module とアーカイブ形式は対象外で、初回ロック時の内容は信頼する前提
- プライベートレジストリで審査済み Module を再公開し、利用側はそのカタログだけを参照する。信頼境界を社内に移す
- 採用前に元リポジトリのリリースタグが保護されているか確認する。タグ保護が無いと `pull_request_target` の悪用 (pwn request) や乗っ取られたメンテナアカウントでタグを動かされる
- 取得済み `.terraform/modules/` のハッシュを記録し、既知の正常版と比較する。標準機能には無いので自前で持つ
- CI のキャッシュに残った Module を無条件に再利用しない。侵害時間帯に取得したキャッシュは削除する

### 2.4 内容の静的解析 (危険パターン・悪性コード)

Module はソースなので、Provider と違って中身を機械的に検査できる。

- Trivy config はダウンロード済み Module を既定でスキャンする。Checkov も外部 Module 取得オプションがある。ただし既定ルールはクラウド設定の不備向けで、悪性コードの検出は意図していない
- サードパーティ Module 内の以下をカスタムポリシー (Rego、Checkov の Python チェック、OPA / Sentinel による plan ゲート) で禁止または要レビューにする
  - `local-exec` / `remote-exec` プロビジョナ
  - `external` データソース
  - `http` データソース (state や環境変数の外部送信に使われる)
  - Module 内で宣言された `required_providers` (利用者が意図しない Provider バイナリを引き込む)
- `terraform providers` の出力に見覚えのない Provider が無いか確認する
- plan の人間向け出力には `local-exec` のコマンド内容が出ない。plan の JSON 表現 (`terraform show -json`) の configuration 部分か、Module ソース自体を見る
- Registry のスター数やダウンロード数を安全性の根拠にしない

### 2.5 既知脆弱性の照合

現時点では手段が無い。GHSA / OSV に Module のエコシステムは無く、`pkg:generic` は照合されない。

- Registry Module の元 GitHub リポジトリの Security Advisory と Release を手動または RSS で追う
- 2.1 のインベントリを維持し、公表された侵害や欠陥に対して影響範囲を即座に特定できるようにする
- purl-spec に `terraform` 型が入り GHSA が対応するまでは、この状況は変わらない (package-url/purl-spec#369 は 2024-12 起票で Open のまま)

### 2.6 実行時・ネットワーク面

- plan / apply を実行するランナーの egress を制限し、DNS / プロキシ / VPC フローログを保持する。Coder 事件で利用者が実際に取れた検出手段は公表後の IOC 照合だった
- プロビジョニングから到達可能な資格情報は短命トークンにし、侵害を否定できない場合は確証を待たずにローテーションできる手順を用意する
- 信頼できないフォークからの PR で Module 取得を伴う CI を動かす場合は、ネットワーク隔離されたランナーを使う

## 3. 本リポジトリの SBOM との関係

| 対策 | 本リポジトリの SBOM で賄えるか |
|---|---|
| 2.1 インベントリ | ○ `tflock2cdx.sh` が Registry Module を `pkg:generic` で記録する |
| 2.2 バージョン追従 | △ SBOM 自体は追従しない。Dependabot version updates を別途設定する |
| 2.3 完全性 | ✗ SBOM はバージョンしか持たない。SHA 固定か tofulock 相当が別途必要 |
| 2.4 静的解析 | ✗ 別途 Trivy config / カスタムポリシーを回す |
| 2.5 脆弱性照合 | ✗ 照合先が無い。インベントリとしての利用に留まる |
| 2.6 実行時 | ✗ 対象外 |

## 参考

- [Scalr: Terraform module supply chain attacks](https://scalr.com/learning-center/terraform-module-supply-chain-attacks)
- [CSA: Coder Registry Compromise (2026-09)](https://labs.cloudsecurityalliance.org/research/csa-research-note-coder-registry-terraform-supply-chain-2026/)
- [BoostSecurity: Erosion of Trust in the Terraform Registry (2023-06)](https://labs.boostsecurity.io/articles/erosion-of-trust-unmasking-supply-chain-vulnerabilities-in-the-terraform-registry)
- [Averlon: Terraform Providers, the overlooked supply chain attack vector (2026-07)](https://www.averlon.ai/blog/terraform-providers-the-overlooked-supply-chain-attack-vector)
- [tofulock](https://pkg.go.dev/github.com/Conalh/tofulock)
- [OpenTofu: dependency lock file](https://opentofu.org/docs/language/files/dependency-lock/)
- [Trivy: Terraform misconfig scanning](https://trivy.dev/latest/docs/coverage/iac/terraform/)
- [Renovate: terraform manager](https://docs.renovatebot.com/modules/manager/terraform/)
- [terraform-config-inspect](https://github.com/hashicorp/terraform-config-inspect)
- [purl-spec #369: Add new PURL type 'terraform'](https://github.com/package-url/purl-spec/issues/369)
- [GitHub Advisory Database: supported ecosystems](https://github.com/github/advisory-database)
- [Trivy discussion #7566](https://github.com/aquasecurity/trivy/discussions/7566)
