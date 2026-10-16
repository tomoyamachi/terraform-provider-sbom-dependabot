# terraform-provider-sbom-dependabot

Terraform コードから Provider / Module の依存関係を SBOM として出力できるかの検証リポジトリ。

## 検証環境

| ツール | バージョン |
|---|---|
| Terraform | v1.16.3 (darwin_arm64) |
| Trivy | v0.76.0 |
| Syft | v1.54.1 |

## 検証対象

`sample/` に以下を配置し `terraform init -backend=false` でロックファイルを生成した。

- Provider: hashicorp/aws, hashicorp/random, hashicorp/null, cloudflare/cloudflare
- Module: ローカルモジュール (`./modules/bucket`) と Registry モジュール (`terraform-aws-modules/vpc/aws` 5.16.0)

## 結論

- Trivy / Syft いずれも単体では `.terraform.lock.hcl` の Provider を GitHub 連携可能な SBOM にできない (Trivy は非検出、Syft は検出するが purl 無し)
- 自前生成した CycloneDX (`scripts/tflock2cdx.sh`) を Dependency submission API に送れば Dependency graph に Provider / Module が表示され、`pkg:golang` purl なら Dependabot alerts も機能する
- ローカルの `gh api` から送った snapshot は manifest 名 `sample/.terraform.lock.hcl` に限って反映されず、GitHub Actions (`GITHUB_TOKEN`) から送ると反映された。原因は未特定のため、送信は Actions から行う前提にしている

### Trivy

**Trivy 単体では `.terraform.lock.hcl` から Provider 依存を SBOM に出力できない。**

| 方法 | 結果 | 備考 |
|---|---|---|
| `trivy fs --format cyclonedx sample/` | ✗ 空の SBOM | `Number of language-specific files num=0`。ロックファイルは未サポート |
| `trivy fs` (ロックファイルなし、.tf のみ) | ✗ 検出なし | `required_providers` ブロックは依存として扱われない |
| `trivy rootfs sample/.terraform/providers` | △ Go バイナリとして検出 | Provider 自身の Go 内部依存 (stdlib, x/net 等) は取れるが、Provider のバージョンは `(devel)`/null で取れない |
| `scripts/tflock2cdx.sh` + `trivy sbom` | ○ 迂回策 | ロックファイルから自前で CycloneDX を生成すれば Trivy は読み込める |

#### 詳細

1. **`trivy fs` は Terraform ロックファイルを依存として認識しない。**
   Trivy の言語サポート一覧 (Go, Node.js, Python, …) に Terraform は含まれず、Terraform はあくまで misconfig スキャンの対象。
   upstream の要望 [aquasecurity/trivy#7566](https://github.com/aquasecurity/trivy/discussions/7566) (2024-09) では
   メンテナが「SBOM 標準化が進んでおらず維持が難しい」と回答し、未実装のまま。

2. **`trivy rootfs` で `.terraform/providers/` 配下の Provider バイナリは Go バイナリとして解析できる。**
   `trivy fs` は Go バイナリを解析しない（ロックファイル専用）ため `rootfs` サブコマンドが必要。
   得られるのは Provider が内包する Go モジュール (例: aws provider は 355 パッケージ、脆弱性 112 件) であり、
   「Provider aws のバージョンは 5.100.0」という情報は SBOM に含まれない (root パッケージのバージョンは null)。
   Provider の供給元リスク（内包する stdlib / grpc / x/crypto の CVE）を見たい場合には有用。

3. **迂回策: `terraform version -json` の `provider_selections` から CycloneDX を生成する。**
   `scripts/tflock2cdx.sh` はロック済み Provider と Registry モジュールを CycloneDX 1.5 に変換する。
   Provider の purl は `pkg:golang/github.com/<ns>/terraform-provider-<name>@v<ver>` とし、
   Go モジュールとして扱わせることで `trivy sbom` が Provider 自体の GHSA 等を照合できる
   (hashicorp/cloudflare など GitHub 上のソース配置が慣習通りの Provider に限る)。
   モジュール (`pkg:generic/...`) は Trivy では脆弱性照合対象外だが、SBOM には記録される。

```sh
# SBOM 生成
scripts/tflock2cdx.sh sample > sample/sbom.cdx.json
# Trivy で読み込み・脆弱性照合
trivy sbom sample/sbom.cdx.json
```

### Syft

**Syft は `.terraform.lock.hcl` の Provider を検出するが purl を付けないため、GitHub 連携にはそのまま使えない。**

| 方法 | 結果 | 備考 |
|---|---|---|
| `syft scan dir:sample -o table` | ○ Provider 4 件検出 | `terraform-lock-cataloger` が解析。name `registry.terraform.io/hashicorp/aws`、version `5.100.0`、type `terraform` |
| `-o cyclonedx-json` / `-o spdx-json` | △ purl 無し | CycloneDX は `purl: null`、SPDX は CPE (`cpe:2.3:a:hashicorp:aws:5.100.0`) のみ |
| `-o github-json` | ✗ `resolved` が空 | purl の無いパッケージは出力されず manifest 名だけ残る。送信しても依存 0 件 |
| Registry モジュール | ✗ 非検出 | `.terraform/modules/modules.json` を読む cataloger は無い |
| `.terraform/providers/` 配下 | △ Go バイナリとして検出 | Trivy rootfs と同様に Provider 内包の Go モジュール (462 件) が出る。`--exclude './.terraform/**'` で除外可 |

purl が無いのは意図的で、`syft/pkg/cataloger/terraform/parse_tf_lock.go` に
「purl-spec に terraform 型が定義されるまで PURL を省略する」旨の TODO がある
([package-url/purl-spec#369](https://github.com/package-url/purl-spec/issues/369))。
なお `.terraform/modules/` 配下に Registry モジュールの `.github/workflows` が含まれると、github-action として拾われるノイズが出る。

```sh
syft scan dir:sample --exclude './.terraform/**' -o cyclonedx-json=syft.cdx.json -o github-json=syft.github.json
```

### GitHub Dependency submission API

**自前 SBOM を snapshot 形式に変換して送れば Dependency graph に表示でき、`pkg:golang` purl なら Dependabot alerts も機能する。**

- エンドポイントは `POST /repos/{owner}/{repo}/dependency-graph/snapshots`。
  `gh api` + OAuth トークン (`repo` スコープ) で送信できる。
- private リポジトリは先に `PUT /repos/{owner}/{repo}/vulnerability-alerts` で Dependency graph と Dependabot alerts を有効化する。
- 変換は `scripts/cdx2ghsnapshot.sh`、送信は `.github/workflows/dependency-submission.yml` (main への push で `GITHUB_TOKEN` を使って送信)。
  Provider のバージョンはロックファイルから読めるため `terraform init` は不要で、モジュール取得の `terraform get` だけ行う。

| purl の表現 | Dependency graph | Dependabot alerts |
|---|---|---|
| `pkg:golang/github.com/hashicorp/terraform-provider-aws@v5.100.0` | ○ ecosystem `GO` として表示 | ○ `v1.13.0` を送ると GHSA-r48h-jr2j-9g78 が open になり、取り除くと fixed になる |
| `pkg:terraform/hashicorp/aws@5.100.0` (独自型) | △ ecosystem `UNKNOWN`、名前とバージョンは表示される | ✗ 照合されない |
| `pkg:generic/registry.terraform.io%2F...%2Fvpc%2Faws@5.16.0` (モジュール) | △ ecosystem `UNKNOWN` | ✗ |
| Syft `github-json` | ✗ 依存 0 件 | ✗ |

GHSA の Go エコシステムに登録された `terraform-provider-*` のアドバイザリは少数
(aws は `< 1.14.0` の 1 件のみ、cloudflare / random / null は 0 件) なので、Provider 自体の脆弱性検知としての実効性は限定的。
内包する Go モジュールの脆弱性を見たい場合は Trivy rootfs / Syft の Go バイナリ解析を併用する。

snapshot の挙動として観測したもの:

- 同じ `job.correlator` + `job.id` で新しい `scanned` を送ると置き換わる。
- 異なる `job.correlator` から同じ manifest 名に送ると依存は和集合になる。
- `manifests: {}` を送っても既存 manifest は消えない。消すには元の correlator から `resolved: {}` を送る (manifest は 0 件として残り、alerts は fixed になる)。
- 同じ `job.correlator` の新しい snapshot は、manifest 名が異なっていても前の snapshot を丸ごと置き換える
  (ワークフローから `sample/sbom.cdx.json` → `sample/.terraform.lock.hcl` と送り分けたら前者は消えた)。
- **ローカルの `gh api` (OAuth トークン) から manifest 名 `sample/.terraform.lock.hcl` に送った snapshot は、
  correlator / `job.id` / `sha` を変えて 10 回以上試しても依存 0 件のまま反映されなかった。**
  同じ内容を存在しないパスや `README.md`、`sample/main.tf` に送ると正常に表示され、
  GitHub Actions の `GITHUB_TOKEN` から同じ manifest 名に送ると 5 件すべて表示された。
  その後ローカルから別 correlator で同じ manifest 名に追加送信しても反映されない。
  原因は特定できていない (private リポジトリでは compare API が 404 で、ネイティブ解析の有無を確認できない)。
  実運用では Actions からの送信を前提にするのが安全。
- Dependency graph に表示されるのはデフォルトブランチの snapshot のみ。

取り込み結果の確認方法:

```sh
# GraphQL (hawkgirl preview) で manifest ごとの依存を見る
gh api graphql -H 'Accept: application/vnd.github.hawkgirl-preview+json' -f query='{ repository(owner:"OWNER", name:"REPO") { dependencyGraphManifests(first:20) { nodes { filename dependenciesCount dependencies(first:20){ nodes { packageName requirements packageManager } } } } } }'
# Dependency graph 全体を SPDX でエクスポート
gh api repos/OWNER/REPO/dependency-graph/sbom
# Dependabot alerts
gh api repos/OWNER/REPO/dependabot/alerts
```

### Dependabot での扱い (まとめ)

**登録はできる。alert も仕組みとしては動くが、実運用で検出されることはほぼ期待できない。**

| 観点 | 結果 |
|---|---|
| Dependency graph への登録 | ○ 自前 CycloneDX → snapshot 変換 → submission API で Provider / Module が表示される (Syft / Trivy の出力では不可) |
| Dependabot alerts の照合 | ○ `pkg:golang` purl なら照合される。aws `v1.13.0` を送ると GHSA-r48h-jr2j-9g78 が open になり、取り除くと fixed になった |
| 実際に alert が出る見込み | ✗ GitHub Advisory Database に Terraform エコシステムが無く、Go モジュールとして登録された Provider のアドバイザリは aws の 1 件 (`< 1.14.0`) 程度。cloudflare / random / null は 0 件 |
| Registry モジュール | ✗ `pkg:generic` で載せるしかなく UNKNOWN 表示のみ。照合対象外 |
| Dependabot security updates (修正 PR) | ✗ `.terraform.lock.hcl` を Go の manifest として扱えないため自動 PR は作られない |
| Dependabot version updates (更新 PR) | ○ 別機能。`dependabot.yml` の `package-ecosystem: terraform` で Dependency graph と無関係に動く |

用途別の整理:

- Provider のバージョンを GitHub 上で可視化したい → submission API で十分
- Provider 自体の脆弱性を Dependabot で拾いたい → GHSA 側の登録が無いので穴だらけ。purl-spec に `terraform` 型が入り GHSA が対応するまでは期待できない
- Provider が内包する Go ライブラリの CVE を見たい → Trivy rootfs / Syft の Go バイナリ解析を別途回す

## 補足

- Terraform 公式にも Provider SBOM を出力する機能はない。`terraform version -json` / `terraform providers` が唯一の機械可読な出力。
- purl-spec に `terraform` 型が定義されれば Syft の purl 出力と GitHub 側のエコシステム認識が揃う可能性があるが、現時点では `pkg:golang` で Go モジュールとして扱わせるのが唯一 Dependabot と連動する表現。
