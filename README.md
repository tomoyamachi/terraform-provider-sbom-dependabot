# ymc-terraform-sbom

Terraform コードから Provider / Module の依存関係を SBOM として出力できるかの検証リポジトリ。

## 検証環境

| ツール | バージョン |
|---|---|
| Terraform | v1.16.3 (darwin_arm64) |
| Trivy | v0.76.0 |

## 検証対象

`sample/` に以下を配置し `terraform init -backend=false` でロックファイルを生成した。

- Provider: hashicorp/aws, hashicorp/random, hashicorp/null, cloudflare/cloudflare
- Module: ローカルモジュール (`./modules/bucket`) と Registry モジュール (`terraform-aws-modules/vpc/aws` 5.16.0)

## 結論

**Trivy 単体では `.terraform.lock.hcl` から Provider 依存を SBOM に出力できない。**

| 方法 | 結果 | 備考 |
|---|---|---|
| `trivy fs --format cyclonedx sample/` | ✗ 空の SBOM | `Number of language-specific files num=0`。ロックファイルは未サポート |
| `trivy fs` (ロックファイルなし、.tf のみ) | ✗ 検出なし | `required_providers` ブロックは依存として扱われない |
| `trivy rootfs sample/.terraform/providers` | △ Go バイナリとして検出 | Provider 自身の Go 内部依存 (stdlib, x/net 等) は取れるが、Provider のバージョンは `(devel)`/null で取れない |
| `scripts/tflock2cdx.sh` + `trivy sbom` | ○ 迂回策 | ロックファイルから自前で CycloneDX を生成すれば Trivy は読み込める |

### 詳細

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

## 補足

- Terraform 公式にも Provider SBOM を出力する機能はない。`terraform version -json` / `terraform providers` が唯一の機械可読な出力。
- Syft (anchore) は `.terraform.lock.hcl` 用 cataloger を持つため、Trivy 以外の選択肢として比較候補になる (本検証では未インストールのため未確認)。
