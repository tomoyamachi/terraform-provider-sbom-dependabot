#!/usr/bin/env bash
# tflock2cdx.sh が生成した CycloneDX SBOM を GitHub Dependency submission API の snapshot 形式に変換する
# 用法: scripts/cdx2ghsnapshot.sh <sbom.cdx.json> <manifestパス> > snapshot.json
# 環境変数:
#   GITHUB_SHA / GITHUB_REF  … snapshot を紐付けるコミットとブランチ (Actions では自動設定)
#   CORRELATOR               … job.correlator (同じ値で送ると上書き、違う値なら並存)
#   PURL_STYLE               … golang (既定) | terraform  Provider の purl 表現を切り替える
# 依存: jq
set -euo pipefail

cdxFile="${1:?cdx file}"
manifestPath="${2:?manifest path}"
purlStyle="${PURL_STYLE:-golang}"
correlator="${CORRELATOR:-tflock2cdx-${purlStyle}}"

jq -n \
  --slurpfile cdx "$cdxFile" \
  --arg sha "${GITHUB_SHA:?GITHUB_SHA}" \
  --arg ref "${GITHUB_REF:?GITHUB_REF}" \
  --arg correlator "$correlator" \
  --arg jobId "${GITHUB_RUN_ID:-local}" \
  --arg manifestPath "$manifestPath" \
  --arg purlStyle "$purlStyle" \
  --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  $cdx[0].components as $components
  # Provider の purl を表現方法に応じて組み立てる (module は CycloneDX の purl をそのまま使う)
  | def purlOf:
      (.properties | map(select(.name == "terraform:provider.source")) | .[0].value) as $src
      | if $purlStyle == "terraform" and $src != null
        then "pkg:terraform/" + ($src | sub("^registry.terraform.io/"; "")) + "@" + .version
        else .purl end;
  {
    version: 0,
    sha: $sha,
    ref: $ref,
    job: {correlator: $correlator, id: $jobId},
    detector: {name: "tflock2cdx", version: "0.1", url: "https://github.com/tomoyamachi/ymc-terraform-sbom"},
    scanned: $now,
    manifests: {
      ($manifestPath): {
        name: $manifestPath,
        file: {source_location: $manifestPath},
        resolved: (
          $components
          | map(purlOf as $p | {key: $p, value: {package_url: $p, relationship: "direct", scope: "runtime"}})
          | from_entries
        )
      }
    }
  }'
