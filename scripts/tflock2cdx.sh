#!/usr/bin/env bash
# .terraform.lock.hcl と .terraform/modules/modules.json から CycloneDX SBOM を生成する
# 用法: scripts/tflock2cdx.sh <terraformディレクトリ> > sbom.cdx.json
# 依存: terraform, jq
set -euo pipefail

tfDir="${1:-.}"
cd "$tfDir"

# terraform version -json の provider_selections からロック済みプロバイダを取得
providers=$(terraform version -json | jq -c '.provider_selections // {}')

# modules.json からレジストリ由来モジュール（バージョン付き）を取得
modulesFile=".terraform/modules/modules.json"
modules='[]'
if [ -f "$modulesFile" ]; then
  modules=$(jq -c '[.Modules[] | select(.Version != null)]' "$modulesFile")
fi

jq -n --argjson providers "$providers" --argjson modules "$modules" '
  # プロバイダ: "registry.terraform.io/hashicorp/aws" -> purl は Go モジュールとして表現
  # (hashicorp 配下は github.com/hashicorp/terraform-provider-<name> がソース)
  def providerComponent:
    (.key | split("/")) as $p
    | {
        type: "library",
        "bom-ref": ("pkg:golang/github.com/" + $p[1] + "/terraform-provider-" + $p[2] + "@v" + .value),
        name: ("github.com/" + $p[1] + "/terraform-provider-" + $p[2]),
        version: .value,
        purl: ("pkg:golang/github.com/" + $p[1] + "/terraform-provider-" + $p[2] + "@v" + .value),
        properties: [
          {name: "terraform:provider.source", value: .key},
          {name: "terraform:component.kind", value: "provider"}
        ]
      };
  def moduleComponent:
    {
      type: "library",
      "bom-ref": ("pkg:generic/" + .Source + "@" + .Version),
      name: .Source,
      version: .Version,
      purl: ("pkg:generic/" + (.Source | @uri) + "@" + .Version),
      properties: [
        {name: "terraform:module.key", value: .Key},
        {name: "terraform:component.kind", value: "module"}
      ]
    };
  {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: (now | todate),
      tools: [{name: "tflock2cdx", version: "0.1"}],
      component: {type: "application", name: "terraform-root-module", "bom-ref": "root"}
    },
    components: (
      ($providers | to_entries | map(providerComponent)) + ($modules | map(moduleComponent))
    ),
    dependencies: [
      {ref: "root", dependsOn: (
        ($providers | to_entries | map(providerComponent."bom-ref")) + ($modules | map(moduleComponent."bom-ref"))
      )}
    ]
  }'
