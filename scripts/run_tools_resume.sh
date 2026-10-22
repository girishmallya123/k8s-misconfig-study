#!/usr/bin/env bash
# Resume of run_tools.sh after an interruption: kube-linter output was already
# complete and valid, so only polaris / kubeaudit / checkov run here.
set +e
cd "$(dirname "$0")/.."
mkdir -p results/tools
BIN=bin

echo "== polaris =="
$BIN/polaris audit --audit-path corpus/helm --format json > results/tools/polaris_helm.json 2> results/tools/polaris_helm.err
echo "exit=$? bytes=$(wc -c < results/tools/polaris_helm.json)"

echo "== kubeaudit (per file) =="
: > results/tools/kubeaudit_helm.jsonl
: > results/tools/kubeaudit_helm.err
for f in corpus/helm/*.yaml; do
  $BIN/kubeaudit all --format json -f "$f" >> results/tools/kubeaudit_helm.jsonl 2>> results/tools/kubeaudit_helm.err
done
echo "lines=$(wc -l < results/tools/kubeaudit_helm.jsonl) bytes=$(wc -c < results/tools/kubeaudit_helm.jsonl)"

echo "== checkov =="
.venv-checkov/bin/checkov -d corpus/helm --framework kubernetes -o json --quiet \
  --output-file-path results/tools/ > results/tools/checkov_helm.out 2>&1
echo "exit=$? files=$(ls results/tools/ | grep -c checkov)"
echo done
