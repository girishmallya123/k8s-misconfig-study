#!/usr/bin/env bash
# RQ3: run the four auditing tools over the Helm arm (identical input for all
# four: corpus/helm, 151 rendered multi-doc YAML files). Raw outputs land in
# results/tools/ for the normalizer to map onto our 24 rules.
set +e
cd "$(dirname "$0")/.."
mkdir -p results/tools
BIN=bin

echo "== kube-linter =="
$BIN/kube-linter lint corpus/helm --format json > results/tools/kubelinter_helm.json 2> results/tools/kubelinter_helm.err
echo "exit=$? bytes=$(wc -c < results/tools/kubelinter_helm.json)"

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
if [ -x .venv-checkov/bin/checkov ]; then
  .venv-checkov/bin/checkov -d corpus/helm --framework kubernetes -o json --quiet \
    --output-file-path results/tools/checkov_helm.json > results/tools/checkov_helm.out 2>&1
  echo "exit=$? bytes=$(wc -c < results/tools/checkov_helm.json 2>/dev/null)"
else
  echo "checkov venv missing"
fi
echo done
