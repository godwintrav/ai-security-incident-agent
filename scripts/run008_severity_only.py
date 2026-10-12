#!/usr/bin/env python3
"""Severity-only ablation for Run 008. Requires torch, transformers, peft, bitsandbytes."""
import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

SEVERITIES = ('low', 'medium', 'high', 'critical')
DEFAULT_ADAPTER = 'godwintrav/ai-security-incident-analyzer-2026-10-12_15.22.45'
SYSTEM_PROMPT = '''You are a security incident severity classifier. Assess severity using only the supplied incident description, evidence, security knowledge, playbook and CVE results. Do not assume compromise or impact without supporting evidence. Distinguish suspicious activity from confirmed compromise and consider scope, impact, affected asset criticality, and containment. Return exactly one JSON object with exactly one field: {"severity":"low|medium|high|critical"}. Do not output findings, IOCs, explanations, markdown, or other fields.'''


def load_jsonl(path):
    with open(path, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def extract_severity(raw):
    raw = raw.strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and set(obj) == {'severity'} and obj['severity'] in SEVERITIES:
            return obj['severity'], None
        return None, 'Not a JSON object with exactly one valid severity field'
    except json.JSONDecodeError as exc:
        return None, str(exc)


def matrix(rows, field):
    return {expected: {predicted: sum(r['expected_severity'] == expected and r[field] == predicted for r in rows)
                       for predicted in (*SEVERITIES, 'invalid')}
            for expected in SEVERITIES}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--regression', required=True, help='Original 104-case regression JSONL')
    ap.add_argument('--full-predictions', required=True, help='Run 008 predictions JSONL')
    ap.add_argument('--adapter', default=DEFAULT_ADAPTER)
    ap.add_argument('--base', default='Qwen/Qwen3.5-9B')
    ap.add_argument('--out', default='run008_severity_only_results')
    ap.add_argument('--max-new-tokens', type=int, default=64)
    ap.add_argument('--limit', type=int, default=0, help='Optional smoke-test case limit')
    args = ap.parse_args()

    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel

    cases = load_jsonl(args.regression)
    full = load_jsonl(args.full_predictions)
    if args.limit:
        cases = cases[:args.limit]
    full_by_id = {r['case_id']: r for r in full}
    assert len(full_by_id) == len(full), 'Duplicate case IDs in full predictions'
    assert len({r['case_id'] for r in cases}) == len(cases), 'Duplicate case IDs in regression'
    if not args.limit:
        assert len(cases) == 104, f'Expected 104 cases; found {len(cases)}'
        assert set(full_by_id) == {r['case_id'] for r in cases}, 'Full and regression case IDs differ'

    tokenizer = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                               bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    base = AutoModelForCausalLM.from_pretrained(
        args.base, quantization_config=quant, device_map='auto',
        torch_dtype=torch.bfloat16, trust_remote_code=True)
    model = PeftModel.from_pretrained(base, args.adapter)
    model.eval()
    device = model.get_input_embeddings().weight.device

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for idx, case in enumerate(cases, 1):
        cid = case['case_id']
        expected = case['expected']['severity']
        old = full_by_id[cid]
        old_pred = old.get('prediction') or {}
        full_severity = old_pred.get('severity')
        if full_severity not in SEVERITIES:
            full_severity = 'invalid'
        # IMPORTANT: send only case['input']; never leak case['expected'] to the model.
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': json.dumps(case['input'], ensure_ascii=False)},
        ]
        inputs = tokenizer.apply_chat_template(
            messages, tokenize=True, add_generation_prompt=True,
            enable_thinking=False, return_tensors='pt')
        inputs = inputs.to(device)
        with torch.inference_mode():
            output = model.generate(
                **inputs,
                max_new_tokens=128,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        raw = tokenizer.decode(output[0, inputs.shape[-1]:], skip_special_tokens=True).strip()
        severity, error = extract_severity(raw)
        row = {
            'case_id': cid, 'expected_severity': expected,
            'full_severity': full_severity,
            'severity_only': severity or 'invalid',
            'full_correct': full_severity == expected,
            'severity_only_correct': severity == expected,
            'raw_response': raw, 'parse_error': error,
        }
        results.append(row)
        print(f'[{idx}/{len(cases)}] {cid}: expected={expected} full={full_severity} only={severity or "invalid"}', flush=True)
        with (out / 'per_case.jsonl').open('w', encoding='utf-8') as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')

    n = len(results)
    full_correct = sum(r['full_correct'] for r in results)
    only_correct = sum(r['severity_only_correct'] for r in results)
    fixed = [r['case_id'] for r in results if not r['full_correct'] and r['severity_only_correct']]
    worsened = [r['case_id'] for r in results if r['full_correct'] and not r['severity_only_correct']]
    summary = {
        'adapter': args.adapter, 'cases': n,
        'full_accuracy': full_correct / n,
        'severity_only_accuracy': only_correct / n,
        'accuracy_change_percentage_points': 100 * (only_correct - full_correct) / n,
        'severity_only_valid_json_rate': sum(r['severity_only'] != 'invalid' for r in results) / n,
        'full_confusion_matrix': matrix(results, 'full_severity'),
        'severity_only_confusion_matrix': matrix(results, 'severity_only'),
        'fixed_count': len(fixed), 'worsened_count': len(worsened),
        'fixed_case_ids': fixed, 'worsened_case_ids': worsened,
        'severity_only_prediction_counts': dict(Counter(r['severity_only'] for r in results)),
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    with (out / 'comparison.csv').open('w', newline='', encoding='utf-8') as f:
        fields = ['case_id', 'expected_severity', 'full_severity', 'severity_only',
                  'full_correct', 'severity_only_correct', 'raw_response', 'parse_error']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    print('\n' + json.dumps(summary, indent=2))
    print(f'\nSaved outputs in {out.resolve()}')

if __name__ == '__main__':
    main()
