#!/usr/bin/env python3
"""Download Hugging Face source samples for manual/LLM-assisted incident labeling.

This script intentionally DOES NOT invent IncidentAnalysis labels. The raw samples
must be grouped by genuine incident identity, labeled, and reviewed before SFT.

Usage:
  pip install datasets huggingface_hub
  python hf_security_curation.py --output hf_source_samples.jsonl --limit 2000
"""
import argparse, json, hashlib, sys
from pathlib import Path

SOURCES = [
    ("witfoo/precinct6-cybersecurity", "attack_reports", "train"),
    ("witfoo/precinct6-cybersecurity", "incident_signals", "train"),
    ("SIABench/SIA_Dataset", "alert_triaging_tii", "tp"),
    ("SIABench/SIA_Dataset", "alert_triaging_tii", "fp"),
    ("SIABench/SIA_Dataset", "sia_dataset", "train"),
    ("bvsam/cic-ids-2017", "machine_learning", "train"),
]

def safe(v):
    if isinstance(v, dict): return {str(k): safe(x) for k,x in v.items()}
    if isinstance(v, (list,tuple)): return [safe(x) for x in v]
    if hasattr(v, 'isoformat'): return v.isoformat()
    if isinstance(v,(str,int,float,bool)) or v is None: return v
    return str(v)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default='hf_source_samples.jsonl');p.add_argument('--limit',type=int,default=2000)
    args=p.parse_args()
    from datasets import load_dataset
    # Source quotas emphasize incident-level material, not individual flows.
    quotas=[int(args.limit*.40),int(args.limit*.25),int(args.limit*.08),int(args.limit*.07),int(args.limit*.05)]
    quotas.append(args.limit-sum(quotas))
    written=0
    with Path(args.output).open('w') as out:
        for (repo,config,split),quota in zip(SOURCES,quotas):
            try:
                ds=load_dataset(repo,config,split=split,streaming=True)
                count=0
                for row in ds:
                    row=safe(row)
                    # These are source records, not labeled training examples.
                    raw=json.dumps(row,ensure_ascii=False,sort_keys=True)
                    record={'source_repo':repo,'source_config':config,'source_split':split,
                            'source_record_sha256':hashlib.sha256(raw.encode()).hexdigest(),
                            'record':row,'label_status':'UNREVIEWED'}
                    out.write(json.dumps(record,ensure_ascii=False)+'\n')
                    count+=1;written+=1
                    if count>=quota:break
                print(f'{repo}/{config}: {count} records',file=sys.stderr)
            except Exception as e:
                print(f'FAILED {repo}/{config}/{split}: {e}',file=sys.stderr)
    print(f'Exported {written} source records to {args.output}. NOT fine-tuning-ready.')
    if written!=args.limit:sys.exit(2)
if __name__=='__main__':main()
