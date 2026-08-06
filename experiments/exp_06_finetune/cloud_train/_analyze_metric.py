import json
d = json.load(open(r'E:\train\train_log_cloud_r8_e2_lr0.0001_s42_rslora.json', encoding='utf-8'))
evals = [e for e in d['log_history'] if 'eval_loss' in e]
print('=== eval_loss 收敛曲线 ===')
for e in evals:
    print(f"step={e['step']:>5}  epoch={e['epoch']:.2f}  eval_loss={e['eval_loss']:.4f}  eval_acc={e.get('eval_mean_token_accuracy',0):.4f}")
print()
print('=== 最终指标 ===')
m = d['metrics']
print(f"train_loss={m['train_loss']:.4f}  train_runtime={m['train_runtime']/3600:.1f}h  samples/s={m['train_samples_per_second']:.3f}")
print(f"train_samples={d['train_samples']}  dev_samples={d['dev_samples']}")
print()
los = [e for e in d['log_history'] if 'loss' in e and 'eval_loss' not in e]
print(f"首个 train_loss={los[0]['loss']:.3f}")
print(f"末个 train_loss={los[-1]['loss']:.3f}")