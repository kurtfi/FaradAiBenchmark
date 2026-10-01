# ISSUE-002: Bildirimsel L1 Statik Kural Motoru ve Bağımsız Benchmark Adaptörü

## Parent
[SPEC-0002: Hibrit Güvenlik Motoru (L1/L2) ve Büyük Ölçekli Karşılaştırmalı Benchmark Platformu](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md)

## What to build
`rules/` dizini altında bildirimsel YAML formatında (`dlp_secrets.yaml`, `command_injection.yaml`, `path_traversal.yaml`, `sqli.yaml`) kural setleri oluşturmak. Uygulama başlangıcında tüm kuralları hafızada önceden derleyerek (`re.compile`) mikrosaniye düzeyinde (<0.2ms) denetim yapan yüksek başarımlı bir `L1RuleEngine` sınıfı geliştirmek.

Bu motoru `benchmark_runner.py` içinde `L1StaticAdapter` olarak tescil etmek ve Web UI model açılır listesine `l1-rules` seçeneğini eklemek.

```yaml
# Rule Structure Reference (ADR 0005)
version: "1.0"
category: "DLP_SECRETS"
rules:
  - id: "DLP-OPENAI-KEY"
    name: "OpenAI Secret Key Leakage"
    threat_domain: "DATA_LEAK"
    cwe: "CWE-532"
    severity: "HIGH"
    regex: "(?:sk-proj-|sk-live-|sk-)[a-zA-Z0-9_-]{20,}"
    description: "Detects exposed OpenAI API secret keys."
```

## Acceptance criteria
- [ ] `rules/` dizini altında en az 4 kural paketi (`dlp_secrets.yaml`, `command_injection.yaml`, `path_traversal.yaml`, `sqli.yaml`) eksiksiz tanımlanmıştır.
- [ ] `L1RuleEngine` sınıfı kuralları diskten okuyup derler ve `inspect(tool_name, tool_arguments, context)` çağrısını ortalama `<0.2ms` sürede tamamlar.
- [ ] `benchmark_runner.py` içine `L1StaticAdapter` eklenmiş ve CLI üzerinden `--model l1-rules` ile çalıştırılabilir durumdadır.
- [ ] Web dashboard model listesinde `L1 Static Rules` seçeneği listelenir ve canlı websocket akışında çalıştırılabilir.
- [ ] `smoke_test_2k` üzerinde çalıştırıldığında klasik syntax ve secret vakalarını yüksek doğrulukla yakalar.

## Blocked by
- [ISSUE-001: Analysis Tier Şeması ve Gerçek DLP/Gizlilik Veri Normalizasyonu](./ISSUE-001-analysis-tier-schema-and-dataset-normalization.md)
