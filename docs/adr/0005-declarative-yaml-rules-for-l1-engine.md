# ADR 0005: L1 Statik Denetim Motorunda Bildirimsel (Declarative) YAML Kural Mimarisi

* **Tarih:** 2026-10-02
* **Durum:** Kabul Edildi (Accepted)
* **Kapsam:** Faraday Guard / L1 Statik Kural Yönetimi

---

## 1. Bağlam ve Problem Tanımı (Context)
L1 Statik Denetim Motoru, LLM'den MCP tool'larına giden parametrelerdeki doğrudan saldırı imzalarını (Path Traversal, SQLi, Command Injection) ve DLP sızıntılarını (API anahtarları, token'lar, özel anahtarlar) mikrosaniye düzeyinde (<0.2ms) engellemekle yükümlüdür.

Bu kuralların Python kaynak koduna gömülü (hardcoded) olması:
- Yeni bir token kalıbı veya saldırı deseni eklendiğinde kod değişikliği ve yeniden dağıtım gerektirir.
- Kuralların modüler olarak açılıp kapatılmasını (kategori bazlı test) zorlaştırır.
- Kurumsal güvenlik politikalarının taşınabilirliğini engeller.

---

## 2. Alınan Kararlar ve Gerekçeleri (Decision Log)

### Karar: `rules/*.yaml` Formatında Bildirimsel Kural Seti
* **Karar:** Tüm statik kurallar `rules/` dizini altında alanlara göre ayrılmış YAML dosyalarında saklanacaktır:
  - `rules/dlp_secrets.yaml`: API anahtarları, JWT, AWS token, SSH anahtarları.
  - `rules/command_injection.yaml`: Tehlikeli komut zincirleri, pipe ve shell kaçışları.
  - `rules/path_traversal.yaml`: Dizin atlama ve hassas sistem dosyası kalıpları.
  - `rules/sqli.yaml`: Temel SQL injection ve boolean saldırı imzaları.
* **Derleme ve Çalıştırma:**
  - Uygulama / benchmark ayağa kalkarken tüm kurallar okunur ve Regex ifadeleri `re.compile` ile önbelleğe alınır.
  - Çalışma zamanında sıfır disk I/O ve sıfır dosya okuma maliyetiyle sadece bellek içi derlenmiş desenler eşleştirilir.
* **Alternatifler:**
  - *Seçenek 2 (In-Code Python Dictionary):* Reddedildi, sürümleme ve dinamik politika yönetimi eksik kalır.
  - *Seçenek 3 (YARA / Hyperscan C Kütüphaneleri):* Reddedildi, Apple Silicon ve Python dağıtımında gereksiz yerel C bağımlılığı doğurur.

---

## 3. Sonuçlar (Consequences)
* `rules/` dizini ve temel kural paketleri oluşturulacaktır.
* `L1RuleEngine` sınıfı bu YAML dosyalarını okuyup derleyecek ve `inspect(tool_name, tool_arguments)` metodunu sunacaktır.
* Benchmark sırasında istenen kural paketi bağımsız olarak test edilebilecektir.
