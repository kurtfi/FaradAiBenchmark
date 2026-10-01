# ADR 0003: L1/L2 Hibrit Denetimde Kademeli Fail-Fast (Kademeli Filtreleme) Mimarisi

* **Tarih:** 2026-10-02
* **Durum:** Kabul Edildi (Accepted)
* **Kapsam:** Faraday Guard / İki Kademeli Hibrit Denetim Motoru

---

## 1. Bağlam ve Problem Tanımı (Context)
LLM ve MCP arasındaki araç çağrılarında (tool call) güvenlik denetimi iki farklı maliyet ve yetenek sınıfına sahiptir:
1. **L1 (Statik Kurallar & DLP):** CPU üzerinde çalışan, mikrosaniye seviyesinde gecikme üreten (<1ms) deterministik desen eşleme ve imza kontrolleri.
2. **L2 (Semantik / Laya MLX):** Apple Silicon GPU / NPU üzerinde çalışan, doğal dil ve bağlam analizi yapan milisaniye seviyesinde gecikme üreten (~15-40ms) küçük dil modelleri (SLM).

Tüm çağrıları doğrudan L2'ye göndermek gereksiz gecikmeye ve GPU darboğazına yol açar. Öte yandan yalnızca L1 kullanmak dolaylı prompt enjeksiyonu ve bağlamsal ajan manipülasyonlarını kaçırır.

---

## 2. Alınan Kararlar ve Gerekçeleri (Decision Log)

### Karar: Kademeli Fail-Fast (L1 ➔ L2) Modeli
* **Karar:** Hibrit güvenlik mimarisinde "Fail-Fast Cascade" deseni uygulanacaktır:
  1. Gelen `tool_name`, `tool_arguments` ve `context` önce L1 motoruna iletilir.
  2. L1 kural eşleşmesi bulur ve `BLOCKED` kararı verirse işlem anında sonlandırılır. L2 (Laya MLX) çağrılmaz; gecikme <0.2ms düzeyinde tutulur.
  3. L1 `ALLOWED` (temiz) veya şüphesiz geçerse, girdi L2'ye (Laya MLX) iletilir. L2 bağlamsal niyet analizi yaparak nihai kararı üretir.
* **Alternatifler:**
  - *Seçenek 2 (Çift / Paralel Koşum):* Her iki motoru her istek için paralel çalıştırmak (reddedildi: bariz saldırılarda dahi gereksiz GPU yükü ve maksimum gecikme yaratır).
  - *Seçenek 3 (Ensemble Skorlama):* İki motorun ürettiği olasılık puanlarını ağırlıklandırmak (reddedildi: deterministik bir ihlalin olasılık ile hafifletilmesi güvenlik açığı doğurabilir).
* **Gerekçe:**
  - **Maksimum Performans & Kaynak Tasarrufu:** Bilinen atakların ve doğrudan sızıntıların %80+'si mikrosaniyede elenir.
  - **Objektif Ölçülebilirlik:** Benchmark testlerinde L1'in offload oranı (GPU'ya gitmeden çözülen vaka sayısı) ve toplam gecikme kazancı net olarak raporlanır.

---

## 3. Sonuçlar (Consequences)
* Model adaptör havuzuna `HybridGuardAdapter` eklenecek ve hem L1 hem L2'yi orkestre edecektir.
* Benchmark raporlarında her vaka için `decided_by: L1 | L2` bilgisi tutulacaktır.
