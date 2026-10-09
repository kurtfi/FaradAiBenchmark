"""
web/schemas.py — Faraday Laya Guard: Pydantic v2 OpenAPI API Sözleşmeleri

Bu modül, FastAPI REST API rotaları için tip güvenli istek ve yanıt şemalarını tanımlar.
OpenAPI / Swagger şemasındaki drift'i önler ve istemciler için standart veri sözleşmesi sunar.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Datasets & Models ────────────────────────────────────────────────────────

class DatasetItem(BaseModel):
    """Kullanılabilir Parquet benchmark veri seti üstverisi."""
    name: str = Field(..., description="Veri seti görünen adı (örn: master_benchmark)")
    path: str = Field(..., description="Parquet dosyasının sunucu üzerindeki yolu")
    cases: int = Field(..., description="Veri setindeki toplam test senaryosu sayısı")
    size_mb: float = Field(..., description="Dosya boyutu (MB)")
    description: str = Field(..., description="Kapsanan güvenlik tehdit alanları özeti")
    source: str = Field("Parquet", description="Veri formatı / kaynağı")


class ModelItem(BaseModel):
    """Güvenlik değerlendirme adapter veya modeli."""
    id: str = Field(..., description="Model tanımlayıcısı (örn: laya-mlx, qwen-coder)")
    name: str = Field(..., description="Arayüzde gösterilen ad")
    backend: str = Field(..., description="Çalışma zamanı altyapısı (MLX, PyTorch, Heuristic)")
    description: str = Field(..., description="Modelin yetenek ve kullanım amacı")
    quantization: str = Field(..., description="Kuantizasyon tipi (4-bit, fp16)")
    loaded: bool = Field(False, description="Model ağırlıkları belleğe yüklü mü?")


# ─── Benchmark Runs ───────────────────────────────────────────────────────────

class RunCreateRequest(BaseModel):
    """Yeni benchmark başlatma isteği."""
    dataset_path: str = Field(..., description="Hedef Parquet dosyasının yolu")
    model_name: str = Field("mock", description="Kullanılacak model adapter adı")
    dataset_name: str = Field("unknown", description="Görüntüleme için veri seti etiketi")
    enable_l1: bool | str = Field(True, description="L1 statik regex cascade devrede mi?")
    tier_filter: str = Field("all", description="Filtreleme kapsamı: all | static | semantic")


class RunCreateResponse(BaseModel):
    """Başlatılan benchmark yanıtı."""
    run_id: str = Field(..., description="Üretilen tekil koşu kimliği")
    status: str = Field("started", description="Koşu durumu")


class RunSummary(BaseModel):
    """Koşu geçmişi özet satırı."""
    run_id: str = Field(..., description="Koşu tekil kimliği")
    dataset_name: str = Field(..., description="Değerlendirilen veri seti")
    model_name: str = Field(..., description="Kullanılan model ve konfigürasyon")
    status: str = Field(..., description="Koşu durumu: pending | running | completed | error")
    total_cases: int = Field(0, description="Toplam test senaryosu")
    accuracy: float = Field(0.0, description="Genel doğruluk oranı (%)")
    precision: float = Field(0.0, description="Hassasiyet (Precision) (%)")
    recall: float = Field(0.0, description="Duyarlılık (Recall) (%)")
    f1: float = Field(0.0, description="F1 skoru (%)")
    fpr: float = Field(0.0, description="Yanlış Pozitif Oranı (False Positive Rate) (%)")
    avg_latency_ms: float = Field(0.0, description="Ortalama gecikme (ms)")
    p95_latency_ms: float = Field(0.0, description="95. persentil gecikme (ms)")
    duration_secs: float = Field(0.0, description="Toplam koşu süresi (saniye)")
    tp: int = Field(0, description="True Positive sayısı")
    tn: int = Field(0, description="True Negative sayısı")
    fp: int = Field(0, description="False Positive sayısı")
    fn: int = Field(0, description="False Negative sayısı")
    started_at: Optional[Any] = Field(None, description="Başlangıç zamanı")
    completed_at: Optional[Any] = Field(None, description="Bitiş zamanı")


class RunEvaluationItem(BaseModel):
    """Tekil bir test senaryosunun değerlendirme kaydı."""
    case_id: str
    source: Optional[str] = ""
    domain: str
    analysis_tier: str
    cwe: Optional[str] = ""
    tool_name: Optional[str] = ""
    is_malicious: bool
    predicted_blocked: bool
    correct: bool
    decided_by: str
    confidence: float = 0.0
    latency_ms: float = 0.0
    offload_saved_ms: float = 0.0
    verdict_detail: Optional[str] = ""
    tool_arguments: Optional[str] = ""
    context: Optional[str] = ""


class RunDetailResponse(BaseModel):
    """Belirli bir benchmark koşusunun detaylı analizi."""
    run_id: str
    dataset_name: str
    model_name: str
    status: str
    total_cases: int
    evaluated: int
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float
    precision_val: float
    recall_val: float
    f1_score: float
    fpr: float
    avg_latency_ms: float
    p95_latency_ms: float
    duration_secs: float
    started_at: Optional[Any] = None
    completed_at: Optional[Any] = None
    category_stats: Dict[str, Any] = Field(default_factory=dict)
    evaluations: List[RunEvaluationItem] = Field(default_factory=list)


class DeleteRunResponse(BaseModel):
    """Koşu silme yanıtı."""
    deleted: str



# ─── Discrepancy & Comparison ─────────────────────────────────────────────────

class CompareRunsResponse(BaseModel):
    """İki model veya koşu arasındaki uyuşmazlık (discrepancy) matrisi."""
    run_a: Dict[str, Any]
    run_b: Dict[str, Any]
    total_shared_cases: int
    agreement_count: int
    discrepancy_count: int
    agreement_rate: float
    discrepancies: List[Dict[str, Any]] = Field(default_factory=list)


# ─── Test Cases Explorer ──────────────────────────────────────────────────────

class CategoryCountItem(BaseModel):
    """Filtreleme kategorisi ve vaka sayısı."""
    name: str = Field(..., description="Kategori adı")
    count: int = Field(..., description="Bu kategorideki vaka sayısı")


class TestCaseFiltersResponse(BaseModel):
    """Test vakaları havuzu için mevcut filtreler."""
    total_pool_cases: int = Field(..., description="Havuzdaki toplam vaka sayısı")
    datasets: List[CategoryCountItem]
    threat_domains: List[CategoryCountItem]
    analysis_tiers: List[CategoryCountItem]


class TestCasePagination(BaseModel):
    """Sayfalama üstverisi."""
    page: int
    limit: int
    total_records: int
    total_pages: int
    has_next: bool
    has_prev: bool


class TestCaseItem(BaseModel):
    """Test vakası veri modeli."""
    model_config = {"extra": "allow"}

    id: str
    source_dataset: str
    threat_domain: str
    analysis_tier: str
    is_malicious: bool
    cwe: Optional[str] = None
    owasp_llm: Optional[str] = None
    traffic_direction: Optional[str] = None
    tool_name: Optional[str] = None
    tool_arguments: Optional[str] = None
    context: Optional[str] = None



class TestCasesListResponse(BaseModel):
    """Sayfalanmış test vakaları yanıtı."""
    cases: List[TestCaseItem]
    pagination: TestCasePagination
