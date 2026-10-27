"""
web/schemas.py — Farad Ai Benchmark: Pydantic v2 OpenAPI API Contracts

This module defines type-safe request and response schemas for FastAPI REST API routes.
Prevents contract drift between the backend and external consumers / UI layers.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Datasets & Models ────────────────────────────────────────────────────────

class DatasetItem(BaseModel):
    """Metadata describing an available Parquet benchmark dataset."""
    id: str = Field(..., description="Unique dataset identifier or slug")
    name: str = Field(..., description="Display name of the dataset (e.g. master_benchmark)")
    filename: str = Field("", description="File name of the Parquet dataset")
    path: str = Field(..., description="Absolute or relative file path on server")
    rows: int = Field(0, description="Total number of standardized test cases")
    cases: int = Field(0, description="Total number of standardized test cases")
    static_rows: int = Field(0, description="Count of STATIC_CAPABLE cases")
    semantic_rows: int = Field(0, description="Count of SEMANTIC_REQUIRED cases")
    size_kb: float = Field(0.0, description="File size on disk in kilobytes")
    size_mb: float = Field(0.0, description="File size on disk in megabytes")
    description: str = Field("", description="Summary of covered threat domains")
    source: str = Field("Parquet", description="Storage format or origin")
    is_core: bool = Field(False, description="Whether this is a primary benchmark suite (Smoke, Train, Master)")
    category: str = Field("domain", description="Dataset grouping: 'core' for benchmark suites, 'domain' for threat slices")


class ModelItem(BaseModel):
    """Registered security evaluation model adapter."""
    id: str = Field(..., description="Model identifier key (e.g. laya-mlx, qwen3guard)")
    name: str = Field(..., description="Human-readable display name")
    backend: str = Field("MLX", description="Execution runtime (MLX, PyTorch, Heuristic)")
    description: str = Field("", description="Model capabilities and intended scope")
    icon: str = Field("🛡️", description="UI display emoji/icon")
    status: str = Field("available", description="Model availability status")
    quantization: str = Field("4-bit", description="Quantization profile (4-bit, fp16)")
    loaded: bool = Field(False, description="Whether weights are currently resident in memory")


# ─── Experiment Templates & Matrix Studio ─────────────────────────────────────

class ExperimentModelConfig(BaseModel):
    """Configuration for an individual model within an experiment template."""
    model_id: str = Field(..., description="Registered model adapter key (e.g. laya-mlx, ollama-d1)")
    runtime_tier: Optional[str] = Field(None, description="Explicit runtime tier: MLX_NATIVE_METAL, OLLAMA_DAEMON_HTTP, PYTORCH_MPS, STATIC_RULE_ENGINE")
    enable_l1_cascade: bool = Field(False, description="Enable L1 static regex cascade filter")
    threat_threshold: Optional[float] = Field(None, description="Continuous probability threshold (MLX only)")
    exploit_threshold: Optional[float] = Field(None, description="Exploit confidence threshold")
    misalignment_threshold: Optional[float] = Field(None, description="Misalignment confidence threshold")


class ExperimentTemplateItem(BaseModel):
    """Declarative experiment matrix template stored in DuckDB."""
    template_id: str = Field(..., description="Unique template identifier (slug)")
    name: str = Field(..., description="Human-readable template name")
    description: str = Field("", description="Detailed description of the benchmark matrix")
    dataset_path: str = Field(..., description="Parquet dataset path or filename")
    models_config: List[Dict[str, Any]] = Field(..., description="List of model evaluation specifications")
    limit_cases: Optional[int] = Field(None, description="Maximum test cases to evaluate")
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    updated_at: Optional[str] = Field(None, description="Last update timestamp")


class ExperimentTemplateCreateRequest(BaseModel):
    """Request payload to create or update an experiment template."""
    template_id: str = Field(..., description="Unique slug for the experiment template")
    name: str = Field(..., description="Human-readable template name")
    description: Optional[str] = Field("", description="Detailed description")
    dataset_path: str = Field(..., description="Parquet dataset path or relative filename")
    models_config: List[Dict[str, Any]] = Field(..., description="List of model evaluation specifications")
    limit_cases: Optional[int] = Field(None, description="Optional case limit")


class ExperimentRunRequest(BaseModel):
    """Request payload to trigger execution of an experiment matrix template."""
    limit_cases: Optional[int] = Field(None, description="Optional override for limit_cases")
    selected_models: Optional[List[str]] = Field(None, description="Optional subset of model_ids to run")


class ExperimentRunResponse(BaseModel):
    """Response returned upon launching an experiment matrix run."""
    template_id: str
    status: str = "started"
    models_count: int
    message: str = "Experiment matrix execution started in background"



# ─── Benchmark Runs ───────────────────────────────────────────────────────────

class RunCreateRequest(BaseModel):
    """Payload to trigger a new benchmark evaluation run."""
    dataset_path: str = Field(..., description="Target Parquet file path")
    model_name: str = Field("mock", description="Registered model adapter identifier")
    dataset_name: str = Field("unknown", description="Display label for the dataset")
    enable_l1: bool | str = Field(True, description="Enable L1 static regex cascade filter")
    tier_filter: str = Field("all", description="Scope filter: all | static | semantic")


class RunCreateResponse(BaseModel):
    """Response returned upon successfully queuing a benchmark run."""
    run_id: str = Field(..., description="Unique generated run identifier")
    status: str = Field("started", description="Execution status")


class RunSummary(BaseModel):
    """Historical summary record for a completed or active benchmark run."""
    run_id: str = Field(..., description="Unique run identifier")
    dataset_name: str = Field(..., description="Evaluated dataset display label")
    model_name: str = Field(..., description="Evaluated model adapter and configuration")
    status: str = Field(..., description="Execution status: pending | running | completed | error")
    total_cases: int = Field(0, description="Total planned test cases")
    accuracy: float = Field(0.0, description="Overall accuracy percentage (%)")
    precision: float = Field(0.0, description="Precision metric percentage (%)")
    recall: float = Field(0.0, description="Recall metric percentage (%)")
    f1: float = Field(0.0, description="F1-score percentage (%)")
    fpr: float = Field(0.0, description="False Positive Rate percentage (%)")
    avg_latency_ms: float = Field(0.0, description="Mean inference latency in milliseconds")
    p95_latency_ms: float = Field(0.0, description="95th percentile latency in milliseconds")
    duration_secs: float = Field(0.0, description="Total elapsed benchmark duration in seconds")
    tp: int = Field(0, description="True Positive count")
    tn: int = Field(0, description="True Negative count")
    fp: int = Field(0, description="False Positive count")
    fn: int = Field(0, description="False Negative count")
    started_at: Optional[Any] = Field(None, description="Start timestamp")
    completed_at: Optional[Any] = Field(None, description="Completion timestamp")


class RunEvaluationItem(BaseModel):
    """Granular evaluation record for a single test case within a run."""
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
    """Detailed benchmark run breakdown including per-category stats."""
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
    """Confirmation payload returned upon deleting a run."""
    deleted: str


# ─── Discrepancy & Comparison ─────────────────────────────────────────────────

class CompareRunsResponse(BaseModel):
    """Cross-model discrepancy matrix comparing two benchmark runs."""
    run_a: Dict[str, Any]
    run_b: Dict[str, Any]
    total_shared_cases: int
    agreement_count: int
    discrepancy_count: int
    agreement_rate: float
    discrepancies: List[Dict[str, Any]] = Field(default_factory=list)


# ─── Test Cases Explorer ──────────────────────────────────────────────────────

class CategoryCountItem(BaseModel):
    """Category filter item with aggregate case count."""
    name: str = Field(..., description="Category label")
    count: int = Field(..., description="Total case count in category")


class TestCaseFiltersResponse(BaseModel):
    """Available filter dimensions and distributions for the test case pool."""
    total_pool_cases: int = Field(..., description="Total cases in the pool")
    datasets: List[CategoryCountItem]
    threat_domains: List[CategoryCountItem]
    analysis_tiers: List[CategoryCountItem]


class TestCasePagination(BaseModel):
    """Pagination metadata for test case queries."""
    page: int
    limit: int
    total_records: int
    total_pages: int
    has_next: bool
    has_prev: bool


class TestCaseItem(BaseModel):
    """Standardized benchmark test case entity."""
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
    """Paginated list of benchmark test cases."""
    cases: List[TestCaseItem]
    pagination: TestCasePagination
