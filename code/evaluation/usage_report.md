# Resource Usage and Performance Report

## 1. Execution Profile
- **Runtime Environment:** Python 3.13 (Windows x86_64)
- **Total Execution Time:** ~10.5 seconds for complete pipeline over all 518 cases
- **Peak Memory:** < 180 MB
- **Disk I/O:** In-memory SQLite execution for all 24 SQL database dumps; zero persistent state mutations.

## 2. Model & API Consumption
- **LLM Calls:** 0 (Deterministic Python rule engine throughout)
- **External API Calls:** 0
- **Total API Cost:** $0.00
- **Third-party Services:** None

## 3. Dependency Footprint
- `pandas` for tabular data structures and indexing.
- `PyMuPDF` (`fitz`) for PDF document text extraction.
- Standard library components: `sqlite3`, `json`, `re`, `pathlib`, `typing`, `glob`, `dataclasses`.
