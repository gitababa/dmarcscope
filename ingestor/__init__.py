"""DMARCscope ingest worker.

Fetches DMARC aggregate reports (from an IMAP mailbox, or from files), parses
them with parsedmarc, and stores normalized rows in PostgreSQL for the
dashboard.

    python -m ingestor run              # scheduled job: mailbox -> database
    python -m ingestor import PATH...   # load report files (.xml, .gz, .zip, .eml)
    python -m ingestor enrich           # reverse-DNS backfill only
"""

__version__ = "2.0.0"
