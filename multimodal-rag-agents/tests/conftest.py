"""Pytest configuration and fixtures."""

import pytest
import sys
import os
from datetime import datetime, timezone

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from rag_agents.models.rag_models import DocumentCandidate


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "mock: mark test as using mocked services"
    )


@pytest.fixture
def sample_documents():
    """Sample document candidates for testing."""
    return [
        DocumentCandidate(
            doc_id="doc_1",
            file_path="/path/to/doc1.pdf",
            page_num=1,
            doc_source="doc1.pdf",
            markdown_text="This document covers the basics of multimodal RAG systems, including text and visual processing.",
            similarity_score=0.92,
            visual_content_type="text_with_diagrams"
        ),
        DocumentCandidate(
            doc_id="doc_2",
            file_path="/path/to/doc2.pdf",
            page_num=5,
            doc_source="doc2.pdf",
            markdown_text="Advanced techniques for document retrieval and ranking in vector databases.",
            similarity_score=0.88,
            visual_content_type="text_only"
        ),
        DocumentCandidate(
            doc_id="doc_3",
            file_path="/path/to/doc3.pdf",
            page_num=12,
            doc_source="doc3.pdf",
            markdown_text="Visual processing in RAG systems requires specialized encoders that can handle images, diagrams, and charts. Integration with text processing creates powerful multimodal capabilities.",
            similarity_score=0.84,
            visual_content_type="text_with_images"
        )
    ]


@pytest.fixture
def mock_datetime():
    """Mock datetime for consistent testing."""
    return datetime.now(timezone.utc)