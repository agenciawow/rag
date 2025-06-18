"""Tests for multimodal retriever agent."""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from rag_agents.agents.retriever import (
    MultimodalRetrieverAgent, RetrieverConfig
)
from rag_agents.agents.base import AgentContext, AgentState
from rag_agents.models.rag_models import DocumentCandidate


class TestRetrieverConfig:
    """Test RetrieverConfig model."""

    def test_default_config(self):
        """Test default configuration values."""
        # Clear environment variables that might interfere
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            config = RetrieverConfig()

            assert config.max_candidates == 20
            assert config.collection_name == "pdf_documents"
            assert config.embedding_model == "voyage-multimodal-3"
            assert config.voyage_api_key is None  # No env var set
            assert config.astra_endpoint is None  # No env var set
            assert config.astra_token is None  # No env var set

    def test_custom_config(self):
        """Test custom configuration values."""
        # Clear environment variables that might interfere
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            config = RetrieverConfig(
                max_candidates=10,
                collection_name="custom_docs",
                voyage_api_key="test_key",
                astra_endpoint="test_endpoint",
                astra_token="test_token",
                embedding_model="voyage-multimodal-2"
            )

            assert config.max_candidates == 10
            assert config.collection_name == "custom_docs"
            assert config.voyage_api_key == "test_key"
            assert config.astra_endpoint == "test_endpoint"
            assert config.astra_token == "test_token"
            assert config.embedding_model == "voyage-multimodal-2"


class TestMultimodalRetrieverAgent:
    """Test MultimodalRetrieverAgent functionality."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        # Clear environment variables that might interfere
        return RetrieverConfig(
            max_candidates=5,
            voyage_api_key="test_voyage_key",
            astra_endpoint="https://test-endpoint.datastax.com", 
            astra_token="test_token",
            collection_name="test_documents"
        )

    @pytest.fixture
    def mock_context(self):
        """Create test context."""
        return AgentContext(
            query="What are the main components of the Zep architecture?",
            objective="Understand Zep system architecture",
            constraints=["Focus on technical details"]
        )

    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    def test_agent_initialization(self, mock_astra, mock_voyage, config):
        """Test agent initialization with config."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find.return_value = []

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")

        assert agent.name == "TestRetriever"
        assert agent.config == config
        assert agent.state == AgentState.IDLE
        assert hasattr(agent, 'voyage_client')
        assert hasattr(agent, 'collection')

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_plan_creation(self, mock_astra, mock_voyage, config, mock_context):
        """Test planning phase."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find.return_value = []

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")

        plan = await agent.plan(mock_context)

        assert hasattr(plan, 'text_queries')
        assert hasattr(plan, 'visual_concepts')
        assert hasattr(plan, 'retrieval_params')
        assert mock_context.query in plan.text_queries
        assert plan.retrieval_params["max_candidates"] == config.max_candidates

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_successful_retrieval(self, mock_astra, mock_voyage, config, mock_context):
        """Test successful document retrieval."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client

        # Mock embedding response
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3, 0.4, 0.5]]
        )

        # Mock Astra DB response
        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection

        # Mock the initial connection check
        mock_collection.find.return_value = []

        # Mock search results with correct format
        mock_documents = [
            {
                "_id": "doc1",
                "file_path": "zep_docs.pdf", 
                "page_num": 1,
                "doc_source": "zep_docs.pdf",
                "markdown_text": "Document about Zep architecture components",
                "$similarity": 0.85
            },
            {
                "_id": "doc2", 
                "file_path": "zep_tech.pdf",
                "page_num": 5,
                "doc_source": "zep_tech.pdf", 
                "markdown_text": "Technical details about Zep system design",
                "$similarity": 0.78
            }
        ]

        # Mock the search method to return documents
        mock_collection.find.side_effect = [[], mock_documents]  # First call for init, second for search

        # Create agent and run
        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
        result = await agent.run(mock_context)

        # Verify results
        assert result.status == AgentState.COMPLETED
        assert isinstance(result.output, list)
        assert len(result.output) == 2

        # Check first document
        doc1 = result.output[0]
        assert isinstance(doc1, DocumentCandidate)
        assert doc1.doc_id == "doc1"
        assert "Zep architecture" in doc1.markdown_text
        assert doc1.similarity_score == 0.85
        assert doc1.doc_source == "zep_docs.pdf"

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_no_documents_found(self, mock_astra, mock_voyage, config, mock_context):
        """Test behavior when no documents are found."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3]]
        )

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find.side_effect = [[], []]  # Init check and search

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
        result = await agent.run(mock_context)

        assert result.status == AgentState.COMPLETED
        assert isinstance(result.output, list)
        assert len(result.output) == 0

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_voyage_api_error(self, mock_astra, mock_voyage, config, mock_context):
        """Test handling of Voyage API errors."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.side_effect = Exception("Voyage API error")

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
        result = await agent.run(mock_context)

        # The agent should complete but with no results due to the API error
        assert result.status == AgentState.COMPLETED
        assert isinstance(result.output, list)
        assert len(result.output) == 0
        # Check that the error was logged in thinking
        thinking_text = " ".join(result.thinking)
        assert "Voyage API error" in thinking_text

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_astra_db_error(self, mock_astra, mock_voyage, config, mock_context):
        """Test handling of Astra DB errors."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3]]
        )

        # Make Astra DB raise exception
        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_astra_client.get_database.side_effect = Exception("Astra DB connection error")

        # The error should happen during initialization
        try:
            agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
            result = await agent.run(mock_context)
            # If we get here, something went wrong
            assert False, "Expected exception during initialization"
        except Exception as e:
            assert "Astra DB connection error" in str(e)

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_similarity_threshold_filtering(self, mock_astra, mock_voyage, mock_context):
        """Test document retrieval and sorting by similarity score."""
        config = RetrieverConfig(
            max_candidates=10,
            voyage_api_key="test_key",
            astra_endpoint="https://test-endpoint.datastax.com",
            astra_token="test_token"
        )

        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3]]
        )

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection

        # Mock documents with various similarity scores using correct format
        mock_documents = [
            {
                "_id": "doc1",
                "file_path": "high_relevance.pdf",
                "page_num": 1,
                "doc_source": "high_relevance.pdf",
                "markdown_text": "High relevance document",
                "$similarity": 0.9
            },
            {
                "_id": "doc2",
                "file_path": "low_relevance.pdf",
                "page_num": 1, 
                "doc_source": "low_relevance.pdf",
                "markdown_text": "Low relevance document",
                "$similarity": 0.7
            },
            {
                "_id": "doc3",
                "file_path": "medium_relevance.pdf",
                "page_num": 1,
                "doc_source": "medium_relevance.pdf", 
                "markdown_text": "Medium relevance document",
                "$similarity": 0.85
            }
        ]

        mock_collection.find.side_effect = [[], mock_documents]  # Init check and search

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
        result = await agent.run(mock_context)

        # Should return documents sorted by similarity score
        assert result.status == AgentState.COMPLETED
        assert len(result.output) == 3  # All documents
        # Check that documents are sorted by similarity (highest first)
        scores = [doc.similarity_score for doc in result.output]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_missing_configuration(self):
        """Test behavior with missing configuration."""
        # Clear environment to ensure missing keys
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            config = RetrieverConfig()  # Missing API keys
            context = AgentContext(
                query="test query",
                objective="test objective"
            )

            # This should fail during initialization due to missing API key
            try:
                agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")
                result = await agent.run(context)
                assert result.status == AgentState.FAILED
                assert "api" in result.error.lower() or "key" in result.error.lower()
            except ValueError as e:
                # This is expected - missing API key should raise ValueError
                assert "api key" in str(e).lower()

    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    def test_document_candidate_creation(self, mock_astra, mock_voyage, config):
        """Test DocumentCandidate creation and visual content type detection."""
        # Setup mocks
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find.return_value = []

        agent = MultimodalRetrieverAgent(config=config, name="TestRetriever")

        # Test visual content type detection
        assert agent._detect_visual_content_type("diagram_figure.pdf") == "diagram"
        assert agent._detect_visual_content_type("data_table.pdf") == "table"
        assert agent._detect_visual_content_type("sales_chart.pdf") == "chart"
        assert agent._detect_visual_content_type("regular_document.pdf") == "mixed"