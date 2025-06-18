"""Integration tests for the complete multimodal RAG system."""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import asyncio
import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from rag_agents.agents.lead_rag import LeadRAGAgent, LeadRAGConfig
from rag_agents.agents.retriever import MultimodalRetrieverAgent, RetrieverConfig
from rag_agents.agents.reranker import MultimodalRerankerAgent, RerankerConfig
from rag_agents.agents.context_analyzer import ContextAnalyzerAgent, ContextAnalyzerConfig
from rag_agents.agents.answer_generator import MultimodalAnswerAgent, AnswerGeneratorConfig
from rag_agents.agents.base import AgentContext, AgentState
from rag_agents.models.rag_models import (
    RAGResult, DocumentCandidate, RankedDocuments, RankingAnalysis,
    ContextAnalysis, StructuredAnswer
)


@pytest.mark.integration
class TestMultimodalRAGSystem:
    """Integration tests for the complete RAG system."""

    @pytest.fixture
    def mock_environment(self):
        """Mock environment with API keys."""
        return {
            "OPENAI_API_KEY": "test_openai_key",
            "VOYAGE_API_KEY": "test_voyage_key",
            "ASTRA_DB_API_ENDPOINT": "https://test.astra.datastax.com",
            "ASTRA_DB_APPLICATION_TOKEN": "AstraCS:test_token"
        }

    @pytest.fixture
    def agent_configs(self, mock_environment):
        """Create configurations for all agents."""
        return {
            'retriever': RetrieverConfig(
                max_candidates=5,
                voyage_api_key=mock_environment["VOYAGE_API_KEY"],
                astra_endpoint=mock_environment["ASTRA_DB_API_ENDPOINT"],
                astra_token=mock_environment["ASTRA_DB_APPLICATION_TOKEN"]
            ),
            'reranker': RerankerConfig(
                openai_api_key=mock_environment["OPENAI_API_KEY"]
            ),
            'context_analyzer': ContextAnalyzerConfig(
                openai_api_key=mock_environment["OPENAI_API_KEY"]
            ),
            'answer_generator': AnswerGeneratorConfig(
                openai_api_key=mock_environment["OPENAI_API_KEY"]
            ),
            'lead': LeadRAGConfig(
                openai_api_key=mock_environment["OPENAI_API_KEY"]
            )
        }

    @pytest.fixture
    def test_context(self):
        """Create test context for queries."""
        return AgentContext(
            query="What are the main components of the Zep architecture and how do they work together?",
            objective="Provide comprehensive overview of Zep system architecture including visual elements",
            constraints=[
                "Focus on technical details",
                "Include architectural diagrams if available",
                "Explain component interactions"
            ]
        )

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    @patch('rag_agents.agents.reranker.instructor.from_openai')
    @patch('rag_agents.agents.context_analyzer.instructor.from_openai')
    @patch('rag_agents.agents.answer_generator.instructor.from_openai')
    @patch('rag_agents.agents.lead_rag.instructor.from_openai')
    async def test_full_rag_pipeline_success(
        self, mock_lead_instructor, mock_answer_instructor, 
        mock_context_instructor, mock_rerank_instructor,
        mock_astra, mock_voyage, agent_configs, test_context
    ):
        """Test complete RAG pipeline with mocked external services."""

        # Mock Voyage AI embeddings
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3, 0.4, 0.5] * 200]  # 1000-dim embedding
        )

        # Mock Astra DB documents
        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection

        mock_documents = [
            {
                "_id": "zep_arch_001",
                "content": "Zep is a memory layer for AI assistants that provides long-term memory capabilities. The architecture consists of three main components: the Memory Store, Vector Store, and API Layer.",
                "metadata": {
                    "source": "zep_architecture.pdf",
                    "page": 1,
                    "section": "Architecture Overview",
                    "has_diagrams": True
                },
                "$similarity": 0.92
            },
            {
                "_id": "zep_arch_002",
                "content": "The Memory Store handles conversation history and user sessions. It integrates with the Vector Store for semantic search capabilities and provides real-time access to conversation context.",
                "metadata": {
                    "source": "zep_technical.pdf", 
                    "page": 15,
                    "section": "Memory Store Details",
                    "has_diagrams": False
                },
                "$similarity": 0.88
            },
            {
                "_id": "zep_arch_003",
                "content": "The Vector Store uses embeddings to enable semantic search across conversation history. It supports multiple embedding models and provides fast similarity search.",
                "metadata": {
                    "source": "zep_vector_guide.pdf",
                    "page": 8,
                    "section": "Vector Store Implementation", 
                    "has_diagrams": True
                },
                "$similarity": 0.85
            }
        ]

        mock_collection.find = AsyncMock(return_value=mock_documents)

        # Mock all LLM responses using Instructor

        # Lead agent decomposition
        from rag_agents.models.rag_models import RAGDecomposition, SearchStrategy, RankingCriterion
        mock_decomposition = RAGDecomposition(
            query_type="analytical",
            key_aspects=["memory_store", "vector_store", "api_layer", "component_integration"],
            search_strategies=[
                SearchStrategy(
                    primary_queries=["Zep architecture components", "memory layer design"],
                    fallback_queries=["Zep system overview", "AI memory architecture"],
                    content_filters=["technical", "architecture", "diagrams"],
                    max_candidates=5
                )
            ],
            ranking_criteria=[
                RankingCriterion(
                    aspect="technical_depth",
                    weight=0.4,
                    evaluation_method="content_analysis"
                ),
                RankingCriterion(
                    aspect="architectural_relevance", 
                    weight=0.3,
                    evaluation_method="semantic_similarity"
                ),
                RankingCriterion(
                    aspect="visual_content",
                    weight=0.3,
                    evaluation_method="metadata_analysis"
                )
            ],
            visual_requirements=["architecture_diagrams", "component_flows", "system_overview"],
            response_format="detailed"
        )

        mock_lead_client = Mock()
        mock_lead_instructor.return_value = mock_lead_client
        mock_lead_client.chat.completions.create = AsyncMock(return_value=mock_decomposition)

        # Reranker response
        mock_rerank_response = RankedDocuments(
            documents=[
                DocumentCandidate(
                    doc_id="zep_arch_001",
                    file_path=mock_documents[0]["metadata"]["source"],
                    page_num=mock_documents[0]["metadata"]["page"],
                    doc_source=mock_documents[0]["metadata"]["source"],
                    markdown_text=mock_documents[0]["content"],
                    similarity_score=0.92,
                    visual_content_type="diagram"
                ),
                DocumentCandidate(
                    doc_id="zep_arch_003",
                    file_path=mock_documents[2]["metadata"]["source"],
                    page_num=mock_documents[2]["metadata"]["page"],
                    doc_source=mock_documents[2]["metadata"]["source"],
                    markdown_text=mock_documents[2]["content"],
                    similarity_score=0.85,
                    visual_content_type="diagram"
                ),
                DocumentCandidate(
                    doc_id="zep_arch_002",
                    file_path=mock_documents[1]["metadata"]["source"],
                    page_num=mock_documents[1]["metadata"]["page"],
                    doc_source=mock_documents[1]["metadata"]["source"],
                    markdown_text=mock_documents[1]["content"],
                    similarity_score=0.88,
                    visual_content_type=None
                )
            ],
            ranking_analysis=RankingAnalysis(
                document_scores={"zep_arch_001": 0.92, "zep_arch_003": 0.85, "zep_arch_002": 0.88},
                ranking_rationale="Documents reranked by technical depth and visual content. Prioritized documents with architectural diagrams and comprehensive component explanations.",
                selected_documents=["zep_arch_001", "zep_arch_003", "zep_arch_002"],
                diversity_score=0.78
            ),
            total_candidates_processed=3,
            selection_strategy_used="technical_relevance_with_visual_priority"
        )

        mock_rerank_client = Mock()
        mock_rerank_instructor.return_value = mock_rerank_client
        mock_rerank_client.chat.completions.create = AsyncMock(return_value=mock_rerank_response)

        # Context analyzer response
        mock_context_analysis = ContextAnalysis(
            completeness_score=0.85,
            confidence_level="high",
            information_gaps=["performance_metrics", "scalability_details"],
            conflicting_sources=[],
            visual_coverage=0.67,
            recommended_action="proceed"
        )

        mock_context_client = Mock()
        mock_context_instructor.return_value = mock_context_client
        mock_context_client.chat.completions.create = AsyncMock(return_value=mock_context_analysis)

        # Answer generator response
        from rag_agents.models.rag_models import SourceCitation
        mock_structured_answer = StructuredAnswer(
            main_response="""The Zep architecture consists of three main components that work together to provide comprehensive memory capabilities for AI assistants:

1. **Memory Store**: Handles conversation history and user sessions, providing the foundation for long-term memory management.

2. **Vector Store**: Enables semantic search capabilities using embeddings, allowing for intelligent retrieval of relevant conversation context.

3. **API Layer**: Provides interfaces for integration with AI assistants and applications.

These components integrate seamlessly - the Memory Store captures and organizes conversations, the Vector Store enables semantic search across this data, and the API Layer provides access to these capabilities. The architecture supports multiple embedding models and provides fast similarity search for real-time context retrieval.""",
            sources_used=[
                SourceCitation(
                    document="zep_architecture.pdf",
                    page_number=1,
                    section="Architecture Overview",
                    content_type="text_with_diagrams",
                    relevance_score=0.92
                ),
                SourceCitation(
                    document="zep_vector_guide.pdf",
                    page_number=8,
                    section="Vector Store Implementation",
                    content_type="text_with_diagrams", 
                    relevance_score=0.85
                ),
                SourceCitation(
                    document="zep_technical.pdf",
                    page_number=15,
                    section="Memory Store Details",
                    content_type="text",
                    relevance_score=0.88
                )
            ],
            multimodal_confidence=0.87,
            evidence_strength="high",
            visual_elements_used=["architecture_diagram", "component_flow_chart"],
            limitations=["Missing recent performance benchmarks", "Limited scalability implementation details"],
            follow_up_suggestions=[
                "Review latest performance documentation",
                "Explore scalability configuration options",
                "Check integration examples and best practices"
            ]
        )

        mock_answer_client = Mock()
        mock_answer_instructor.return_value = mock_answer_client
        mock_answer_client.chat.completions.create = AsyncMock(return_value=mock_structured_answer)

        # Create all agents
        retriever = MultimodalRetrieverAgent(
            config=agent_configs['retriever'],
            name="TestRetriever"
        )

        reranker = MultimodalRerankerAgent(
            config=agent_configs['reranker'],
            name="TestReranker"
        )

        context_analyzer = ContextAnalyzerAgent(
            config=agent_configs['context_analyzer'],
            name="TestContextAnalyzer"
        )

        answer_generator = MultimodalAnswerAgent(
            config=agent_configs['answer_generator'],
            name="TestAnswerGenerator"
        )

        lead_agent = LeadRAGAgent(
            retriever_agent=retriever,
            reranker_agent=reranker,
            context_analyzer_agent=context_analyzer,
            answer_generator_agent=answer_generator,
            config=agent_configs['lead'],
            name="TestLeadRAG"
        )

        # Execute full RAG pipeline
        result = await lead_agent.run(test_context)

        # Verify successful execution
        assert result.status == AgentState.COMPLETED
        assert isinstance(result.output, RAGResult)

        rag_result = result.output

        # Verify query decomposition
        assert rag_result.query_decomposition.query_type == "analytical"
        assert "memory_store" in rag_result.query_decomposition.key_aspects
        assert len(rag_result.query_decomposition.search_strategies) == 1

        # Verify document retrieval and ranking
        assert len(rag_result.ranked_documents.documents) == 3
        assert rag_result.ranked_documents.documents[0].doc_id == "zep_arch_001"
        assert rag_result.ranked_documents.ranking_analysis.diversity_score == 0.78

        # Verify context analysis
        assert rag_result.context_analysis.completeness_score == 0.85
        assert rag_result.context_analysis.confidence_level == "high"
        assert rag_result.context_analysis.recommended_action == "proceed"

        # Verify answer generation
        assert "Memory Store" in rag_result.answer.main_response
        assert "Vector Store" in rag_result.answer.main_response
        assert "API Layer" in rag_result.answer.main_response
        assert len(rag_result.answer.sources_used) == 3
        assert rag_result.answer.multimodal_confidence == 0.87
        assert rag_result.answer.evidence_strength == "high"

        # Verify processing metadata
        assert len(rag_result.processing_steps) >= 4  # At least 4 agent steps
        assert rag_result.total_tokens_used > 0
        assert rag_result.total_processing_time > 0

        # Verify visual elements
        assert "architecture_diagram" in rag_result.answer.visual_elements_used
        assert rag_result.context_analysis.visual_coverage > 0.5

    @pytest.mark.asyncio
    @patch('rag_agents.agents.retriever.voyageai.Client')
    @patch('rag_agents.agents.retriever.DataAPIClient')
    async def test_no_documents_found_scenario(self, mock_astra, mock_voyage, agent_configs, test_context):
        """Test system behavior when no documents are found."""
        # Mock empty search results
        mock_voyage_client = Mock()
        mock_voyage.return_value = mock_voyage_client
        mock_voyage_client.multimodal_embed.return_value = Mock(
            embeddings=[[0.1, 0.2, 0.3] * 333]  # 999-dim embedding
        )

        mock_astra_client = Mock()
        mock_astra.return_value = mock_astra_client
        mock_database = Mock()
        mock_collection = Mock()
        mock_astra_client.get_database.return_value = mock_database
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find = AsyncMock(return_value=[])  # No documents

        # Create retriever agent
        retriever = MultimodalRetrieverAgent(
            config=agent_configs['retriever'],
            name="EmptyRetriever"
        )

        # Run retriever
        result = await retriever.run(test_context)

        assert result.status == AgentState.COMPLETED
        assert isinstance(result.output, list)
        assert len(result.output) == 0

    @pytest.mark.asyncio
    async def test_agent_coordination_timing(self, agent_configs, test_context):
        """Test that agents execute in proper sequence and timing."""
        import time

        # Create mock agents that track execution order
        execution_order = []

        class TimedMockAgent:
            def __init__(self, name, delay=0.1):
                self.name = name
                self.delay = delay

            async def run(self, context):
                execution_order.append(f"{self.name}_start")
                await asyncio.sleep(self.delay)
                execution_order.append(f"{self.name}_end")

                result = Mock()
                result.status = AgentState.COMPLETED
                result.output = f"{self.name}_output"
                result.thinking = []
                result.processing_steps = []
                result.tokens_used = 50
                result.error = None
                return result

        # Mock lead agent decomposition
        with patch('rag_agents.agents.lead_rag.instructor.from_openai') as mock_instructor:
            from rag_agents.models.rag_models import RAGDecomposition, SearchStrategy

            mock_decomposition = RAGDecomposition(
                query_type="factual",
                key_aspects=["test"],
                search_strategies=[SearchStrategy(primary_queries=["test"])],
                ranking_criteria=[],
                visual_requirements=[],
                response_format="detailed"
            )

            mock_client = Mock()
            mock_instructor.return_value = mock_client
            mock_client.chat.completions.create = AsyncMock(return_value=mock_decomposition)

            # Create timed mock agents
            retriever = TimedMockAgent("Retriever", 0.1)
            reranker = TimedMockAgent("Reranker", 0.05)
            context_analyzer = TimedMockAgent("ContextAnalyzer", 0.05)
            answer_generator = TimedMockAgent("AnswerGenerator", 0.1)

            lead_agent = LeadRAGAgent(
                retriever_agent=retriever,
                reranker_agent=reranker,
                context_analyzer_agent=context_analyzer,
                answer_generator_agent=answer_generator,
                config=agent_configs['lead'],
                name="TimingTestLead"
            )

            start_time = time.time()
            result = await lead_agent.run(test_context)
            end_time = time.time()

            # Verify execution completed
            assert result.status == AgentState.COMPLETED

            # Verify sequential execution order
            assert "Retriever_start" in execution_order
            assert "Retriever_end" in execution_order
            assert "Reranker_start" in execution_order
            assert "Reranker_end" in execution_order

            # Verify retriever completes before reranker starts
            retriever_end_idx = execution_order.index("Retriever_end")
            reranker_start_idx = execution_order.index("Reranker_start")
            assert retriever_end_idx < reranker_start_idx

            # Verify reasonable total execution time
            total_time = end_time - start_time
            assert total_time > 0.25  # At least sum of agent delays
            assert total_time < 2.0   # But not too long

    @pytest.mark.asyncio
    async def test_error_propagation(self, agent_configs, test_context):
        """Test error handling and propagation through the system."""

        # Create failing retriever
        class FailingRetriever:
            def __init__(self):
                self.name = "FailingRetriever"

            async def run(self, context):
                result = Mock()
                result.status = AgentState.FAILED
                result.output = None
                result.error = "Database connection failed"
                result.thinking = ["Attempting to connect to database", "Connection timeout"]
                result.processing_steps = []
                result.tokens_used = 0
                return result

        # Create normal mock agents for others
        class NormalMockAgent:
            def __init__(self, name):
                self.name = name

            async def run(self, context):
                result = Mock()
                result.status = AgentState.COMPLETED
                result.output = f"{name}_output"
                result.thinking = []
                result.processing_steps = []
                result.tokens_used = 50
                result.error = None
                return result

        failing_retriever = FailingRetriever()
        normal_reranker = NormalMockAgent("Reranker")
        normal_context_analyzer = NormalMockAgent("ContextAnalyzer")
        normal_answer_generator = NormalMockAgent("AnswerGenerator")

        with patch('rag_agents.agents.lead_rag.instructor.from_openai') as mock_instructor:
            from rag_agents.models.rag_models import RAGDecomposition, SearchStrategy

            mock_decomposition = RAGDecomposition(
                query_type="factual",
                key_aspects=["test"],
                search_strategies=[SearchStrategy(primary_queries=["test"])],
                ranking_criteria=[],
                visual_requirements=[],
                response_format="detailed"
            )

            mock_client = Mock()
            mock_instructor.return_value = mock_client
            mock_client.chat.completions.create = AsyncMock(return_value=mock_decomposition)

            lead_agent = LeadRAGAgent(
                retriever_agent=failing_retriever,
                reranker_agent=normal_reranker,
                context_analyzer_agent=normal_context_analyzer,
                answer_generator_agent=normal_answer_generator,
                config=agent_configs['lead'],
                name="ErrorTestLead"
            )

            result = await lead_agent.run(test_context)

            # Should fail due to retriever failure
            assert result.status == AgentState.FAILED
            assert "Database connection failed" in result.error

    @pytest.mark.asyncio
    async def test_concurrent_agent_operations(self, agent_configs):
        """Test concurrent execution of multiple independent RAG queries."""

        class FastMockAgent:
            def __init__(self, name, base_delay=0.01):
                self.name = name
                self.base_delay = base_delay

            async def run(self, context):
                # Small random delay to simulate real processing
                await asyncio.sleep(self.base_delay)

                result = Mock()
                result.status = AgentState.COMPLETED
                result.output = f"{self.name}_result_for_{context.query[:10]}"
                result.thinking = [f"Processing {context.query}"]
                result.processing_steps = []
                result.tokens_used = 25
                result.error = None
                return result

        # Create contexts for multiple queries
        contexts = [
            AgentContext(query="Query 1", objective="Objective 1"),
            AgentContext(query="Query 2", objective="Objective 2"),
            AgentContext(query="Query 3", objective="Objective 3"),
        ]

        # Create lead agents for each query
        lead_agents = []

        with patch('rag_agents.agents.lead_rag.instructor.from_openai') as mock_instructor:
            from rag_agents.models.rag_models import RAGDecomposition, SearchStrategy

            mock_decomposition = RAGDecomposition(
                query_type="factual",
                key_aspects=["test"],
                search_strategies=[SearchStrategy(primary_queries=["test"])],
                ranking_criteria=[],
                visual_requirements=[],
                response_format="detailed"
            )

            mock_client = Mock()
            mock_instructor.return_value = mock_client
            mock_client.chat.completions.create = AsyncMock(return_value=mock_decomposition)

            for i in range(3):
                lead_agent = LeadRAGAgent(
                    retriever_agent=FastMockAgent(f"Retriever{i}"),
                    reranker_agent=FastMockAgent(f"Reranker{i}"),
                    context_analyzer_agent=FastMockAgent(f"ContextAnalyzer{i}"),
                    answer_generator_agent=FastMockAgent(f"AnswerGenerator{i}"),
                    config=agent_configs['lead'],
                    name=f"ConcurrentLead{i}"
                )
                lead_agents.append(lead_agent)

            # Execute all queries concurrently
            start_time = time.time()
            results = await asyncio.gather(*[
                agent.run(context) for agent, context in zip(lead_agents, contexts)
            ])
            end_time = time.time()

            # Verify all completed successfully
            assert len(results) == 3
            for result in results:
                assert result.status == AgentState.COMPLETED

            # Concurrent execution should be faster than sequential
            total_time = end_time - start_time
            assert total_time < 0.5  # Should complete much faster than sequential