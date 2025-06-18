# evaluator.py

import os
import json
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import statistics

from tqdm import tqdm

# Importa a classe RAG de produção
try:
    from search import ProductionConversationalRAG as MultimodalRagSearcher
except ImportError:
    print("ERRO: O arquivo 'search.py' não foi encontrado.")
    print("Por favor, certifique-se de que todos os arquivos estão na mesma pasta.")
    exit()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

@dataclass
class TestQuestion:
    """Estrutura para perguntas de teste"""
    id: str
    question: str
    expected_pages: List[int]  # Páginas que deveriam ser encontradas
    expected_keywords: List[str]  # Palavras-chave que deveriam aparecer na resposta
    category: str  # Categoria da pergunta (ex: "technical", "conceptual", "specific")
    difficulty: str  # "easy", "medium", "hard"
    ground_truth: Optional[str] = None  # Resposta esperada (opcional)

@dataclass
class EvaluationResult:
    """Resultado da avaliação de uma pergunta"""
    question_id: str
    question: str
    selected_pages: List[int]
    expected_pages: List[int]
    answer: str
    response_time: float
    precision: float
    recall: float
    f1_score: float
    page_accuracy: float
    keyword_coverage: float
    total_candidates: int
    error: Optional[str] = None

class RAGEvaluator:
    """Avaliador completo do sistema RAG"""

    def __init__(self, rag_searcher: MultimodalRagSearcher):
        """
        Inicializa o avaliador

        Args:
            rag_searcher: Instância do MultimodalRagSearcher real.
        """
        self.rag_searcher = rag_searcher
        self.results: List[EvaluationResult] = []

    def create_test_dataset(self) -> List[TestQuestion]:
        """
        Cria dataset de teste personalizado para o paper "ZEP: A TEMPORAL KNOWLEDGE GRAPH ARCHITECTURE FOR AGENT MEMORY"
        """
        return [
            # Perguntas técnicas específicas
            TestQuestion(
                id="tech_001",
                question="Quais são os três subgrafos hierárquicos na arquitetura do Zep?",
                expected_pages=[2],
                expected_keywords=["subgrafo de episódio", "subgrafo de entidade semântica", "subgrafo de comunidade", "hierárquicos"],
                category="technical",
                difficulty="easy"
            ),
            TestQuestion(
                id="tech_002",
                question="Como o Graphiti lida com a invalidação de arestas (fatos) no grafo de conhecimento?",
                expected_pages=[3],
                expected_keywords=["invalidação", "aresta", "temporal", "t_invalid", "bi-temporal", "contradições"],
                category="technical",
                difficulty="medium"
            ),
            TestQuestion(
                id="tech_003",
                question="Quais são os três métodos de busca implementados pelo Zep para recuperação de memória?",
                expected_pages=[5],
                expected_keywords=["similaridade de cosseno", "BM25", "busca em largura", "breadth-first", "retrieval"],
                category="technical",
                difficulty="medium"
            ),

            # Perguntas conceituais
            TestQuestion(
                id="concept_001",
                question="Qual é a principal limitação dos frameworks RAG que o Zep visa resolver?",
                expected_pages=[1],
                expected_keywords=["RAG", "estático", "documento", "dinâmico", "conhecimento", "conversas"],
                category="conceptual",
                difficulty="easy"
            ),
            TestQuestion(
                id="concept_002",
                question="De que forma a estrutura de memória do Zep se assemelha aos modelos psicológicos da memória humana?",
                expected_pages=[2],
                expected_keywords=["memória humana", "episódica", "semântica", "psicológicos", "associações"],
                category="conceptual",
                difficulty="medium"
            ),

            # Perguntas específicas (dados, tabelas)
            TestQuestion(
                id="specific_001",
                question="Qual foi a pontuação de acurácia (Score) do Zep com o modelo gpt-4-turbo na avaliação Deep Memory Retrieval (DMR), conforme a Tabela 1?",
                expected_pages=[6],
                expected_keywords=["94.8%", "DMR", "Tabela 1", "gpt-4-turbo", "score"],
                category="specific",
                difficulty="easy"
            ),
            TestQuestion(
                id="specific_002",
                question="Na Tabela 2, qual foi a redução de latência do Zep em comparação com o baseline 'Full-context' usando o modelo gpt-4o?",
                expected_pages=[7],
                expected_keywords=["latência", "2.58 s", "28.9 s", "90%", "Tabela 2", "LongMemEval"],
                category="specific",
                difficulty="hard"
            ),
             TestQuestion(
                id="specific_003",
                question="Qual algoritmo de detecção de comunidade o Zep utiliza e por quê?",
                expected_pages=[4],
                expected_keywords=["label propagation", "Leiden", "dinâmico", "comunidade"],
                category="specific",
                difficulty="hard"
            ),

            # Perguntas sobre conteúdo visual (tabelas, pois não há figuras)
            TestQuestion(
                id="visual_001",
                question="O que a Tabela 3 detalha sobre os resultados da avaliação LongMemEval?",
                expected_pages=[7],
                expected_keywords=["Tabela 3", "detalhamento", "tipo de pergunta", "delta", "single-session-preference", "multi-session"],
                category="visual",
                difficulty="medium"
            ),

            # Perguntas que podem não ter resposta clara (negativas)
            TestQuestion(
                id="negative_001",
                question="Qual é o custo para licenciar a tecnologia Zep para uso comercial?",
                expected_pages=[],  # Não deveria encontrar páginas relevantes
                expected_keywords=[],
                category="negative",
                difficulty="easy"
            ),
        ]

    def calculate_metrics(self, 
                          selected_pages: List[int], 
                          expected_pages: List[int],
                          answer: str,
                          expected_keywords: List[str]) -> Tuple[float, float, float, float, float]:
        """
        Calcula métricas de avaliação.
        """
        if not expected_pages:
            if not selected_pages:
                return 1.0, 1.0, 1.0, 1.0, 1.0  # Acerto: não retornou nada quando não devia
            else:
                return 0.0, 0.0, 0.0, 0.0, 0.0  # Erro: retornou algo quando não devia

        if not selected_pages:
            return 0.0, 0.0, 0.0, 0.0, 0.0  # No results when should have results

        relevant_selected_set = set(selected_pages) & set(expected_pages)

        precision = len(relevant_selected_set) / len(selected_pages)
        recall = len(relevant_selected_set) / len(expected_pages)

        if precision + recall == 0:
            f1_score = 0.0
        else:
            f1_score = 2 * (precision * recall) / (precision + recall)

        union_set = set(selected_pages) | set(expected_pages)
        page_accuracy = len(relevant_selected_set) / len(union_set) if union_set else 1.0

        if not expected_keywords:
            keyword_coverage = 1.0
        else:
            answer_lower = answer.lower()
            found_keywords = sum(1 for kw in expected_keywords if kw.lower() in answer_lower)
            keyword_coverage = found_keywords / len(expected_keywords)

        return precision, recall, f1_score, page_accuracy, keyword_coverage

    def evaluate_single_question(self, test_q: TestQuestion) -> EvaluationResult:
        """Avalia uma única pergunta."""
        start_time = time.time()

        try:
            result = self.rag_searcher.search_and_answer(test_q.question)
            response_time = time.time() - start_time

            # --- TRECHO ALTERADO ---
            # Trata o caso específico onde a verificação de relevância corretamente não encontra uma resposta.
            # Isso é considerado um SUCESSO para perguntas negativas, não um erro.
            relevance_error = "A informação solicitada não foi encontrada de forma explícita no documento."
            if "error" in result and result["error"] == relevance_error:
                # Transforma o "erro de relevância" em um resultado bem-sucedido com zero páginas.
                logger.info(f"Pergunta '{test_q.id}' corretamente identificada como sem resposta pela verificação de relevância.")
                result = {
                    "answer": "Nenhuma informação relevante encontrada (confirmado pela verificação de relevância).",
                    "selected_pages_details": [],
                    "total_candidates": result.get("total_candidates", 0),
                }
            # Trata todos os outros erros como falhas.
            elif "error" in result:
                return EvaluationResult(
                    question_id=test_q.id, question=test_q.question,
                    selected_pages=[], expected_pages=test_q.expected_pages,
                    answer="", response_time=response_time,
                    precision=0.0, recall=0.0, f1_score=0.0, page_accuracy=0.0,
                    keyword_coverage=0.0, total_candidates=0,
                    error=result["error"]
                )

            selected_pages = [p["page_number"] for p in result["selected_pages_details"]]

            precision, recall, f1_score, page_accuracy, keyword_coverage = self.calculate_metrics(
                selected_pages, test_q.expected_pages, result["answer"], test_q.expected_keywords
            )

            return EvaluationResult(
                question_id=test_q.id, question=test_q.question,
                selected_pages=selected_pages, expected_pages=test_q.expected_pages,
                answer=result["answer"], response_time=response_time,
                precision=precision, recall=recall, f1_score=f1_score,
                page_accuracy=page_accuracy, keyword_coverage=keyword_coverage,
                total_candidates=result.get("total_candidates", 0)
            )

        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Erro fatal avaliando pergunta {test_q.id}: {e}", exc_info=True)
            return EvaluationResult(
                question_id=test_q.id, question=test_q.question,
                selected_pages=[], expected_pages=test_q.expected_pages,
                answer="", response_time=response_time,
                precision=0.0, recall=0.0, f1_score=0.0, page_accuracy=0.0,
                keyword_coverage=0.0, total_candidates=0, error=str(e)
            )

    def run_evaluation(self, test_questions: Optional[List[TestQuestion]] = None) -> Dict[str, Any]:
        """Executa avaliação completa."""
        if test_questions is None:
            test_questions = self.create_test_dataset()

        logger.info(f"Iniciando avaliação com {len(test_questions)} perguntas")

        self.results = [self.evaluate_single_question(test_q) for test_q in tqdm(test_questions, desc="Avaliando perguntas")]

        for result in self.results:
             logger.info(f"Q_ID:{result.question_id}: P={result.precision:.2f}, R={result.recall:.2f}, "
                        f"F1={result.f1_score:.2f}, T={result.response_time:.2f}s")

        successful_results = [r for r in self.results if r.error is None]

        if not successful_results:
            logger.error("Nenhuma pergunta foi avaliada com sucesso!")
            return {"error": "Nenhuma avaliação bem-sucedida"}

        # Agrega métricas gerais
        overall_metrics = {
            "average_precision": statistics.mean([r.precision for r in successful_results]),
            "average_recall": statistics.mean([r.recall for r in successful_results]),
            "average_f1_score": statistics.mean([r.f1_score for r in successful_results]),
            "average_page_accuracy": statistics.mean([r.page_accuracy for r in successful_results]),
            "average_keyword_coverage": statistics.mean([r.keyword_coverage for r in successful_results]),
            "average_response_time": statistics.mean([r.response_time for r in successful_results]),
        }

        # Agrega métricas por categoria
        categories = {q.category for q in test_questions}
        category_stats = {}
        for cat in categories:
            cat_results = [r for r in successful_results if r.question_id.startswith(cat)]
            if cat_results:
                category_stats[cat] = {
                    "count": len(cat_results),
                    "avg_precision": statistics.mean([r.precision for r in cat_results]),
                    "avg_recall": statistics.mean([r.recall for r in cat_results]),
                    "avg_f1": statistics.mean([r.f1_score for r in cat_results]),
                    "avg_response_time": statistics.mean([r.response_time for r in cat_results]),
                }

        report = {
            "evaluation_summary": {
                "total_questions": len(test_questions),
                "successful_evaluations": len(successful_results),
                "failed_evaluations": len(self.results) - len(successful_results),
                "success_rate": len(successful_results) / len(test_questions) if test_questions else 0,
            },
            "overall_metrics": overall_metrics,
            "category_breakdown": category_stats,
            "detailed_results": [asdict(r) for r in self.results],
            "evaluation_timestamp": datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(),
        }

        return report

    def save_report(self, report: Dict[str, Any], output_path: str = "rag_evaluation_report.json"):
        """Salva relatório em arquivo JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"Relatório JSON salvo em: {output_path}")

    def create_detailed_report(self, report: Dict[str, Any]) -> str:
        """Cria relatório detalhado em texto."""
        lines = ["=" * 80, "RELATÓRIO DE AVALIAÇÃO DO SISTEMA RAG MULTIMODAL", "=" * 80, ""]

        summary = report["evaluation_summary"]
        lines.extend([
            "📊 RESUMO GERAL:",
            f"• Total de perguntas: {summary['total_questions']}",
            f"• Avaliações bem-sucedidas: {summary['successful_evaluations']}",
            f"• Avaliações com falha: {summary['failed_evaluations']}",
            f"• Taxa de sucesso: {summary['success_rate']:.1%}", ""
        ])

        metrics = report["overall_metrics"]
        lines.extend([
            "📈 MÉTRICAS GERAIS:",
            f"• Precisão média: {metrics['average_precision']:.3f}",
            f"• Recall médio: {metrics['average_recall']:.3f}",
            f"• F1-Score médio: {metrics['average_f1_score']:.3f}",
            f"• Acurácia de páginas (Jaccard): {metrics['average_page_accuracy']:.3f}",
            f"• Cobertura de palavras-chave: {metrics['average_keyword_coverage']:.3f}",
            f"• Tempo de resposta médio: {metrics['average_response_time']:.2f}s", ""
        ])

        lines.append("🏷️ ANÁLISE POR CATEGORIA:")
        for cat, stats in report["category_breakdown"].items():
            lines.extend([
                f"• {cat.upper()} ({stats['count']} perguntas):",
                f"  - Precisão: {stats['avg_precision']:.3f}",
                f"  - Recall: {stats['avg_recall']:.3f}",
                f"  - F1-Score: {stats['avg_f1']:.3f}",
                f"  - Tempo médio: {stats['avg_response_time']:.2f}s"
            ])
        lines.append("")

        lines.append("📋 RESULTADOS DETALHADOS:")
        for result in report["detailed_results"]:
            lines.append(f"• {result['question_id']}: {result['question']}")
            if result['error']:
                lines.append(f"  ❌ ERRO: {result['error']}")
            else:
                lines.append(f"  ✅ Páginas: {result['selected_pages']} (Esperado: {result['expected_pages']})")
                lines.append(f"     P={result['precision']:.2f}, R={result['recall']:.2f}, F1={result['f1_score']:.2f}")
        lines.append("")

        return "\n".join(lines)

def main():
    """Função principal para execução standalone."""
    print("🚀 AVALIADOR DE SISTEMA RAG MULTIMODAL 🚀")
    print("=" * 60)

    try:
        print("🔧 Inicializando o sistema RAG real...")
        rag_searcher = MultimodalRagSearcher()
        print("✅ Sistema RAG inicializado com sucesso!")

        evaluator = RAGEvaluator(rag_searcher=rag_searcher)

        print("\n🔍 Executando avaliação completa...")
        report = evaluator.run_evaluation()

        # Salva e imprime relatórios
        evaluator.save_report(report)

        detailed_report = evaluator.create_detailed_report(report)
        report_path = "rag_evaluation_detailed.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(detailed_report)
        logger.info(f"Relatório detalhado salvo em: {report_path}")


        print("\n" + detailed_report)
        print("\n✅ Avaliação concluída! Arquivos salvos:")
        print("• rag_evaluation_report.json")
        print("• rag_evaluation_detailed.txt")

    except Exception as e:
        print(f"\n❌ Erro fatal durante a execução do avaliador: {e}")
        logger.critical("Erro fatal no main do avaliador", exc_info=True)
        print("\nVerifique se:")
        print("1. O arquivo 'buscador.py' está na mesma pasta.")
        print("2. O arquivo '.env' com as chaves de API está configurado corretamente.")
        print("3. O sistema RAG foi indexado (rode o 'indexador.py' primeiro).")
        print("4. Todas as dependências (`requirements.txt`) estão instaladas.")

if __name__ == "__main__":
    main()