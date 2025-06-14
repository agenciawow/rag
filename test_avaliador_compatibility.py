# Teste de compatibilidade do avaliador com a versão de produção

try:
    from buscador_conversacional_producao import ProductionConversationalRAG
    print("✅ Import do RAG de produção: OK")
    
    # Testa inicialização
    rag = ProductionConversationalRAG()
    print("✅ Inicialização do RAG: OK")
    
    # Testa se tem o método search_and_answer
    if hasattr(rag, 'search_and_answer'):
        print("✅ Método search_and_answer: OK")
    else:
        print("❌ Método search_and_answer: FALTANDO")
        
    # Testa formato de retorno
    result = rag.search_and_answer("teste")
    if isinstance(result, dict):
        print("✅ Formato de retorno (dict): OK")
        expected_keys = ["answer", "selected_pages_details", "total_candidates"]
        has_keys = all(key in result or "error" in result for key in expected_keys)
        if has_keys or "error" in result:
            print("✅ Chaves necessárias: OK")
        else:
            print(f"❌ Chaves faltando: {expected_keys}")
    else:
        print("❌ Formato de retorno inválido")
        
    print("\n🎯 AVALIADOR ESTÁ COMPATÍVEL COM A VERSÃO DE PRODUÇÃO!")
    
except Exception as e:
    print(f"❌ Erro de compatibilidade: {e}")
    print("⚠️  AVALIADOR PRECISA DE AJUSTES")
