#!/usr/bin/env python3
"""
Script para testar conexões com os bancos de dados e funcionalidades do RAG
"""

import os
import sys
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

def test_vector_database():
    """Testa conexão com o banco vetorial"""
    print("🔍 Testando conexão com banco vetorial...")
    
    try:
        from astrapy import DataAPIClient
        
        endpoint = os.getenv("VECTOR_DB_API_ENDPOINT")
        token = os.getenv("VECTOR_DB_TOKEN")
        
        if not endpoint or not token:
            print("❌ Variáveis VECTOR_DB_API_ENDPOINT ou VECTOR_DB_TOKEN não encontradas")
            return False
            
        print(f"   Endpoint: {endpoint}")
        print(f"   Token: {token[:20]}...")
        
        # Conecta ao banco vetorial
        client = DataAPIClient(token)
        database = client.get_database_by_api_endpoint(endpoint)
        
        # Lista collections
        collections = database.list_collection_names()
        print(f"   Collections encontradas: {collections}")
        
        # Testa collection pdf_documents
        if "pdf_documents" in collections:
            collection = database.get_collection("pdf_documents")
            # Usa estimated_document_count ao invés de count_documents
            count = collection.estimated_document_count()
            print(f"   Documentos na collection: {count}")
        else:
            print("   Collection 'pdf_documents' não encontrada")
            
        print("✅ Conexão com banco vetorial: OK")
        return True
        
    except Exception as e:
        print(f"❌ Erro na conexão com banco vetorial: {e}")
        return False

def test_user_management():
    """Testa gerenciamento local de usuários"""
    print("\n👤 Testando gerenciamento de usuários...")
    
    try:
        from manage_production_users import ProductionUserManager
        import os
        
        # Testa se o arquivo de usuários existe
        user_file = "production_users.json"
        if os.path.exists(user_file):
            print(f"   Arquivo de usuários encontrado: {user_file}")
        else:
            print(f"   Arquivo de usuários será criado: {user_file}")
        
        # Testa inicialização do gerenciador
        user_manager = ProductionUserManager()
        print(f"   Usuários carregados: {len(user_manager.users)}")
        
        # Testa diretório de memórias
        memory_dir = "production_users"
        if os.path.exists(memory_dir):
            user_dirs = [d for d in os.listdir(memory_dir) if os.path.isdir(os.path.join(memory_dir, d))]
            print(f"   Diretórios de usuários: {len(user_dirs)}")
        else:
            print(f"   Diretório de memórias será criado: {memory_dir}")
        
        print("✅ Gerenciamento local de usuários: OK")
        return True
        
    except Exception as e:
        print(f"❌ Erro no gerenciamento de usuários: {e}")
        return False

def test_rag_system():
    """Testa o sistema RAG completo"""
    print("\n🤖 Testando sistema RAG...")
    
    try:
        from buscador_conversacional_producao import ProductionConversationalRAG
        
        # Inicializa o sistema RAG
        rag = ProductionConversationalRAG()
        print("✅ Sistema RAG inicializado com sucesso")
        
        # Testa uma busca simples
        print("   Testando busca...")
        response = rag.ask("teste de conexão")
        print(f"   Resposta recebida: {len(response)} caracteres")
        print("✅ Busca RAG: OK")
        return True
        
    except Exception as e:
        print(f"❌ Erro no sistema RAG: {e}")
        return False

def test_indexing():
    """Testa a funcionalidade de indexação"""
    print("\n📚 Testando indexação...")
    
    try:
        from indexador import validate_env_vars, connect_to_astra, get_config
        
        # Valida variáveis de ambiente
        validate_env_vars()
        print("✅ Variáveis de ambiente para indexação: OK")
        
        # Testa conexão
        config = get_config()
        collection = connect_to_astra(config)
        print("✅ Conexão para indexação: OK")
        
        # Verifica se pode acessar a collection
        count = collection.estimated_document_count()
        print(f"   Documentos indexados: {count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro na indexação: {e}")
        return False

def main():
    """Executa todos os testes"""
    print("🚀 INICIANDO TESTES DO SISTEMA RAG")
    print("=" * 50)
    
    results = {
        "vector_db": test_vector_database(),
        "user_management": test_user_management(), 
        "indexing": test_indexing(),
        "rag_system": test_rag_system()
    }
    
    print("\n" + "=" * 50)
    print("📊 RESUMO DOS TESTES:")
    
    all_passed = True
    for test_name, result in results.items():
        status = "✅ PASSOU" if result else "❌ FALHOU"
        print(f"   {test_name:15}: {status}")
        if not result:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 TODOS OS TESTES PASSARAM! Sistema funcionando corretamente.")
    else:
        print("⚠️ ALGUNS TESTES FALHARAM. Verifique os erros acima.")
        sys.exit(1)

if __name__ == "__main__":
    main()