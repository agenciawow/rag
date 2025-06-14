# streamlit_rag_app_producao.py

import streamlit as st
import json
import hashlib
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from zoneinfo import ZoneInfo
import re
import tempfile
from dotenv import load_dotenv

# Importa a versão do sistema
from buscador_conversacional_producao import ProductionConversationalRAG, health_check, test_apis

# Configuração da página
st.set_page_config(
    page_title="RAG Conversacional",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuração de logging específica para o Streamlit
def setup_streamlit_logging():
    """Configura logging específico para o Streamlit"""
    st_logger = logging.getLogger(__name__)
    st_logger.setLevel(logging.DEBUG)
    
    # Remove handlers existentes para evitar duplicação
    for handler in st_logger.handlers[:]:
        st_logger.removeHandler(handler)
    
    # Formatter detalhado
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
    )
    
    # Handler para console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # Menos verboso no console para Streamlit
    console_handler.setFormatter(formatter)
    st_logger.addHandler(console_handler)
    
    # Handler para arquivo específico do Streamlit
    file_handler = logging.FileHandler("streamlit_debug.log", encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    st_logger.addHandler(file_handler)
    
    # Permite propagação para mostrar logs no console principal
    st_logger.propagate = True
    
    return st_logger

logger = setup_streamlit_logging()

# Log inicial para confirmar que o sistema de logging está funcionando
logger.info("🌐 [INIT] Sistema de logging do Streamlit inicializado")

def get_sao_paulo_time():
    """Retorna datetime atual no fuso horário de São Paulo"""
    return datetime.now(ZoneInfo("America/Sao_Paulo"))

def close_all_modals():
    """Fecha todos os modals abertos"""
    st.session_state.show_user_management = False
    st.session_state.show_user_stats = False
    st.session_state.show_document_management = False
    st.session_state.show_ia_config = False
    if 'edit_user' in st.session_state:
        del st.session_state.edit_user

class StreamlitUserManager:
    """Gerenciador de usuários para Streamlit"""
    
    def __init__(self, users_file="production_users.json"):
        self.users_file = Path(users_file)
        self.users = self.load_users()
        self._create_default_users()
    
    def _create_default_users(self):
        """Cria usuários padrão se não existirem"""
        # Não cria mais usuários automaticamente
        pass
    
    def load_users(self) -> Dict:
        """Carrega usuários do arquivo"""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erro ao carregar usuários: {e}")
                return {}
        return {}
    
    def save_users(self):
        """Salva usuários no arquivo"""
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Erro ao salvar usuários: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash da senha com salt"""
        salt = "streamlit_rag_production_2025"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def authenticate(self, username: str, password: str) -> bool:
        """Autentica usuário"""
        if username in self.users:
            return self.users[username]["password_hash"] == self.hash_password(password)
        return False
    
    def get_user_info(self, username: str) -> Dict:
        """Pega informações do usuário"""
        return self.users.get(username, {})
    
    def is_admin(self, username: str) -> bool:
        """Verifica se usuário é admin"""
        user = self.users.get(username, {})
        return user.get("role") == "Admin"

@st.cache_resource
def _get_global_rag_instance():
    """Instância global do RAG (cache do Streamlit)"""
    try:
        logger.info("[CACHE] Inicializando instância global RAG...")
        start_time = time.time()
        
        rag_instance = ProductionConversationalRAG()
        
        init_time = time.time() - start_time
        logger.info(f"[CACHE] RAG inicializado com sucesso em {init_time:.2f}s")
        
        return rag_instance
    except Exception as e:
        logger.error(f"[CACHE] Erro ao inicializar RAG: {e}", exc_info=True)
        st.error(f"❌ Erro na inicialização: {e}")
        return None

class ProductionStreamlitRAG:
    """RAG adaptado para Streamlit com cache e otimizações"""
    
    def __init__(self, user_id: str):
        logger.info(f"[USER] Inicializando ProductionStreamlitRAG para usuário: {user_id}")
        
        self.user_id = user_id
        self.user_dir = Path(f"production_users/{user_id}")
        self.user_dir.mkdir(parents=True, exist_ok=True)
        self.memory_file = self.user_dir / "chat_history.json"
        self.stats_file = self.user_dir / "user_stats.json"
        
        logger.debug(f"[USER] Diretório do usuário: {self.user_dir}")
        
        # Inicializa RAG (com cache global no Streamlit)
        self._initialize_rag()
        
        # Carrega histórico e estatísticas do usuário
        self.load_user_data()
        
        logger.info(f"[USER] ProductionStreamlitRAG inicializado para {user_id}")
    
    def _initialize_rag(self):
        """Inicializa RAG usando cache global"""
        if "rag_instance" not in st.session_state:
            st.session_state.rag_instance = _get_global_rag_instance()
        
        if st.session_state.rag_instance is None:
            st.error("❌ Sistema RAG não inicializado corretamente")
            st.stop()
    
    def load_user_data(self):
        """Carrega dados específicos do usuário"""
        # Carrega histórico
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Define histórico específico do usuário no RAG
                    chat_history = data.get("chat_history", [])
                    st.session_state.rag_instance.chat_history = chat_history
                    logger.info(f"[LOAD] Histórico carregado: {len(chat_history)} mensagens para {self.user_id}")
            except Exception as e:
                logger.warning(f"Erro ao carregar histórico do usuário {self.user_id}: {e}")
                st.session_state.rag_instance.chat_history = []
        else:
            st.session_state.rag_instance.chat_history = []
            logger.info(f"[LOAD] Novo usuário, histórico vazio para {self.user_id}")
        
        # Carrega estatísticas
        self.user_stats = self._load_user_stats()
    
    def _load_user_stats(self) -> Dict:
        """Carrega estatísticas do usuário"""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            "total_questions": 0,
            "successful_answers": 0,
            "first_login": get_sao_paulo_time().isoformat(),
            "last_activity": get_sao_paulo_time().isoformat()
        }
    
    def _save_user_stats(self):
        """Salva estatísticas do usuário"""
        try:
            self.user_stats["last_activity"] = get_sao_paulo_time().isoformat()
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.user_stats, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Erro ao salvar estatísticas: {e}")
    
    def save_user_history(self):
        """Salva histórico do usuário de forma sincronizada"""
        try:
            # Usa o histórico do frontend como fonte da verdade
            current_history = getattr(st.session_state, 'messages', [])
            
            # Se não houver histórico no frontend, usa o do backend
            if not current_history and hasattr(st.session_state.rag_instance, 'chat_history'):
                current_history = st.session_state.rag_instance.chat_history
            
            memory_data = {
                "user_id": self.user_id,
                "last_updated": get_sao_paulo_time().isoformat(),
                "total_messages": len(current_history),
                "chat_history": current_history
            }
            
            with open(self.memory_file, 'w', encoding='utf-8') as f:
                json.dump(memory_data, f, indent=2, ensure_ascii=False)
            
            # Sincroniza o histórico do backend com o frontend
            if hasattr(st.session_state.rag_instance, 'chat_history'):
                st.session_state.rag_instance.chat_history = current_history.copy()
            
            self._save_user_stats()
            logger.debug(f"[SAVE] Histórico salvo: {len(current_history)} mensagens")
            
        except Exception as e:
            logger.error(f"Erro ao salvar histórico: {e}")
            # Não exibe erro no Streamlit para evitar inundação de mensagens
    
    def ask(self, question: str) -> str:
        """Faz pergunta usando RAG e salva automaticamente"""
        start_time = time.time()
        
        logger.info(f"[ASK] Usuário {self.user_id} perguntou: {question[:100]}...")
        
        try:
            self.user_stats["total_questions"] += 1
            logger.debug(f"[ASK] Total de perguntas do usuário: {self.user_stats['total_questions']}")
            
            # Usa o método ask do sistema
            logger.debug(f"[ASK] Chamando RAG...")
            response = st.session_state.rag_instance.ask(question)
            
            processing_time = time.time() - start_time
            logger.info(f"[ASK] Resposta gerada em {processing_time:.2f}s")
            
            if "erro" not in response.lower() and "desculpe" not in response.lower():
                self.user_stats["successful_answers"] += 1
                logger.debug(f"[ASK] Resposta bem-sucedida registrada")
            else:
                logger.warning(f"[ASK] Resposta com possível erro detectado")
            
            logger.debug(f"[ASK] Salvando histórico do usuário...")
            self.save_user_history()
            
            logger.info(f"[ASK] Processo completo em {time.time() - start_time:.2f}s")
            return response
            
        except Exception as e:
            error_time = time.time() - start_time
            logger.error(f"[ASK] Erro na pergunta do usuário {self.user_id} após {error_time:.2f}s: {e}", exc_info=True)
            return f"❌ Erro ao processar pergunta: {e}"
    
    def ask_question_only(self, question: str) -> str:
        """Faz pergunta usando RAG retornando apenas a resposta, sem gerenciar histórico"""
        start_time = time.time()
        
        logger.info(f"[ASK_ONLY] Usuário {self.user_id} perguntou: {question[:100]}...")
        
        try:
            self.user_stats["total_questions"] += 1
            logger.debug(f"[ASK_ONLY] Total de perguntas do usuário: {self.user_stats['total_questions']}")
            
            # Cria uma instância temporária do RAG com o contexto atual
            temp_history = st.session_state.rag_instance.chat_history.copy()
            
            # Adiciona a pergunta temporariamente para contexto
            temp_history.append({"role": "user", "content": question})
            
            # Salva o histórico original
            original_history = st.session_state.rag_instance.chat_history
            
            # Define o histórico temporário
            st.session_state.rag_instance.chat_history = temp_history
            
            # Usa o método search_and_answer diretamente (sem adicionar ao histórico)
            from buscador_conversacional_producao import ProductionQueryTransformer
            transformer = ProductionQueryTransformer(st.session_state.rag_instance.openai_client)
            
            # Transforma a query
            transformed_query = transformer.transform_query(temp_history)
            
            if not transformer.needs_rag(transformed_query):
                response = self._generate_simple_response(question)
            else:
                clean_query = transformer.clean_query(transformed_query)
                rag_result = st.session_state.rag_instance.search_and_answer(clean_query)
                
                if "error" in rag_result:
                    response = f"Desculpe, não consegui encontrar informações sobre isso. {rag_result['error']}"
                else:
                    response = rag_result["answer"]
            
            # Restaura o histórico original
            st.session_state.rag_instance.chat_history = original_history
            
            processing_time = time.time() - start_time
            logger.info(f"[ASK_ONLY] Resposta gerada em {processing_time:.2f}s")
            
            # Limpa a resposta
            if isinstance(response, str):
                response = self._clean_rag_response(response)
            
            # Atualiza estatísticas
            if "erro" not in response.lower() and "desculpe" not in response.lower():
                self.user_stats["successful_answers"] += 1
                logger.debug(f"[ASK_ONLY] Resposta bem-sucedida registrada")
            else:
                logger.warning(f"[ASK_ONLY] Resposta com possível erro detectado")
            
            # Salva estatísticas (mas não o histórico)
            self._save_user_stats()
            
            logger.info(f"[ASK_ONLY] Processo completo em {time.time() - start_time:.2f}s")
            return response
            
        except Exception as e:
            error_time = time.time() - start_time
            logger.error(f"[ASK_ONLY] Erro na pergunta do usuário {self.user_id} após {error_time:.2f}s: {e}", exc_info=True)
            return f"❌ Erro ao processar pergunta: {e}"
    
    def _clean_rag_response(self, response: str) -> str:
        """Remove mensagens de status e indicadores de tempo da resposta"""
        if not response:
            return response
        
        # Lista de padrões a serem removidos
        patterns_to_remove = [
            r'⏱️.*?gerada.*?',  # Remove "⏱️ Resposta gerada" e variações
            r'⏰.*?tempo.*?',   # Remove indicadores de tempo
            r'🕐.*?atividade.*?', # Remove última atividade
            r'Tempo de.*?:.*?\n',  # Remove "Tempo de processamento: X.Xs"
            r'Response time:.*?\n', # Remove "Response time: X.Xs"
            r'Processado em.*?\n',  # Remove "Processado em X.Xs"
            r'Generated in.*?\n',   # Remove "Generated in X.Xs"
        ]
        
        cleaned = response
        for pattern in patterns_to_remove:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.MULTILINE)
        
        # Remove linhas em branco extras
        lines = cleaned.split('\n')
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            # Remove linhas que são só indicadores de tempo/status
            if not any(indicator in stripped.lower() for indicator in [
                '⏱️', '⏰', '🕐', 'resposta gerada', 'tempo de', 'processado em', 
                'generated in', 'response time', 'processing time'
            ]):
                cleaned_lines.append(line)
        
        # Reconstrói o texto e remove espaços extras
        result = '\n'.join(cleaned_lines).strip()
        
        # Remove múltiplas linhas em branco consecutivas
        result = re.sub(r'\n\s*\n\s*\n', '\n\n', result)
        
        return result

    def _generate_simple_response(self, question: str) -> str:
        """Gera resposta simples para perguntas que não precisam de RAG"""
        greetings = ["oi", "olá", "hello", "hi", "boa tarde", "bom dia", "boa noite"]
        
        if any(greeting in question.lower() for greeting in greetings):
            return "Olá! Sou seu assistente para consultas sobre documentos acadêmicos. Como posso ajudar você hoje?"
        
        thanks = ["obrigado", "obrigada", "thanks", "valeu"]
        if any(thank in question.lower() for thank in thanks):
            return "De nada! Fico feliz em ajudar. Há mais alguma coisa que gostaria de saber?"
        
        return "Como posso ajudar você com consultas sobre os documentos? Faça uma pergunta específica e eu buscarei as informações relevantes."

    def clear_history(self):
        """Limpa histórico do usuário"""
        if hasattr(st.session_state.rag_instance, 'clear_history'):
            st.session_state.rag_instance.clear_history()
        self.save_user_history()
        
    def get_chat_history(self) -> List[Dict[str, str]]:
        """Retorna o histórico de chat atual"""
        return st.session_state.rag_instance.chat_history.copy() if hasattr(st.session_state.rag_instance, 'chat_history') else []

    def get_user_stats(self):
        """Retorna estatísticas do usuário, sempre garantindo estrutura válida"""
        padrao = {
            "total_questions": 0,
            "successful_answers": 0,
            "first_login": get_sao_paulo_time().isoformat(),
            "last_activity": get_sao_paulo_time().isoformat()
        }
        try:
            # Tenta carregar do atributo
            stats = getattr(self, 'user_stats', None)
            if not stats or not isinstance(stats, dict):
                stats = self._load_user_stats()
            # Garante todos os campos
            for k, v in padrao.items():
                if k not in stats:
                    stats[k] = v
            self.user_stats = stats
            return stats.copy()
        except Exception as e:
            logger.error(f"Erro ao acessar estatísticas do usuário: {e}")
            # Força regravação do arquivo com valores padrão
            self.user_stats = padrao
            self._save_user_stats()
            return self.user_stats.copy()

def login_page():
    """Página de login do sistema"""
    st.title("🚀 Login - Sistema RAG Conversacional")
    
    # Health check do sistema
    with st.spinner("Verificando sistema...", show_time=True):
        try:
            health_status = health_check()
            if health_status["status"] == "healthy":
                st.success("✅ Sistema operacional")
            elif health_status["status"] == "degraded":
                st.warning("⚠️ Sistema com degradação")
            else:
                st.error("❌ Sistema com problemas")
                st.json(health_status)
        except Exception as e:
            st.error(f"❌ Erro no health check: {str(e)}")
    
    st.markdown("### 🔐 Acesso ao Sistema")
    
    with st.form("login_form"):
        username = st.text_input("👤 Usuário", placeholder="Digite seu usuário")
        password = st.text_input("🔒 Senha", type="password", placeholder="Digite sua senha")
        login_button = st.form_submit_button("🚀 Entrar", use_container_width=True)
    
    if login_button:
        if username and password:
            user_manager = StreamlitUserManager()
            
            if user_manager.authenticate(username, password):
                # Login bem-sucedido
                user_info = user_manager.get_user_info(username)
                
                logger.info(f"[LOGIN] Login bem-sucedido: {username} - {user_info.get('name')} - {user_info.get('role')}")
                logger.debug(f"[LOGIN] Permissões do usuário: {user_info.get('permissions', [])}")
                
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.user_info = user_info
                st.session_state.user_manager = user_manager
                
                st.success(f"✅ Bem-vindo, {user_info.get('name', username)}!")
                time.sleep(1)
                st.rerun()
            else:
                logger.warning(f"[LOGIN] Tentativa de login falhada para usuário: {username}")
                st.error("❌ Usuário ou senha incorretos!")
        else:
            st.warning("⚠️ Preencha todos os campos!")

def sidebar_user_info():
    with st.sidebar:
        st.markdown("### 👤 Usuário Logado")
        user_info = st.session_state.get('user_info', {})
        st.markdown(f"**Nome:** {user_info.get('name', 'N/A')}")
        st.markdown(f"**Perfil:** {user_info.get('role', 'N/A')}")
        st.markdown(f"**Organização:** {user_info.get('organization', 'N/A')}")
        st.markdown("---")

        if st.button("🏠 Home", key="btn_home", use_container_width=True):
            close_all_modals()
            st.rerun()

        if st.button("📊 Minhas Estatísticas", key="btn_stats", use_container_width=True):
            close_all_modals()
            st.session_state.show_user_stats = True
            st.rerun()

        if st.button("🧹 Limpar Conversa", key="btn_clear", use_container_width=True):
            # Limpa histórico do frontend
            st.session_state.messages = []
            
            # Limpa histórico do backend
            if 'user_rag' in st.session_state:
                st.session_state.user_rag.clear_history()
            
            # Limpa histórico da instância RAG
            if hasattr(st.session_state, 'rag_instance') and st.session_state.rag_instance:
                st.session_state.rag_instance.chat_history = []
                
            logger.info(f"[CHAT] Histórico limpo para {st.session_state.username}")
            st.success("✅ Conversa limpa!")
            st.rerun()

        user_manager = st.session_state.get('user_manager')
        is_admin = user_manager and user_manager.is_admin(st.session_state.username)
        if is_admin:
            st.markdown("---")
            st.markdown("### 🛠️ Painel Admin")
            if st.button("👥 Gerenciar Usuários", key="btn_admin_users", use_container_width=True):
                close_all_modals()
                st.session_state.show_user_management = True
                st.rerun()
            if st.button("📄 Gerenciar Documentos", key="btn_admin_docs", use_container_width=True):
                close_all_modals()
                st.session_state.show_document_management = True
                st.rerun()
            if st.button('🤖 Configurações de IA', key="btn_admin_ia", use_container_width=True):
                close_all_modals()
                st.session_state.show_ia_config = True
                st.rerun()
            st.markdown('---')

        if st.button("🚪 Logout", key="btn_logout", use_container_width=True):
            logger.info(f"Logout: {st.session_state.get('username', 'unknown')}")
            close_all_modals()
            # Limpa apenas o necessário para logout
            for key in [
                'authenticated', 'username', 'user_info', 'user_manager', 'user_rag',
                'messages', 'show_user_management', 'show_user_stats',
                'show_document_management', 'show_ia_config', 'edit_user', 'active_user_tab',
                'form_key', 'user_updated_message', 'user_deleted_message', 'processando_ia'
            ]:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

def user_management_modal():
    """Modal para gerenciamento de usuários (apenas admins)"""
    if st.session_state.get('show_user_management', False):
        # Cabeçalho com botão de fechar
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("# 👥 Gerenciamento de Usuários")
        with col2:
            if st.button("❌ Fechar", key="close_users_header", use_container_width=True):
                logger.info(f"[MODAL] Gerenciamento de usuários fechado por {st.session_state.username}")
                close_all_modals()
                st.rerun()
        
        st.markdown("---")
        
        user_manager = st.session_state.get('user_manager')
        if not user_manager:
            st.error("❌ Gerenciador de usuários não disponível")
            return
        
        # Tabs para diferentes funcionalidades
        tab_names = ["📋 Lista de Usuários", "➕ Criar Usuário", "✏️ Editar Usuário", "📊 Estatísticas"]
        
        # Cria as tabs
        tabs = st.tabs(tab_names)
        
        with tabs[0]:  # Lista de Usuários
            st.markdown("#### 📋 Usuários Cadastrados")
            
            # Mostra mensagem de sucesso se houver
            if 'user_updated_message' in st.session_state:
                st.success(st.session_state.user_updated_message)
                del st.session_state.user_updated_message
            
            if 'user_deleted_message' in st.session_state:
                st.success(st.session_state.user_deleted_message)
                del st.session_state.user_deleted_message
            
            # Lista todos os usuários
            users = user_manager.users
            if users:
                for username, user_data in users.items():
                    with st.expander(f"👤 {user_data.get('name', username)} (@{username})"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Nome:** {user_data.get('name', 'N/A')}")
                            st.write(f"**Tipo:** {user_data.get('role', 'N/A')}")
                            st.write(f"**Organização:** {user_data.get('organization', 'N/A')}")
                        
                        with col2:
                            # Botões de ação
                            col_edit, col_delete = st.columns(2)
                            with col_edit:
                                if st.button(f"✏️ Editar", key=f"edit_{username}"):
                                    st.session_state.edit_user = username
                                    st.session_state.active_user_tab = 2  # Vai para aba de edição
                                    st.rerun()
                            
                            with col_delete:
                                if username != st.session_state.username:  # Não pode deletar a si mesmo
                                    if st.button(f"🗑️ Excluir", key=f"delete_{username}"):
                                        # Remove usuário
                                        del user_manager.users[username]
                                        user_manager.save_users()
                                        
                                        # Remove dados da pasta production_users
                                        import shutil
                                        user_dir = Path(f"production_users/{username}")
                                        if user_dir.exists():
                                            try:
                                                shutil.rmtree(user_dir)
                                                logger.info(f"[ADMIN] Dados da pasta removidos para {username}")
                                            except Exception as e:
                                                logger.error(f"[ADMIN] Erro ao remover pasta {user_dir}: {e}")
                                        
                                        logger.info(f"[ADMIN] Usuário {username} excluído por {st.session_state.username}")
                                        st.session_state.user_deleted_message = f"✅ Usuário '{username}' excluído com sucesso!"
                                        st.rerun()
            else:
                st.info("Nenhum usuário cadastrado.")
        
        with tabs[1]:  # Criar Usuário
            st.markdown("#### ➕ Criar Novo Usuário")
            
            # Key dinâmica para forçar limpeza dos campos
            form_key = f"create_user_form_{st.session_state.get('form_key', 0)}"
            
            with st.form(form_key):
                col1, col2 = st.columns(2)
                
                with col1:
                    new_username = st.text_input("👤 Nome de usuário", help="Nome único para login")
                    new_name = st.text_input("📛 Nome completo")
                    new_password = st.text_input("🔒 Senha", type="password")
                
                with col2:
                    new_role = st.selectbox("🎭 Tipo", ["Admin", "Usuário"])
                    new_organization = st.text_input("🏢 Organização")
                
                if st.form_submit_button("➕ Criar Usuário", use_container_width=True):
                    if new_username and new_name and new_password:
                        if new_username not in user_manager.users:
                            # Cria usuário
                            user_manager.users[new_username] = {
                                "password_hash": user_manager.hash_password(new_password),
                                "name": new_name,
                                "role": new_role,
                                "organization": new_organization,
                                "created_at": get_sao_paulo_time().isoformat(),
                                "last_login": "",
                                "total_conversations": 0,
                                "successful_queries": 0,
                                "failed_queries": 0,
                                "active": True,
                                "notes": ""
                            }
                            
                            # Salva
                            user_manager.save_users()
                            logger.info(f"[ADMIN] Novo usuário {new_username} criado por {st.session_state.username}")
                            
                            # Mostra sucesso imediatamente na aba atual
                            st.success(f"✅ Usuário '{new_username}' criado com sucesso!")
                            
                            # Força recriação do formulário para limpar campos
                            if 'form_key' in st.session_state:
                                st.session_state.form_key += 1
                            else:
                                st.session_state.form_key = 1
                            
                            # Pequeno delay para usuário ver a mensagem antes de limpar
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Nome de usuário já existe!")
                    else:
                        st.error("❌ Preencha todos os campos obrigatórios!")
        
        with tabs[2]:  # Editar Usuário
            st.markdown("#### ✏️ Editar Usuário")
            
            if st.session_state.get('edit_user'):
                edit_username = st.session_state.edit_user
                edit_user_data = user_manager.users.get(edit_username, {})
                
                st.info(f"Editando usuário: **{edit_username}**")
                
                with st.form("edit_user_form"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        edit_name = st.text_input("📛 Nome completo", value=edit_user_data.get('name', ''))
                        edit_new_password = st.text_input("🔒 Nova senha (deixe vazio para manter atual)", type="password")
                    
                    with col2:
                        edit_role = st.selectbox("🎭 Tipo", ["Admin", "Usuário"], 
                                                index=["Admin", "Usuário"].index(edit_user_data.get('role', 'Usuário')))
                        edit_organization = st.text_input("🏢 Organização", value=edit_user_data.get('organization', ''))
                    
                    col_save, col_cancel = st.columns(2)
                    
                    with col_save:
                        if st.form_submit_button("💾 Salvar Alterações", use_container_width=True):
                            # Atualiza dados
                            user_manager.users[edit_username]['name'] = edit_name
                            user_manager.users[edit_username]['role'] = edit_role
                            user_manager.users[edit_username]['organization'] = edit_organization
                            
                            # Atualiza senha se fornecida
                            if edit_new_password:
                                user_manager.users[edit_username]['password_hash'] = user_manager.hash_password(edit_new_password)
                            
                            # Salva
                            user_manager.save_users()
                            logger.info(f"[ADMIN] Usuário {edit_username} editado por {st.session_state.username}")
                            
                            # Mostra sucesso imediatamente na aba atual
                            st.success(f"✅ Usuário '{edit_username}' atualizado com sucesso!")
                            
                            # Define mensagem para mostrar na listagem também
                            st.session_state.user_updated_message = f"✅ Usuário '{edit_username}' atualizado com sucesso!"
                            st.session_state.active_user_tab = 0  # Volta para aba de listagem
                            del st.session_state.edit_user
                            
                            # Pequeno delay para usuário ver a mensagem
                            time.sleep(1)
                            st.rerun()
                    
                    with col_cancel:
                        if st.form_submit_button("❌ Cancelar", use_container_width=True):
                            del st.session_state.edit_user
                            st.rerun()
            else:
                st.info("Selecione um usuário na aba 'Lista de Usuários' para editar.")
        
        with tabs[3]:  # Estatísticas
            st.markdown("#### 📊 Estatísticas de Uso")
            
            # Estatísticas gerais
            total_users = len(user_manager.users)
            roles_count = {}
            
            for user_data in user_manager.users.values():
                role = user_data.get('role', 'Não definido')
                roles_count[role] = roles_count.get(role, 0) + 1
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("👥 Total de Usuários", total_users)
            
            with col2:
                st.metric("🛠️ Administradores", roles_count.get('Admin', 0))
            
            with col3:
                st.metric("👤 Usuários", roles_count.get('Usuário', 0))
            
            # Estatísticas por usuário
            st.markdown("##### 📈 Atividade por Usuário")
            
            # Carrega estatísticas de todos os usuários
            users_stats = []
            for username in user_manager.users.keys():
                user_stats_file = Path(f"production_users/{username}/user_stats.json")
                if user_stats_file.exists():
                    try:
                        with open(user_stats_file, 'r', encoding='utf-8') as f:
                            stats = json.load(f)
                            stats['username'] = username
                            stats['name'] = user_manager.users[username].get('name', username)
                            users_stats.append(stats)
                    except:
                        pass
            
            if users_stats:
                # Ordena por atividade
                users_stats.sort(key=lambda x: x.get('total_questions', 0), reverse=True)
                
                for stats in users_stats:
                    with st.expander(f"📊 {stats['name']} (@{stats['username']})"):
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("❓ Perguntas", stats.get('total_questions', 0))
                        
                        with col2:
                            st.metric("✅ Sucessos", stats.get('successful_answers', 0))
                        
                        with col4:
                            success_rate = 0
                            if stats.get('total_questions', 0) > 0:
                                success_rate = (stats.get('successful_answers', 0) / stats.get('total_questions', 1)) * 100
                            st.metric("📈 Taxa Sucesso", f"{success_rate:.1f}%")
                        
                        # Última atividade
                        if stats.get('last_activity'):
                            try:
                                last_activity = datetime.fromisoformat(stats['last_activity'])
                                st.caption(f"🕐 Última atividade: {last_activity.strftime('%d/%m/%Y %H:%M')}")
                            except:
                                st.caption("🕐 Última atividade: Não disponível")
            else:
                st.info("Nenhuma estatística de uso disponível ainda.")

def document_management_modal():
    """Modal para gerenciamento de documentos (apenas admins)"""
    if st.session_state.get('show_document_management', False):
        # Cabeçalho com botão de fechar
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("# 📄 Gerenciamento de Documentos")
        with col2:
            if st.button("❌ Fechar", key="close_documents_header", use_container_width=True):
                logger.info(f"[MODAL] Gerenciamento de documentos fechado por {st.session_state.username}")
                close_all_modals()
                st.rerun()
        st.markdown("---")
        # Tabs para funcionalidades (incluindo configurações do banco)
        tab_names = ["📤 Upload/Indexar", "📋 Documentos Indexados", "⚙️ Configurações"]
        tabs = st.tabs(tab_names)
        with tabs[0]:  # Upload/Indexar
            st.markdown("#### 📤 Adicionar Novo Documento")
            
            # Opções de entrada
            input_method = st.radio(
                "Método de entrada:",
                ["🔗 URL do PDF", "📎 Upload de arquivo"],
                help="Escolha como fornecer o documento para indexação"
            )
            
            if input_method == "🔗 URL do PDF":
                # Lógica de limpeza de campos
                if st.session_state.get("clear_url_field", False):
                    st.session_state.clear_url_field = False
                    st.session_state.pdf_url_input = ""

                def validate_url(url):
                    if not url:
                        return None
                    if url.lower().endswith('.pdf') or 'arxiv.org/pdf/' in url:
                        st.success("✅ URL válida detectada!")
                        return True
                    else:
                        st.warning("⚠️ A URL pode não ser um PDF válido. Prossiga com cuidado.")
                        return False

                pdf_url = st.text_input(
                    "URL do documento PDF:",
                    key="pdf_url_input",
                    placeholder="https://arxiv.org/pdf/2501.13956",
                    help="Cole aqui o link direto para o arquivo PDF",
                    on_change=validate_url,
                    args=(st.session_state.get("pdf_url_input", ""),)
                )
                
                # Validação inicial se já houver URL
                if pdf_url:
                    validate_url(pdf_url)
                
                source_type = "url"
                source_value = pdf_url
            
            else:  # Upload de arquivo
                # Lógica de limpeza para upload
                upload_key = "pdf_uploader"
                if st.session_state.get('clear_upload_field', False):
                    st.session_state.clear_upload_field = False
                    if upload_key in st.session_state:
                        del st.session_state[upload_key]
                    upload_key = f"pdf_uploader_{hash(str(st.session_state.get('upload_counter', 0)))}"
                    st.session_state.upload_counter = st.session_state.get('upload_counter', 0) + 1
                
                uploaded_file = st.file_uploader(
                    "Escolha um arquivo PDF:",
                    type=['pdf'],
                    help="Selecione um arquivo PDF do seu computador",
                    key=upload_key
                )
                
                if uploaded_file:
                    st.success(f"✅ Arquivo carregado: {uploaded_file.name} ({uploaded_file.size} bytes)")
                
                source_type = "upload"
                source_value = uploaded_file
            
            # Configuração automática: sempre substitui documentos existentes
            
            # Botão de indexação
            st.markdown("---")
            
            can_index = (source_type == "url" and source_value) or (source_type == "upload" and source_value is not None)
            
            if st.button("🚀 Iniciar Indexação", disabled=not can_index, use_container_width=True):
                if can_index:
                    try:
                        st.info("🔄 Iniciando processo de indexação...")
                        
                        # Cria container para logs em tempo real
                        progress_container = st.container()
                        log_container = st.container()
                        
                        with progress_container:
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                        
                        with log_container:
                            log_area = st.empty()
                        
                        # Processa o arquivo real
                        if source_type == "upload":
                            # Salva arquivo temporário para upload
                            import subprocess
                            import sys
                            temp_pdf_path = None
                            result = None  # Inicializa result como None
                            
                            try:
                                # Obtém o diretório atual do workspace
                                current_dir = os.path.dirname(os.path.abspath(__file__))
                                
                                # Obtém o nome original do arquivo
                                original_filename = source_value.name
                                # Remove extensão .pdf se existir
                                base_filename = os.path.splitext(original_filename)[0]
                                # Substitui espaços por underscores e remove caracteres especiais
                                safe_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', base_filename)
                                
                                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', prefix=f'temp_{safe_filename}_') as tmp_file:
                                    tmp_file.write(source_value.getvalue())
                                    temp_pdf_path = tmp_file.name
                                
                                logger.info(f"[INDEXING] Arquivo temporário criado: {temp_pdf_path}")
                                status_text.text("📥 Processando arquivo PDF...")
                                progress_bar.progress(20)
                                
                                # Prepara ambiente com todas as variáveis necessárias
                                env = os.environ.copy()
                                env['PDF_URL'] = temp_pdf_path
                                # Adiciona o nome original do arquivo como variável de ambiente
                                env['ORIGINAL_FILENAME'] = safe_filename
                                
                                # Garante que todas as variáveis do Astra DB estão presentes
                                required_env_vars = [
                                    'VOYAGE_API_KEY', 'ASTRA_DB_API_ENDPOINT', 'ASTRA_DB_APPLICATION_TOKEN'
                                ]
                                missing_vars = [var for var in required_env_vars if not env.get(var)]
                                if missing_vars:
                                    st.error(f"❌ Variáveis de ambiente faltando: {', '.join(missing_vars)}")
                                    return
                                
                                status_text.text("🖼️ Extraindo imagens e texto...")
                                progress_bar.progress(50)
                                
                                logger.info(f"[INDEXING] Executando indexador com arquivo: {temp_pdf_path}")
                                
                                result = subprocess.run([
                                    sys.executable, "-u", "indexador.py"
                                ], 
                                env=env, 
                                capture_output=True, 
                                text=True, 
                                cwd=current_dir,  # Usa o diretório atual do script
                                timeout=300)
                                
                                logger.info(f"[INDEXING] Indexador finalizado com código: {result.returncode}")
                                if result.stdout:
                                    logger.info(f"[INDEXING] STDOUT: {result.stdout}")
                                if result.stderr:
                                    logger.warning(f"[INDEXING] STDERR: {result.stderr}")
                                
                                if result.returncode == 0:
                                    status_text.text("✅ Indexação concluída com sucesso!")
                                    progress_bar.progress(100)
                                    st.success("🎉 Documento indexado com sucesso!")
                                    st.info("📊 O documento já está disponível para consultas no sistema RAG.")
                                    # Mostra log de sucesso se houver
                                    if result.stdout:
                                        with st.expander("📄 Ver detalhes da indexação"):
                                            st.text(result.stdout)
                                else:
                                    st.error(f"❌ Erro na indexação (código {result.returncode})")
                                    if result.stderr:
                                        st.error(f"**Erro detalhado:** {result.stderr}")
                                    if result.stdout:
                                        st.text(f"**Saída do processo:** {result.stdout}")
                                    
                            except subprocess.TimeoutExpired as e:
                                st.error("❌ Timeout na indexação (5 minutos). Documento muito grande ou processamento lento.")
                                logger.error(f"[INDEXING] Timeout: {str(e)}")
                            except Exception as e:
                                logger.error(f"[INDEXING] Erro durante indexação: {e}")
                                st.error(f"❌ Erro durante indexação: {e}")
                                # Mostra stderr se disponível
                                if result and hasattr(result, 'stderr') and result.stderr:
                                    st.error(f"**Erro detalhado:** {result.stderr}")
                                if result and hasattr(result, 'stdout') and result.stdout:
                                    st.text(f"**Saída do processo:** {result.stdout}")
                            finally:
                                # Remove arquivo temporário se ainda existir
                                if temp_pdf_path and os.path.exists(temp_pdf_path):
                                    try:
                                        os.remove(temp_pdf_path)
                                        logger.info(f"[INDEXING] Arquivo temporário removido: {temp_pdf_path}")
                                    except Exception as e:
                                        logger.warning(f"[INDEXING] Erro ao remover arquivo temporário: {e}")
                        else:
                            # URL processing real
                            import subprocess
                            import sys
                            
                            status_text.text("📥 Baixando PDF da URL...")
                            progress_bar.progress(20)
                            
                            # Prepara ambiente com todas as variáveis necessárias
                            env = os.environ.copy()
                            env['PDF_URL'] = source_value
                            
                            # Garante que todas as variáveis do Astra DB estão presentes
                            required_env_vars = [
                                'VOYAGE_API_KEY', 'ASTRA_DB_API_ENDPOINT', 'ASTRA_DB_APPLICATION_TOKEN'
                            ]
                            missing_vars = [var for var in required_env_vars if not env.get(var)]
                            if missing_vars:
                                st.error(f"❌ Variáveis de ambiente faltando: {', '.join(missing_vars)}")
                                return
                            
                            status_text.text("🖼️ Extraindo imagens e texto...")
                            progress_bar.progress(50)
                            
                            logger.info(f"[INDEXING] Executando indexador com URL: {source_value}")
                            
                            # Inicializa result como None para evitar erro de variável não definida
                            result = None
                            
                            try:
                                # Obtém o diretório atual do workspace
                                current_dir = os.path.dirname(os.path.abspath(__file__))
                                
                                result = subprocess.run([
                                    sys.executable, "-u", "indexador.py"
                                ], 
                                env=env, 
                                capture_output=True, 
                                text=True, 
                                cwd=current_dir,  # Usa o diretório atual do script
                                timeout=600)
                                
                                logger.info(f"[INDEXING] Indexador finalizado com código: {result.returncode}")
                                if result.stdout:
                                    logger.info(f"[INDEXING] STDOUT: {result.stdout}")
                                if result.stderr:
                                    logger.warning(f"[INDEXING] STDERR: {result.stderr}")
                                
                                if result.returncode == 0:
                                    status_text.text("✅ Indexação concluída com sucesso!")
                                    progress_bar.progress(100)
                                    st.success("🎉 Documento indexado com sucesso!")
                                    st.info("📊 O documento já está disponível para consultas no sistema RAG.")
                                    # Mostra log de sucesso se houver
                                    if result.stdout:
                                        with st.expander("📄 Ver detalhes da indexação"):
                                            st.text(result.stdout)
                                else:
                                    st.error(f"❌ Erro na indexação (código {result.returncode})")
                                    if result.stderr:
                                        st.error(f"**Erro detalhado:** {result.stderr}")
                                    if result.stdout:
                                        st.text(f"**Saída do processo:** {result.stdout}")
                                        
                            except subprocess.TimeoutExpired as e:
                                st.error("❌ Timeout na indexação (10 minutos). URL inacessível ou processamento muito lento.")
                                logger.error(f"[INDEXING] Timeout: {str(e)}")
                            except Exception as e:
                                logger.error(f"[INDEXING] Erro durante indexação: {e}")
                                st.error(f"❌ Erro durante indexação: {e}")
                                # Mostra stderr se disponível
                                if result and hasattr(result, 'stderr') and result.stderr:
                                    st.error(f"**Erro detalhado:** {result.stderr}")
                                if result and hasattr(result, 'stdout') and result.stdout:
                                    st.text(f"**Saída do processo:** {result.stdout}")
                        
                        # Log da indexação
                        logger.info(f"[ADMIN] Documento indexado por {st.session_state.username}: {source_type}={str(source_value)[:100]}")
                        
                        # Automaticamente força limpeza dos campos após sucesso
                        if result.returncode == 0:
                            # Limpa o session state relacionado aos campos
                            if source_type == "url":
                                st.session_state.clear_url_field = True
                            else:
                                st.session_state.clear_upload_field = True
                            
                        # Mostra botão para limpar campos e atualizar lista
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("🔄 Limpar campos", key="clear_fields", use_container_width=True):
                                # Força limpeza dos campos
                                st.session_state.clear_url_field = True
                                st.session_state.clear_upload_field = True
                                st.rerun()
                        with col2:
                            if st.button("📋 Atualizar lista", key="refresh_docs_list", use_container_width=True):
                                st.rerun()
                        
                    except Exception as e:
                        st.error(f"❌ Erro durante a indexação: {e}")
                        logger.error(f"[ADMIN] Erro na indexação por {st.session_state.username}: {e}")
                        # Mostra stderr do processo para debug
                        if 'result' in locals() and hasattr(result, 'stderr') and result.stderr:
                            st.error(f"Erro detalhado: {result.stderr}")
                        if 'result' in locals() and hasattr(result, 'stdout') and result.stdout:
                            st.info(f"Saída do processo: {result.stdout}")
                else:
                    st.warning("⚠️ Forneça uma URL válida ou faça upload de um arquivo antes de indexar.")
        
        with tabs[1]:  # Documentos Indexados
            st.markdown("#### 📋 Documentos Atualmente Indexados")
            
            # Botão para atualizar lista manualmente
            if st.button("🔄 Atualizar Lista", key="refresh_docs"):
                st.rerun()
            
            try:
                # Busca documentos reais no Astra DB
                from astrapy import DataAPIClient
                endpoint = os.getenv("ASTRA_DB_API_ENDPOINT")
                token = os.getenv("ASTRA_DB_APPLICATION_TOKEN")
                
                if endpoint and token:
                    client = DataAPIClient(token)
                    database = client.get_database(endpoint)
                    collection = database.get_collection("pdf_documents")
                    
                    # Busca documentos únicos pela fonte
                    try:
                        documents = collection.distinct("doc_source")
                    except Exception as e:
                        # Fallback: busca alguns documentos e extrai sources únicos
                        st.warning(f"⚠️ Usando método alternativo para listar documentos: {e}")
                        docs = collection.find({}, limit=100)
                        sources = set()
                        for doc in docs:
                            if 'doc_source' in doc:
                                sources.add(doc['doc_source'])
                        documents = list(sources)
                    
                    if documents:
                        st.markdown("##### 📚 Documentos Indexados:")
                        
                        for doc_source in documents:
                            if doc_source:
                                # Extrai nome do documento
                                doc_name = doc_source.split("/")[-1] if "/" in doc_source else doc_source
                                
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.write(f"📄 **{doc_name}**")
                                
                                with col2:
                                    # Botão de remover com confirmação
                                    delete_key = f"remove_{hash(doc_source)}"
                                    confirm_key = f"confirm_delete_{hash(doc_source)}"
                                    cancel_key = f"cancel_delete_{hash(doc_source)}"
                                    
                                    # Se não estiver em modo de confirmação
                                    if not st.session_state.get(confirm_key, False):
                                        if st.button("🗑️ Remover", key=delete_key, use_container_width=True):
                                            st.session_state[confirm_key] = True
                                            st.rerun()
                                    else:
                                        # Modo de confirmação
                                        st.warning("⚠️ Clique novamente para confirmar a remoção.")
                                        
                                        col_confirm, col_cancel = st.columns(2)
                                        with col_confirm:
                                            if st.button("✅ Confirmar", key=f"confirm_{delete_key}", use_container_width=True):
                                                try:
                                                    # Remove todos os chunks relacionados ao documento
                                                    result = collection.delete_many({"doc_source": doc_source})
                                                    
                                                    # Remove imagens relacionadas
                                                    import glob
                                                    pdf_images_dir = "pdf_images"
                                                    if os.path.exists(pdf_images_dir):
                                                        doc_base_name = doc_name.replace(".pdf", "").replace(" ", "_")
                                                        for img_file in glob.glob(f"{pdf_images_dir}/*{doc_base_name}*"):
                                                            try:
                                                                os.remove(img_file)
                                                            except:
                                                                pass
                                                    
                                                    st.success(f"✅ Documento '{doc_name}' removido! {result.deleted_count} chunks excluídos.")
                                                    # Limpa o estado de confirmação
                                                    st.session_state[confirm_key] = False
                                                    # Aguarda um pouco para que o usuário veja a mensagem
                                                    time.sleep(2)
                                                    st.rerun()
                                                    
                                                except Exception as e:
                                                    st.error(f"❌ Erro ao remover documento: {str(e)}")
                                                    st.session_state[confirm_key] = False
                                        
                                        with col_cancel:
                                            if st.button("❌ Cancelar", key=cancel_key, use_container_width=True):
                                                # Limpa o estado de confirmação
                                                st.session_state[confirm_key] = False
                                                st.rerun()
                    else:
                        st.info("📄 Nenhum documento indexado encontrado.")
                else:
                    st.warning("⚠️ Configurações do Astra DB não encontradas.")
                    
            except Exception as e:
                st.error(f"❌ Erro ao carregar documentos: {str(e)}")

        with tabs[2]:  # Configurações do Banco
            st.markdown("#### ⚙️ Configurações de Conexão com o Banco de Dados")
            with st.form("db_config_form"):
                current_endpoint = os.getenv("ASTRA_DB_API_ENDPOINT", "")
                new_endpoint = st.text_input(
                    "Endpoint do Astra DB:",
                    value=current_endpoint,
                    help="URL do endpoint do Astra DB (ex: https://db-id.us-east-1.apps.astra.datastax.com)",
                    key="db_endpoint_input"
                )
                current_token = os.getenv("ASTRA_DB_APPLICATION_TOKEN", "")
                new_token = st.text_input(
                    "Token de Aplicação:",
                    value=current_token,
                    type="password",
                    help="Token de autenticação do Astra DB",
                    key="db_token_input"
                )
                if st.form_submit_button("💾 Salvar Configurações", use_container_width=True):
                    try:
                        if new_endpoint != current_endpoint:
                            set_env_var("ASTRA_DB_API_ENDPOINT", new_endpoint)
                            logger.info(f"[CONFIG] Endpoint do Astra DB atualizado")
                        if new_token != current_token:
                            set_env_var("ASTRA_DB_APPLICATION_TOKEN", new_token)
                            logger.info("[CONFIG] Token do Astra DB atualizado")
                        st.success("✅ Configurações salvas!")
                    except Exception as e:
                        st.error(f"❌ Erro ao salvar configurações: {str(e)}")
                        logger.error(f"[CONFIG] Erro ao salvar configurações: {e}")
            if st.button("🔗 Testar Conexão", use_container_width=True):
                try:
                    from astrapy import DataAPIClient
                    endpoint = os.getenv("ASTRA_DB_API_ENDPOINT")
                    token = os.getenv("ASTRA_DB_APPLICATION_TOKEN")
                    if not endpoint or not token:
                        st.warning("⚠️ Configure o endpoint e token primeiro")
                    else:
                        client = DataAPIClient()
                        database = client.get_database(endpoint, token=token)
                        collection = database.get_collection("pdf_documents")
                        list(collection.find({}, limit=1))
                        st.success("✅ Conexão com Astra DB estabelecida!")
                except Exception as e:
                    st.error(f"❌ Erro de conexão: {e}")

def user_stats_modal():
    """Modal para exibir estatísticas pessoais do usuário"""
    if st.session_state.get('show_user_stats', False):
        # Cabeçalho com botão de fechar
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("# 📊 Minhas Estatísticas")
        with col2:
            if st.button("❌ Fechar", key="close_user_stats_header", use_container_width=True):
                logger.info(f"[MODAL] Estatísticas pessoais fechadas por {st.session_state.username}")
                close_all_modals()
                st.rerun()
        
        st.markdown("---")
        
        if 'user_rag' in st.session_state:
            try:
                user_stats = st.session_state.user_rag.get_user_stats()
                user_info = st.session_state.get('user_info', {})
                
                # Informações do usuário
                st.markdown("### 👤 Informações do Usuário")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.info(f"**Nome:** {user_info.get('name', 'N/A')}")
                with col2:
                    st.info(f"**Perfil:** {user_info.get('role', 'N/A')}")
                with col3:
                    st.info(f"**Organização:** {user_info.get('organization', 'N/A')}")
                
                st.markdown("---")
                
                # Métricas principais
                st.markdown("### 📈 Atividade no Sistema")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        label="❓ Total de Perguntas",
                        value=user_stats.get("total_questions", 0),
                        help="Número total de perguntas feitas ao sistema"
                    )
                
                with col2:
                    st.metric(
                        label="✅ Respostas Bem-sucedidas",
                        value=user_stats.get("successful_answers", 0),
                        help="Perguntas que resultaram em respostas satisfatórias"
                    )
                
                with col4:
                    # Taxa de sucesso
                    success_rate = 0
                    if user_stats.get("total_questions", 0) > 0:
                        success_rate = (user_stats.get("successful_answers", 0) / user_stats.get("total_questions", 1)) * 100
                    
                    st.metric(
                        label="📈 Taxa de Sucesso",
                        value=f"{success_rate:.1f}%",
                        help="Percentual de perguntas com respostas bem-sucedidas"
                    )
                
                st.markdown("---")
                
                # Informações temporais
                st.markdown("### 🕐 Histórico de Uso")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if user_stats.get('first_login'):
                        try:
                            first_login = datetime.fromisoformat(user_stats['first_login'])
                            st.info(f"**Primeiro acesso:** {first_login.strftime('%d/%m/%Y %H:%M')}")
                        except:
                            st.info("**Primeiro acesso:** Não disponível")
                    else:
                        st.info("**Primeiro acesso:** Não disponível")
                
                with col2:
                    if user_stats.get('last_activity'):
                        try:
                            last_activity = datetime.fromisoformat(user_stats['last_activity'])
                            st.info(f"**Última atividade:** {last_activity.strftime('%d/%m/%Y %H:%M')}")
                        except:
                            st.info("**Última atividade:** Não disponível")
                    else:
                        st.info("**Última atividade:** Não disponível")
                
                # Análise de performance
                if user_stats.get("total_questions", 0) > 0:
                    st.markdown("---")
                    st.markdown("### 📊 Análise de Performance")
                    
                    # Barra de progresso para taxa de sucesso
                    st.markdown("**Taxa de Sucesso:**")
                    st.progress(success_rate / 100)
                    
                    # Insights
                    if success_rate >= 90:
                        st.success("🎯 **Excelente!** Você está obtendo ótimos resultados!")
                    elif success_rate >= 70:
                        st.info("👍 **Bom trabalho!** Continue assim.")
                    elif success_rate >= 50:
                        st.warning("⚠️ **Pode melhorar.** Tente perguntas mais específicas.")
                    else:
                        st.error("🔄 **Vamos melhorar!** Experimente reformular suas perguntas.")
                
                else:
                    st.info("📝 **Primeira vez?** Faça algumas perguntas para ver suas estatísticas aqui!")
                    
            except Exception as e:
                logger.error(f"Erro ao exibir estatísticas pessoais: {e}")
                st.error("❌ Erro ao carregar suas estatísticas. Tente novamente.")

def ia_config_modal():
    """Modal central para configurações de IA"""
    if st.session_state.get('show_ia_config', False):
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("# 🤖 Configurações de IA")
        with col2:
            if st.button("❌ Fechar", key="close_ia_config", use_container_width=True):
                st.session_state.show_ia_config = False
                st.rerun()
        st.markdown("---")
        with st.form('ia_api_config_form'):
            current_openai_key = os.getenv('OPENAI_API_KEY', '')
            new_openai_key = st.text_input(
                'OpenAI API Key:',
                value=current_openai_key,
                type='password',
                help='Chave de API da OpenAI para geração de texto',
                key='openai_key_input'
            )
            current_voyage_key = os.getenv('VOYAGE_API_KEY', '')
            new_voyage_key = st.text_input(
                'Voyage API Key:',
                value=current_voyage_key,
                type='password',
                help='Chave de API da Voyage AI para embeddings',
                key='voyage_key_input'
            )
            if st.form_submit_button('💾 Salvar Chaves de API', use_container_width=True):
                try:
                    if new_openai_key != current_openai_key:
                        set_env_var('OPENAI_API_KEY', new_openai_key)
                        logger.info('[CONFIG] OpenAI API Key atualizada')
                    if new_voyage_key != current_voyage_key:
                        set_env_var('VOYAGE_API_KEY', new_voyage_key)
                        logger.info('[CONFIG] Voyage API Key atualizada')
                    st.success('✅ Chaves de API salvas!')
                except Exception as e:
                    st.error(f'❌ Erro ao salvar chaves: {str(e)}')
                    logger.error(f'[CONFIG] Erro ao salvar chaves: {e}')

def set_env_var(key: str, value: str, env_path: str = ".env"):
    """Atualiza ou adiciona uma variável no arquivo .env e no ambiente do processo."""
    env_file = Path(env_path)
    lines = []
    found = False
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith(f"{key}="):
                    lines.append(f"{key}={value}\n")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_file, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    os.environ[key] = value
    load_dotenv(override=True)

def chat_interface():
    """Interface de chat com sincronização corrigida"""
    if not (
        st.session_state.get('show_user_management', False) or
        st.session_state.get('show_user_stats', False) or
        st.session_state.get('show_document_management', False) or
        st.session_state.get('show_ia_config', False)
    ):
        st.title("🚀 RAG Conversacional")
    
    # Inicialização do sistema RAG
    if 'user_rag' not in st.session_state:
        with st.spinner("Inicializando sistema RAG...", show_time=True):
            try:
                st.session_state.user_rag = ProductionStreamlitRAG(st.session_state.username)
                st.success("✅ Sistema inicializado com sucesso!")
            except Exception as e:
                st.error(f"❌ Erro na inicialização: {e}")
                st.stop()
    
    # Carregamento inicial do histórico (apenas uma vez)
    if "messages" not in st.session_state:
        try:
            # Carrega histórico salvo do backend
            history = st.session_state.user_rag.get_chat_history()
            st.session_state.messages = history.copy() if history else []
            logger.info(f"[CHAT] Histórico carregado: {len(st.session_state.messages)} mensagens")
        except Exception as e:
            logger.warning(f"[CHAT] Erro ao carregar histórico: {e}")
            st.session_state.messages = []
    
    # Mensagem de boas-vindas se não houver histórico
    if not st.session_state.messages:
        user_name = st.session_state.user_info.get('name', 'usuário')
        st.markdown(f"""
        👋 Olá, **{user_name}**! Bem-vindo ao sistema RAG.
        
        💡 **Exemplos de perguntas:**
        - "O que é o Zep Graphiti?"
        - "Explique a arquitetura temporal"
        - "Quais são os resultados de performance?"
        
        Faça sua primeira pergunta!
        """)
    
    # Exibe histórico existente
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Input para nova mensagem
    if prompt := st.chat_input("Digite sua pergunta..."):
        logger.info(f"[CHAT] Nova mensagem do usuário {st.session_state.username}: {prompt[:100]}...")
        
        # PASSO 1: Adiciona pergunta do usuário
        user_message = {"role": "user", "content": prompt}
        st.session_state.messages.append(user_message)
        
        # Adiciona ao backend
        if hasattr(st.session_state.rag_instance, 'chat_history'):
            st.session_state.rag_instance.chat_history.append(user_message)
        
        # Exibe pergunta do usuário
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # PASSO 2: Processa resposta
        with st.chat_message("assistant"):
            start_time = time.time()
            try:
                with st.spinner("🧠 Processando com IA...", show_time=True):
                    # Usa o método que não duplica histórico
                    resposta = st.session_state.user_rag.ask_question_only(prompt)
                
                processing_time = time.time() - start_time
                logger.info(f"[CHAT] Resposta processada em {processing_time:.2f}s para {st.session_state.username}")
                logger.debug(f"[CHAT] Resposta: {resposta[:200]}...")
                
                # Exibe resposta
                st.markdown(resposta)
                
                # PASSO 3: Adiciona resposta ao histórico
                assistant_message = {"role": "assistant", "content": resposta}
                st.session_state.messages.append(assistant_message)
                
                # Adiciona ao backend
                if hasattr(st.session_state.rag_instance, 'chat_history'):
                    st.session_state.rag_instance.chat_history.append(assistant_message)
                
                # PASSO 4: Salva histórico (apenas uma vez)
                try:
                    st.session_state.user_rag.save_user_history()
                    logger.debug(f"[CHAT] Histórico salvo com {len(st.session_state.messages)} mensagens")
                except Exception as save_error:
                    logger.error(f"[CHAT] Erro ao salvar histórico: {save_error}")
                
                # Mostra tempo para admins
                if st.session_state.user_info.get('role') == 'Admin':
                    st.caption(f"⏱️ Processado em {processing_time:.2f}s")
                    
            except Exception as e:
                error_time = time.time() - start_time
                error_msg = f"❌ Erro ao processar pergunta: {e}"
                logger.error(f"[CHAT] Erro no chat para {st.session_state.username} após {error_time:.2f}s: {e}", exc_info=True)
                
                # Exibe erro
                st.error(error_msg)
                
                # Adiciona erro ao histórico
                error_message = {"role": "assistant", "content": error_msg}
                st.session_state.messages.append(error_message)
                
                if hasattr(st.session_state.rag_instance, 'chat_history'):
                    st.session_state.rag_instance.chat_history.append(error_message)
                
                # Salva histórico mesmo com erro
                try:
                    st.session_state.user_rag.save_user_history()
                except Exception as save_error:
                    logger.error(f"[CHAT] Erro ao salvar histórico de erro: {save_error}")

def main():
    """Função principal da aplicação"""
    st.markdown("""
    <style>
    .stApp > header {
        background-color: transparent;
    }
    .stApp {
        margin-top: -80px;
    }
    </style>
    """, unsafe_allow_html=True)

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        login_page()
    else:
        sidebar_user_info()
        # Exibe o modal/tela correta conforme o estado
        if st.session_state.get('show_user_management', False):
            user_management_modal()
            return
        if st.session_state.get('show_user_stats', False):
            user_stats_modal()
            return
        if st.session_state.get('show_document_management', False):
            document_management_modal()
            return
        if st.session_state.get('show_ia_config', False):
            ia_config_modal()
            return
        # Se nenhum modal, exibe o chat
        chat_interface()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Erro crítico na aplicação: {e}")
        st.error(f"❌ Erro crítico: {e}")
        st.markdown("**Verifique:**")
        st.markdown("1. Variáveis de ambiente configuradas")
        st.markdown("2. Conexão com Astra DB")
        st.markdown("3. Documentos indexados corretamente")
        st.markdown("4. Dependências instaladas")