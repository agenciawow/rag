# manage_production_users.py

import json
import hashlib
import secrets
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import sys
import shutil

def get_sao_paulo_time():
    """Retorna datetime atual no fuso horário de São Paulo"""
    return datetime.now(ZoneInfo("America/Sao_Paulo"))

class ProductionUserManager:
    """Gerenciador de usuários para o sistema RAG"""
    
    def __init__(self, users_file="production_users.json"):
        self.users_file = Path(users_file)
        self.users = self.load_users()
        self.salt = "streamlit_rag_production_2025"  # Salt do sistema
        
        # Apenas dois tipos de usuários
        self.available_roles = ["Admin", "Usuário"]
    
    def load_users(self):
        """Carrega usuários do arquivo"""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"❌ Erro ao carregar usuários: {e}")
                return {}
        return {}
    
    def save_users(self):
        """Salva usuários no arquivo"""
        try:
            # Backup do arquivo atual
            if self.users_file.exists():
                backup_file = self.users_file.with_suffix('.json.backup')
                shutil.copy2(self.users_file, backup_file)
            
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ Erro ao salvar usuários: {e}")
            return False
    
    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Valida força da senha"""
        if len(password) < 8:
            return False, "Senha deve ter pelo menos 8 caracteres"
        
        if not re.search(r'[A-Z]', password):
            return False, "Senha deve conter pelo menos uma letra maiúscula"
        
        if not re.search(r'[a-z]', password):
            return False, "Senha deve conter pelo menos uma letra minúscula"
        
        if not re.search(r'\d', password):
            return False, "Senha deve conter pelo menos um número"
        
        # Verifica senhas comuns
        weak_passwords = [
            'password', '123456', '12345678', 'admin', 'qwerty',
            'password123', 'admin123', '123456789', 'senha123'
        ]
        if password.lower() in weak_passwords:
            return False, "Senha muito comum, escolha outra"
        
        return True, "Senha válida"
    
    def hash_password(self, password: str) -> str:
        """Cria hash seguro da senha com salt aleatório"""
        # Gera salt aleatório
        salt = secrets.token_hex(32)
        
        # PBKDF2 com 100.000 iterações
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return f"pbkdf2_sha256$100000${salt}${password_hash.hex()}"
    
    def add_user(self, username: str, name: str, password: str, role: str = "Usuário", 
                 organization: str = ""):
        """Adiciona novo usuário"""
        if username in self.users:
            return False, "Usuário já existe!"
        
        if len(username) < 3:
            return False, "Nome de usuário deve ter pelo menos 3 caracteres!"
        
        # Valida força da senha
        is_valid, message = self._validate_password_strength(password)
        if not is_valid:
            return False, message
        
        # Valida role
        if role not in self.available_roles:
            role = "Usuário"
        
        self.users[username] = {
            "password_hash": self.hash_password(password),
            "name": name,
            "role": role,
            "organization": organization,
            "created_at": get_sao_paulo_time().isoformat(),
            "last_login": "",
            "total_conversations": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "active": True,
            "notes": ""
        }
        
        if self.save_users():
            return True, f"Usuário '{username}' criado com sucesso!"
        else:
            return False, "Erro ao salvar usuário!"
    
    def update_user(self, username: str, **kwargs):
        """Atualiza informações do usuário"""
        if username not in self.users:
            return False, "Usuário não encontrado!"
        
        # Campos que podem ser atualizados
        allowed_fields = ['name', 'role', 'organization', 'active', 'notes']
        
        for field, value in kwargs.items():
            if field in allowed_fields:
                self.users[username][field] = value
            elif field == 'password':
                self.users[username]['password_hash'] = self.hash_password(value)
            elif field == 'role':
                # Valida role
                if value in self.available_roles:
                    self.users[username]['role'] = value
        
        self.users[username]['updated_at'] = get_sao_paulo_time().isoformat()
        
        if self.save_users():
            return True, f"Usuário '{username}' atualizado com sucesso!"
        else:
            return False, "Erro ao atualizar usuário!"
    
    def remove_user(self, username: str):
        """Remove usuário"""
        if username not in self.users:
            return False, "Usuário não encontrado!"
        
        # Não permite remover se for o último admin
        if self.users[username].get('role') == 'Admin':
            admin_count = sum(1 for user in self.users.values() 
                            if user.get('role') == 'Admin' and user.get('active', True))
            if admin_count <= 1:
                return False, "Não é possível remover o último administrador!"
        
        del self.users[username]
        
        if self.save_users():
            # Remove também os dados do usuário
            user_dir = Path(f"production_users/{username}")
            if user_dir.exists():
                try:
                    shutil.rmtree(user_dir)
                    print(f"📁 Dados do usuário removidos: {user_dir}")
                except Exception as e:
                    print(f"⚠️ Erro ao remover dados: {e}")
            
            return True, f"Usuário '{username}' removido com sucesso!"
        else:
            return False, "Erro ao remover usuário!"
    
    def list_users(self, show_inactive=False):
        """Lista todos os usuários"""
        if not self.users:
            print("📋 Nenhum usuário cadastrado.")
            return
        
        users_to_show = self.users
        if not show_inactive:
            users_to_show = {k: v for k, v in self.users.items() if v.get('active', True)}
        
        print("📋 USUÁRIOS CADASTRADOS:")
        print("=" * 100)
        print(f"{'Username':<15} {'Nome':<25} {'Tipo':<15} {'Organização':<20} {'Status':<8}")
        print("-" * 80)
        
        for username, info in users_to_show.items():
            status = "Ativo" if info.get('active', True) else "Inativo"
            org = info.get('organization', 'N/A')[:19]  # Trunca se muito longo
            
            print(f"{username:<15} {info['name']:<25} {info['role']:<15} {org:<20} {status:<8}")
        
        total_shown = len(users_to_show)
        total_all = len(self.users)
        
        if show_inactive:
            print(f"\nTotal: {total_all} usuários")
        else:
            print(f"\nAtivos: {total_shown} | Total: {total_all} usuários")
            if total_all > total_shown:
                print("💡 Use --include-inactive para ver usuários inativos")
    
    def get_user_details(self, username: str):
        """Mostra detalhes de um usuário específico"""
        if username not in self.users:
            print(f"❌ Usuário '{username}' não encontrado!")
            return
        
        user = self.users[username]
        print(f"\n👤 DETALHES DO USUÁRIO: {username}")
        print("=" * 60)
        print(f"Nome: {user['name']}")
        print(f"Perfil: {user['role']}")
        print(f"Organização: {user.get('organization', 'N/A')}")
        print(f"Status: {'Ativo' if user.get('active', True) else 'Inativo'}")
        print(f"Criado em: {user['created_at']}")
        print(f"Último login: {user.get('last_login', 'Nunca')}")
        
        print(f"Tipo: {user['role']}")
        
        # Estatísticas de uso
        print(f"\n📊 Estatísticas de Uso:")
        print(f"  Conversas totais: {user.get('total_conversations', 0)}")
        print(f"  Consultas bem-sucedidas: {user.get('successful_queries', 0)}")
        print(f"  Consultas falhadas: {user.get('failed_queries', 0)}")
        
        # Taxa de sucesso
        total_queries = user.get('successful_queries', 0) + user.get('failed_queries', 0)
        if total_queries > 0:
            success_rate = (user.get('successful_queries', 0) / total_queries) * 100
            print(f"  Taxa de sucesso: {success_rate:.1f}%")
        
        # Notas
        if user.get('notes'):
            print(f"\n📝 Notas: {user['notes']}")
        
        # Verifica dados salvos
        user_dir = Path(f"production_users/{username}")
        if user_dir.exists():
            memory_file = user_dir / "chat_history.json"
            stats_file = user_dir / "user_stats.json"
            
            print(f"\n💾 Dados Salvos:")
            
            if memory_file.exists():
                try:
                    with open(memory_file, 'r') as f:
                        data = json.load(f)
                        print(f"  Histórico: {data.get('total_messages', 0)} mensagens")
                        print(f"  Última atualização: {data.get('last_updated', 'N/A')}")
                except:
                    print("  Histórico: Erro ao ler")
            else:
                print("  Histórico: Nenhum")
            
            if stats_file.exists():
                try:
                    with open(stats_file, 'r') as f:
                        stats = json.load(f)
                        print(f"  Primeira atividade: {stats.get('first_login', 'N/A')}")
                        print(f"  Última atividade: {stats.get('last_activity', 'N/A')}")
                except:
                    print("  Estatísticas: Erro ao ler")
        else:
            print(f"\n💾 Dados Salvos: Nenhum")

def show_menu():
    """Mostra menu principal"""
    print("\n🚀 GERENCIADOR DE USUÁRIOS - SISTEMA RAG")
    print("=" * 60)
    print("1. 👤 Adicionar usuário")
    print("2. 📋 Listar usuários")
    print("3. 🔍 Detalhes do usuário")
    print("4. ✏️  Editar usuário")
    print("5. 🔒 Alterar senha")
    print("6. ❌ Remover usuário")
    print("7. 🔧 Ferramentas")
    print("8. 🚪 Sair")
    print("-" * 60)

def add_user_interactive(manager):
    """Adiciona usuário interativamente"""
    print("\n👤 ADICIONAR NOVO USUÁRIO")
    print("-" * 40)
    
    username = input("Username (login): ").strip()
    name = input("Nome completo: ").strip()
    password = input("Senha: ").strip()
    
    print(f"\nTipos de usuário disponíveis:")
    roles = manager.available_roles
    for i, role in enumerate(roles, 1):
        print(f"{i}. {role}")
    
    role_choice = input(f"Escolha o tipo (1-{len(roles)}): ").strip()
    try:
        role = roles[int(role_choice) - 1]
    except (ValueError, IndexError):
        role = "Usuário"
        print(f"⚠️ Opção inválida, usando tipo padrão: {role}")
    
    organization = input("Organização (opcional): ").strip()
    
    success, message = manager.add_user(username, name, password, role, organization)
    
    if success:
        print(f"✅ {message}")
        
        # Mostra resumo do usuário criado
        user = manager.users[username]
        print(f"\n📋 Resumo do usuário criado:")
        print(f"  Username: {username}")
        print(f"  Nome: {name}")
        print(f"  Tipo: {role}")
    else:
        print(f"❌ {message}")

def edit_user_interactive(manager):
    """Edita usuário interativamente"""
    print("\n✏️ EDITAR USUÁRIO")
    print("-" * 30)
    
    username = input("Username para editar: ").strip()
    
    if username not in manager.users:
        print("❌ Usuário não encontrado!")
        return
    
    user = manager.users[username]
    print(f"\nDados atuais de '{username}':")
    print(f"Nome: {user['name']}")
    print(f"Tipo: {user['role']}")
    print(f"Organização: {user.get('organization', 'N/A')}")
    print(f"Status: {'Ativo' if user.get('active', True) else 'Inativo'}")
    print(f"Notas: {user.get('notes', 'Nenhuma')}")
    
    print("\nDeixe em branco para manter o valor atual:")
    
    new_name = input(f"Novo nome [{user['name']}]: ").strip()
    
    # Tipos
    print(f"\nTipos disponíveis:")
    roles = manager.available_roles
    for i, role in enumerate(roles, 1):
        print(f"{i}. {role}")
    
    current_role_idx = roles.index(user['role']) + 1 if user['role'] in roles else 0
    new_role_input = input(f"Novo tipo [{current_role_idx}={user['role']}]: ").strip()
    
    new_org = input(f"Nova organização [{user.get('organization', 'N/A')}]: ").strip()
    
    new_notes = input(f"Novas notas [{user.get('notes', 'Nenhuma')}]: ").strip()
    
    status_input = input("Ativo? (s/n) [atual: {}]: ".format('s' if user.get('active', True) else 'n')).strip().lower()
    
    # Prepara atualizações
    updates = {}
    
    if new_name:
        updates['name'] = new_name
    
    if new_role_input:
        try:
            role_idx = int(new_role_input) - 1
            if 0 <= role_idx < len(roles):
                updates['role'] = roles[role_idx]
        except ValueError:
            pass
    
    if new_org:
        updates['organization'] = new_org
    
    if new_notes:
        updates['notes'] = new_notes
    
    if status_input in ['s', 'n']:
        updates['active'] = status_input == 's'
    
    if updates:
        success, message = manager.update_user(username, **updates)
        print(f"✅ {message}" if success else f"❌ {message}")
    else:
        print("ℹ️ Nenhuma alteração feita.")


def change_password_interactive(manager):
    """Altera senha do usuário"""
    print("\n🔒 ALTERAR SENHA")
    print("-" * 20)
    
    username = input("Username: ").strip()
    
    if username not in manager.users:
        print("❌ Usuário não encontrado!")
        return
    
    print(f"Alterando senha para: {manager.users[username]['name']}")
    new_password = input("Nova senha: ").strip()
    
    if len(new_password) < 4:
        print("❌ Senha deve ter pelo menos 4 caracteres!")
        return
    
    confirm_password = input("Confirme a nova senha: ").strip()
    
    if new_password != confirm_password:
        print("❌ Senhas não coincidem!")
        return
    
    success, message = manager.update_user(username, password=new_password)
    print(f"✅ {message}" if success else f"❌ {message}")


def tools_menu(manager):
    """Menu de ferramentas"""
    print("\n🔧 FERRAMENTAS")
    print("-" * 20)
    print("1. Backup dos usuários")
    print("2. Limpar dados de usuário")
    print("3. Resetar estatísticas")
    print("4. Migrar da versão antiga")
    print("5. Voltar")
    
    choice = input("Escolha (1-5): ").strip()
    
    if choice == "1":
        # Backup
        backup_file = f"production_users_backup_{get_sao_paulo_time().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            shutil.copy2(manager.users_file, backup_file)
            print(f"✅ Backup criado: {backup_file}")
        except Exception as e:
            print(f"❌ Erro no backup: {e}")
    
    elif choice == "2":
        # Limpar dados de usuário
        username = input("Username para limpar dados: ").strip()
        if username not in manager.users:
            print("❌ Usuário não encontrado!")
            return
        
        confirm = input(f"⚠️ Confirma limpeza dos dados de '{username}'? (CONFIRMAR): ").strip()
        if confirm == "CONFIRMAR":
            user_dir = Path(f"production_users/{username}")
            if user_dir.exists():
                try:
                    shutil.rmtree(user_dir)
                    print(f"✅ Dados removidos: {user_dir}")
                except Exception as e:
                    print(f"❌ Erro: {e}")
            else:
                print("ℹ️ Usuário não possui dados salvos")
    
    elif choice == "3":
        # Resetar estatísticas
        username = input("Username para resetar estatísticas (ou 'todos'): ").strip()
        
        if username == "todos":
            confirm = input("⚠️ Resetar estatísticas de TODOS os usuários? (CONFIRMAR): ").strip()
            if confirm == "CONFIRMAR":
                for user in manager.users.values():
                    user['total_conversations'] = 0
                    user['successful_queries'] = 0
                    user['failed_queries'] = 0
                
                if manager.save_users():
                    print("✅ Estatísticas resetadas para todos os usuários!")
                else:
                    print("❌ Erro ao salvar!")
        
        elif username in manager.users:
            manager.users[username].update({
                'total_conversations': 0,
                'successful_queries': 0,
                'failed_queries': 0
            })
            
            if manager.save_users():
                print(f"✅ Estatísticas resetadas para '{username}'!")
            else:
                print("❌ Erro ao salvar!")
        else:
            print("❌ Usuário não encontrado!")
    
    elif choice == "4":
        # Migração da versão antiga
        old_file = "streamlit_users.json"
        if Path(old_file).exists():
            print(f"📁 Encontrado arquivo antigo: {old_file}")
            migrate = input("Migrar usuários? (s/n): ").strip().lower()
            
            if migrate == 's':
                try:
                    with open(old_file, 'r') as f:
                        old_users = json.load(f)
                    
                    migrated = 0
                    for username, old_user in old_users.items():
                        if username not in manager.users:
                            # Converte formato antigo para novo
                            # Mapeia roles antigos para novos
                            role_mapping = {
                                "researcher": "Pesquisador",
                                "student": "Estudante", 
                                "professor": "Professor",
                                "admin": "Admin"
                            }
                            
                            old_role = old_user.get("role", "researcher")
                            new_role = role_mapping.get(old_role, "Pesquisador")
                            
                            new_user = {
                                "password_hash": old_user.get("password_hash", ""),
                                "name": old_user.get("name", username),
                                "role": new_role,
                                "organization": old_user.get("organization", ""),
                                "permissions": manager.role_permissions.get(new_role, []),
                                "created_at": old_user.get("created_at", get_sao_paulo_time().isoformat()),
                                "last_login": old_user.get("last_login", ""),
                                "total_conversations": old_user.get("total_conversations", 0),
                                "successful_queries": 0,
                                "failed_queries": 0,
                                "active": old_user.get("active", True),
                                "notes": f"Migrado de {old_file}"
                            }
                            
                            manager.users[username] = new_user
                            migrated += 1
                    
                    if manager.save_users():
                        print(f"✅ {migrated} usuários migrados com sucesso!")
                        
                        # Pergunta se quer fazer backup do arquivo antigo
                        backup = input("Fazer backup do arquivo antigo? (s/n): ").strip().lower()
                        if backup == 's':
                            backup_name = f"streamlit_users_backup_{get_sao_paulo_time().strftime('%Y%m%d_%H%M%S')}.json"
                            shutil.copy2(old_file, backup_name)
                            print(f"📁 Backup criado: {backup_name}")
                    else:
                        print("❌ Erro ao salvar usuários migrados!")
                        
                except Exception as e:
                    print(f"❌ Erro na migração: {e}")
        else:
            print(f"ℹ️ Arquivo antigo não encontrado: {old_file}")

def main():
    """Função principal"""
    manager = ProductionUserManager()
    
    # Não cria mais usuários padrão automaticamente
    
    # Modo não-interativo para automação
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "list":
            show_inactive = "--include-inactive" in sys.argv
            manager.list_users(show_inactive)
        
        elif command == "add" and len(sys.argv) >= 5:
            username, name, password = sys.argv[2:5]
            role = sys.argv[5] if len(sys.argv) > 5 else "Usuário"
            organization = sys.argv[6] if len(sys.argv) > 6 else ""
            
            success, message = manager.add_user(username, name, password, role, organization)
            print(message)
        
        elif command == "remove" and len(sys.argv) >= 3:
            username = sys.argv[2]
            success, message = manager.remove_user(username)
            print(message)
        
        elif command == "details" and len(sys.argv) >= 3:
            username = sys.argv[2]
            manager.get_user_details(username)
        
        elif command == "password" and len(sys.argv) >= 4:
            username, new_password = sys.argv[2:4]
            success, message = manager.update_user(username, password=new_password)
            print(message)
        
        
        elif command == "backup":
            backup_file = f"production_users_backup_{get_sao_paulo_time().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                shutil.copy2(manager.users_file, backup_file)
                print(f"✅ Backup criado: {backup_file}")
            except Exception as e:
                print(f"❌ Erro no backup: {e}")
        
        elif command == "help":
            print("🚀 GERENCIADOR DE USUÁRIOS RAG")
            print("\nComandos disponíveis:")
            print("  list [--include-inactive]  - Lista usuários")
            print("  add <user> <nome> <senha> [role] [org] - Adiciona usuário")
            print("  remove <user>              - Remove usuário")
            print("  details <user>             - Detalhes do usuário")
            print("  password <user> <senha>    - Altera senha")
            print("  backup                     - Backup dos usuários")
            print("  help                       - Esta ajuda")
            print("\nTipos disponíveis: Admin, Usuário")
            print("\nExemplos:")
            print("  python manage_production_users.py add joao 'João Silva' senha123 Usuário 'UFMG'")
            print("  python manage_production_users.py list --include-inactive")
            print("  python manage_production_users.py details admin")
        
        else:
            print("❌ Comando inválido! Use 'help' para ver comandos disponíveis.")
        
        return
    
    # Modo interativo
    while True:
        show_menu()
        choice = input("\nEscolha uma opção (1-8): ").strip()
        
        if choice == "1":
            add_user_interactive(manager)
        
        elif choice == "2":
            show_inactive = input("\nIncluir usuários inativos? (s/n): ").strip().lower() == 's'
            manager.list_users(show_inactive)
        
        elif choice == "3":
            username = input("\nUsername para ver detalhes: ").strip()
            manager.get_user_details(username)
        
        elif choice == "4":
            edit_user_interactive(manager)
        
        elif choice == "5":
            change_password_interactive(manager)
        
        elif choice == "6":
            username = input("\nUsername para remover: ").strip()
            
            if username in manager.users:
                user_info = manager.users[username]
                print(f"\n⚠️ ATENÇÃO: Você está prestes a remover:")
                print(f"   Usuário: {username}")
                print(f"   Nome: {user_info['name']}")
                print(f"   Perfil: {user_info['role']}")
                print(f"   Organização: {user_info.get('organization', 'N/A')}")
                
                confirm = input(f"\nPara confirmar, digite 'REMOVER {username}': ").strip()
                
                if confirm == f"REMOVER {username}":
                    success, message = manager.remove_user(username)
                    print(f"✅ {message}" if success else f"❌ {message}")
                else:
                    print("❌ Remoção cancelada.")
            else:
                print("❌ Usuário não encontrado!")
        
        
        elif choice == "7":
            tools_menu(manager)
        
        elif choice == "8":
            print("\n👋 Até logo!")
            print("🚀 Sistema RAG - Usuários gerenciados com sucesso!")
            break
        
        else:
            print("❌ Opção inválida!")
        
        input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Operação cancelada pelo usuário.")
    except Exception as e:
        print(f"\n❌ Erro crítico: {e}")
        sys.exit(1)
