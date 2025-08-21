import sys
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import shutil

# Configura logging
logging.basicConfig(
    filename='ransomware_simulator.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class TextUI:
    """Interface de texto simples"""
    
    def __init__(self):
        # Códigos de cores ANSI
        self.COLORS = {
            'RED': '\033[91m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'RESET': '\033[0m'
        }
    
    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_color(self, text, color='WHITE'):
        """Imprime texto colorido"""
        color_code = self.COLORS.get(color, self.COLORS['WHITE'])
        print(f"{color_code}{text}{self.COLORS['RESET']}")
    
    def print_center(self, text, color='WHITE'):
        """Imprime texto centralizado"""
        try:
            columns = os.get_terminal_size().columns
            centered_text = text.center(columns)
            self.print_color(centered_text, color)
        except:
            self.print_color(text, color)
    
    def show_banner(self):
        """Exibe banner"""
        self.clear_screen()
        print()
        self.print_center("╔══════════════════════════════════════════════════╗", "CYAN")
        self.print_center("║               RANSOMWARE SIMULATOR               ║", "CYAN")
        self.print_center("║                 (MODO ÉTICO)                     ║", "CYAN")
        self.print_center("╚══════════════════════════════════════════════════╝", "CYAN")
        print()
        self.print_center("▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄", "YELLOW")
        print()
        self.print_center("AVISO: APENAS PARA FINS EDUCACIONAIS!", "RED")
        self.print_center("NÃO USE PARA ATIVIDADES MALICIOSAS!", "RED")
        print()
        self.print_center("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀", "YELLOW")
        print("\n" * 2)
        time.sleep(2)
    
    def progress_bar(self, title, duration=2):
        """Exibe barra de progresso"""
        self.clear_screen()
        self.print_center(title, "CYAN")
        print()
        
        width = 40
        for i in range(width + 1):
            progress = i / width
            bar = "[" + "█" * i + " " * (width - i) + "]"
            percent = f"{progress*100:.1f}%"
            
            self.print_center(bar, "GREEN")
            self.print_center(percent, "YELLOW")
            print("\033[3A")  # Move cursor para cima 3 linhas
            time.sleep(duration / width)
        
        print("\033[3B")  # Move cursor para baixo 3 linhas
    
    def main_menu(self):
        """Exibe menu principal"""
        self.clear_screen()
        
        self.print_center("MENU PRINCIPAL", "CYAN")
        print()
        
        menu_options = [
            "1. Criptografar Arquivos de Teste",
            "2. Descriptografar Arquivos", 
            "3. Gerar Novas Chaves",
            "4. Verificar Arquivos",
            "5. Sobre o Projeto",
            "6. Sair"
        ]
        
        for option in menu_options:
            self.print_center(option, "GREEN")
        
        print()
        self.print_center("Selecione uma opção [1-6]:", "YELLOW")
        
        while True:
            try:
                choice = input().strip()
                if choice in ['1', '2', '3', '4', '5', '6']:
                    return choice
                else:
                    self.print_center("Opção inválida! Digite 1-6:", "RED")
            except:
                return '6'
    
    def confirm_action(self, message):
        """Solicita confirmação"""
        self.print_center(message, "YELLOW")
        self.print_center("Digite S para confirmar ou N para cancelar:", "WHITE")
        
        while True:
            try:
                choice = input().strip().lower()
                if choice == 's':
                    return True
                elif choice == 'n':
                    return False
            except:
                return False
    
    def print_status(self, message, success=True):
        """Exibe mensagem de status"""
        color = "GREEN" if success else "RED"
        self.print_center(f"STATUS: {message}", color)
        time.sleep(2)
    
    def input_path(self, prompt):
        """Solicita caminho do diretório"""
        self.print_center(prompt, "YELLOW")
        self.print_center("Deixe em branco para usar 'test_files':", "WHITE")
        
        try:
            path = input().strip()
            return path if path else "test_files"
        except:
            return "test_files"

class RansomwareSimulator:
    def __init__(self):
        self.ui = TextUI()
    
    def generate_keys(self):
        """Gera e salva chaves RSA"""
        try:
            self.ui.print_status("Gerando chaves RSA...", False)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            
            # Salva chave privada
            with open("private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Backup da chave
            shutil.copy2("private_key.pem", "private_key_backup.pem")
            self.ui.print_status("Chaves geradas e salvas com backup!", True)
            logging.info("Chaves RSA geradas com sucesso")
            
            return public_key
            
        except Exception as e:
            self.ui.print_status(f"Erro ao gerar chaves: {e}", False)
            logging.error(f"Erro ao gerar chaves: {e}")
            return None
    
    def load_private_key(self):
        """Carrega a chave privada do arquivo"""
        try:
            if not os.path.exists("private_key.pem"):
                self.ui.print_status("Chave privada não encontrada!", False)
                return None
            
            with open("private_key.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            return private_key
        except Exception as e:
            self.ui.print_status(f"Erro ao carregar chave privada: {e}", False)
            logging.error(f"Erro ao carregar chave privada: {e}")
            return None
    
    def encrypt_file(self, file_path, public_key):
        """Criptografa um arquivo individual"""
        try:
            # Gera uma chave AES aleatória
            aes_key = os.urandom(32)
            iv = os.urandom(16)

            # Criptografa a chave AES com RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Lê e criptografa o arquivo com AES
            with open(file_path, "rb") as f:
                file_data = f.read()

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()

            # Salva o arquivo criptografado
            encrypted_file_path = file_path + ".encrypted"
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_aes_key + iv + encrypted_data)

            logging.info(f"Arquivo criptografado: {file_path}")
            return True
            
        except Exception as e:
            logging.error(f"Erro ao criptografar {file_path}: {e}")
            return False
    
    def decrypt_file(self, file_path, private_key):
        """Descriptografa um arquivo individual"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Extrai componentes do arquivo criptografado
            encrypted_aes_key = data[:256]
            iv = data[256:272]
            encrypted_data = data[272:]
            
            # Decifra a chave AES com RSA
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decifra o arquivo com AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Salva o arquivo original
            original_path = file_path.replace(".encrypted", "")
            with open(original_path, "wb") as f:
                f.write(decrypted_data)
            
            # Remove o arquivo criptografado
            os.remove(file_path)
            
            logging.info(f"Arquivo descriptografado: {original_path}")
            return True
            
        except Exception as e:
            logging.error(f"Erro ao descriptografar {file_path}: {e}")
            return False
    
    def encrypt_directory(self, directory_path, public_key):
        """Criptografa todos os arquivos de um diretório"""
        if not os.path.exists(directory_path):
            self.ui.print_status("Diretório não encontrado!", False)
            return False
        
        encrypted_count = 0
        total_files = 0
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                
                # Ignora arquivos já criptografados e arquivos do sistema
                if (not file_path.endswith('.encrypted') and 
                    not file.startswith('.') and 
                    os.path.isfile(file_path)):
                    
                    if self.encrypt_file(file_path, public_key):
                        encrypted_count += 1
                        self.ui.print_center(f"Criptografado: {file}", "GREEN")
        
        self.ui.print_center(f"Resumo: {encrypted_count}/{total_files} arquivos criptografados!", "GREEN")
        return encrypted_count > 0
    
    def decrypt_directory(self, directory_path):
        """Descriptografa todos os arquivos de um diretório"""
        private_key = self.load_private_key()
        if not private_key:
            return False
        
        if not os.path.exists(directory_path):
            self.ui.print_status("Diretório não encontrado!", False)
            return False
        
        decrypted_count = 0
        total_encrypted = 0
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.encrypted'):
                    total_encrypted += 1
                    file_path = os.path.join(root, file)
                    
                    if self.decrypt_file(file_path, private_key):
                        decrypted_count += 1
                        self.ui.print_center(f"Descriptografado: {file}", "GREEN")
        
        if total_encrypted == 0:
            self.ui.print_status("Nenhum arquivo criptografado encontrado!", False)
            return False
        
        self.ui.print_center(f"Resumo: {decrypted_count}/{total_encrypted} arquivos descriptografados!", "GREEN")
        return decrypted_count > 0
    
    def check_files(self, directory_path):
        """Verifica arquivos no diretório"""
        if not os.path.exists(directory_path):
            self.ui.print_status("Diretório não encontrado!", False)
            return False
        
        normal_files = 0
        encrypted_files = 0
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.encrypted'):
                    encrypted_files += 1
                elif not file.startswith('.'):
                    normal_files += 1
        
        self.ui.clear_screen()
        self.ui.print_center("RELATÓRIO DE ARQUIVOS", "CYAN")
        print()
        self.ui.print_center(f"Diretório: {directory_path}", "WHITE")
        self.ui.print_center(f"Arquivos normais: {normal_files}", "GREEN")
        self.ui.print_center(f"Arquivos criptografados: {encrypted_files}", "YELLOW" if encrypted_files == 0 else "RED")
        print()
        
        if encrypted_files > 0:
            self.ui.print_center("Use a opção 2 para descriptografar", "YELLOW")
        
        input("\nPressione Enter para continuar...")
        return True
    
    def create_test_environment(self):
        """Cria ambiente de teste seguro"""
        test_dir = "test_files"
        if not os.path.exists(test_dir):
            os.makedirs(test_dir)
            self.ui.print_status("Pasta 'test_files' criada. Adicione arquivos!", False)
            return False
        
        # Verifica se há arquivos para criptografar
        files = [f for f in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, f)) and not f.startswith('.')]
        if not files:
            self.ui.print_status("Adicione arquivos na pasta 'test_files'!", False)
            return False
        
        return True
    
    def run_encryption(self):
        """Executa processo de criptografia"""
        directory_path = self.ui.input_path("Digite o caminho do diretório para criptografar:")
        
        if not os.path.exists(directory_path):
            self.ui.print_status("Diretório não encontrado!", False)
            return False
        
        if not self.ui.confirm_action(f"Deseja criptografar arquivos em '{directory_path}'?"):
            self.ui.print_status("Operação cancelada", False)
            return False
        
        self.ui.progress_bar("Inicializando sistema de criptografia")
        public_key = self.generate_keys()
        if not public_key:
            return False
        
        success = self.encrypt_directory(directory_path, public_key)
        
        if success:
            self.ui.print_status("Criptografia concluída com sucesso!", True)
        else:
            self.ui.print_status("Nenhum arquivo foi criptografado", False)
        
        return success
    
    def run_decryption(self):
        """Executa processo de descriptografia"""
        directory_path = self.ui.input_path("Digite o caminho do diretório para descriptografar:")
        
        if not os.path.exists(directory_path):
            self.ui.print_status("Diretório não encontrado!", False)
            return False
        
        if not self.ui.confirm_action(f"Deseja descriptografar arquivos em '{directory_path}'?"):
            self.ui.print_status("Operação cancelada", False)
            return False
        
        self.ui.progress_bar("Inicializando sistema de descriptografia")
        success = self.decrypt_directory(directory_path)
        
        if success:
            self.ui.print_status("Descriptografia concluída com sucesso!", True)
        else:
            self.ui.print_status("Falha na descriptografia", False)
        
        return success
    
    def show_about(self):
        """Exibe informações sobre o projeto"""
        self.ui.clear_screen()
        self.ui.print_center("SOBRE O PROJETO", "CYAN")
        print()
        about_info = [
            "Ransomware Simulator - Modo Ético",
            "Desenvolvido para fins educacionais",
            "Por Calebe Menezes",
            "",
            "Tecnologias utilizadas:",
            "- Python 3.x",
            "- Cryptography Library", 
            "- Criptografia AES-256 + RSA-2048",
            "",
            "Funcionalidades:",
            "✓ Criptografia de arquivos",
            "✓ Descriptografia com chave privada",
            "✓ Interface estilo terminal",
            "✓ Modo totalmente ético e seguro",
            "",
            "Pressione Enter para voltar"
        ]
        
        for line in about_info:
            self.ui.print_center(line, "WHITE")
        
        input()
    
    def run(self):
        """Loop principal da aplicação"""
        self.ui.show_banner()
        
        while True:
            choice = self.ui.main_menu()
            
            if choice == '1':
                self.run_encryption()
                
            elif choice == '2':
                self.run_decryption()
                
            elif choice == '3':
                self.ui.progress_bar("Gerando novas chaves")
                self.generate_keys()
                
            elif choice == '4':
                directory_path = self.ui.input_path("Digite o caminho do diretório para verificar:")
                self.check_files(directory_path)
                
            elif choice == '5':
                self.show_about()
                
            elif choice == '6':
                self.ui.print_status("Saindo... Obrigado por usar o simulador ético!", True)
                break

def main():
    """Função principal"""
    # Verifica se estamos em um terminal interativo
    if not sys.stdout.isatty():
        print("Este programa requer um terminal interativo.")
        print("Execute em um terminal como CMD, PowerShell ou Bash.")
        return
    
    try:
        app = RansomwareSimulator()
        app.run()
    except KeyboardInterrupt:
        print("\n\nPrograma interrompido pelo usuário.")
    except Exception as e:
        print(f"\nErro inesperado: {e}")
        print("Verifique o arquivo ransomware_simulator.log para detalhes.")

if __name__ == "__main__":
    main()