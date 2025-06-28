import json
import os
import re
import sys
import wmi
import ctypes
import subprocess
import locale
import queue
import time
import socket
import pprint
from requests.auth import HTTPBasicAuth
import requests
import webbrowser
import copy
import pyodbc
import threading
from datetime import datetime, timedelta
from threading import Thread, Lock
from queue import Queue, Empty
from paho.mqtt import client as mqtt_client
import paho.mqtt.client as mqtt
from pyModbusTCP.client import ModbusClient
import traceback

# Imports PyQt5: VERIFICADO E CORRIGIDO
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QMdiArea,
    QMenuBar, QAction, QTextEdit, QMenu, QDialog, QLineEdit, QMessageBox, QInputDialog, QSizePolicy,
    QFileDialog, QFrame, QGridLayout, QScrollArea, QColorDialog, QSpacerItem, QSlider, QCheckBox,
    QRadioButton, QProgressBar, QComboBox, QDateEdit, QSpinBox, QStyle, QFontDialog, QListWidget, QToolBar,
    QSystemTrayIcon, QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QWhatsThis, QDockWidget, QMdiSubWindow, QFormLayout, QPlainTextEdit, QGraphicsDropShadowEffect,
    QStackedWidget, QGraphicsOpacityEffect, QProgressBar, QSizePolicy

)
from PyQt5.QtCore import Qt, QPoint, QSize, QEvent, QObject, pyqtSignal, QThread, QDate, QSharedMemory, QTimer, QUrl, QMutex, QRect, QPropertyAnimation,  QParallelAnimationGroup
from PyQt5.QtGui import QIcon, QPixmap, QColor, QMovie, QTextCursor, QTextCharFormat, QSyntaxHighlighter, QFont, QTextFormat, QDesktopServices, QLinearGradient, QFontDatabase, QPainter, QFontMetrics


# --- Adicionar o diretório pai (InLogic) ao sys.path ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from Modulos.donwload_backup import BackupManager   # importar modulo 
from Modulos.modulo_google_drive import iniciar_download_recursos  



# --- IMPORTS PARA O SISTEMA DE CRIPTOGRAFIA (Conforme especificado na última mensagem - REPLICADO EXATAMENTE) ---
# Assume que estas bibliotecas estão instaladas no ambiente de produção (pycryptodome, win32file)
# Se faltarem, um ImportError ocorrerá na inicialização.
try:
    from base64 import b64encode, b64decode
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import win32file, pywintypes      # Incluído conforme solicitado - Requer pywin32
    print("[INFO] Bibliotecas de criptografia importadas (conforme especificação).")
    crypto_available = True # Flag para indicar que a importação foi bem-sucedida.

except ImportError as e:
    print(f"---------------------------------------------------------------------------")
    print(f"ERRO CRÍTICO: Biblioteca de criptografia ou dependência não encontrada: {e}")
    print(f"A funcionalidade de criptografia/descriptografia NÃO PODE FUNCIONAR sem ela.")
    print(f"Por favor, instale 'pycryptodome' (pip install pycryptodome) e 'pywin32' (pip install pywin32).")
    print(f"---------------------------------------------------------------------------")
    # Define crypto_available como False. As funções de criptografia abaixo precisarão verificar isso.
    crypto_available = False


# --- Chave Secreta (Conforme especificado na última mensagem - REPLICADO EXATAMENTE) ---
CHAVE_SECRETA = b"inlogic18366058".ljust(32, b'0')  # Garante 32 bytes

# Verifica o tamanho da chave APENAS se a criptografia real está disponível (após importação)
if crypto_available and hasattr(AES, 'new'): # Verifica se a classe AES foi importada com sucesso
    assert len(CHAVE_SECRETA) == 32, "A chave secreta deve ter 32 bytes para AES-256"


# --- Integração qtawesome ---
try:
    import qtawesome as awesome
    print("[INFO] Biblioteca 'qtawesome' encontrada. Ícones modernos serão usados como fallback para arquivos.")
    qtawesome_available = True

    # Mapeamento de ícones qtawesome (fallback)
    QTAWESOME_ASSET_ICONS = {
        "Address": 'fa5s.network-wired',
        "Servidor": 'fa5s.server',
        "Caminho Excel": 'fa5s.file-excel',
        "Banco de Dados": 'fa5s.database',
        "Tabela": 'fa5s.table',
        "Login": 'fa5s.user',
        "Usuário": 'fa5s.user-circle',
        "Senha": 'fa5s.lock',
        "Memória de Gatilho": 'fa5s.arrow-up',
        "Memórias de Gravação": 'fa5s.arrow-down',
        "Temporizador": 'fa5s.clock',
        "Calculos": 'fa5s.calculator',
        "Calculo": 'fa5s.superscript',
        "Local de Gravação": 'fa5s.save',
        "MQTT": 'fa5s.wifi',
        "Notificacao": 'fa5s.bell',
        "Evento": 'fa5s.bolt',
        "Info": 'fa5s.info-circle',
        "Erro Crítico": 'fa5s.exclamation-circle',
        "Pasta": 'fa5s.folder',
        "Arquivo": 'fa5s.file',
        "Drive": 'fa5s.hdd',
        
    }

    QTAWESOME_TOOLBAR_ICONS = {
        "Play": 'fa5s.play',
        "Stop": 'fa5s.stop',
        "Download": 'fa5s.download',
        "Upload": 'fa5s.upload',
        "Login": 'fa5s.sign-in-alt',
        "Logout": 'fa5s.sign-out-alt',
        "Change Password": 'fa5s.key',
        "Reset Password": 'fa5s.undo',
        "Recarregar": 'fa5s.sync-alt' # Exemplo de ícone de sincronizar/atualizar
    }

    QTAWESOME_MENU_ICONS = {
         "Script Editor": 'fa5s.code',
         "Logs Viewer": 'fa5s.clipboard-list',
         "Properties Viewer": 'fa5s.info-circle'
    }

except ImportError:
    print("---------------------------------------------------------------------------")
    print("AVISO: A biblioteca 'qtawesome' NÃO está instalada.")
    print("Ícones modernos NÃO serão usados. Utilizando fallback para QStyle básico.")
    print("Por favor, instale-a para ícones modernos: pip install qtawesome")
    print("---------------------------------------------------------------------------")
    qtawesome_available = False

    QTAWESOME_ASSET_ICONS = {} # Dicionários vazios se qtawesome não estiver disponível
    QTAWESOME_TOOLBAR_ICONS = {}
    QTAWESOME_MENU_ICONS = {}


# --- Fallback para ícones QStyle BÁSICOS e Universais ---
QSTYLE_FALLBACK_ICONS = {
     "Address": QStyle.SP_ComputerIcon,
     "Servidor": QStyle.SP_DriveHDIcon,
     "Caminho Excel": QStyle.SP_FileIcon,
     "Banco de Dados": QStyle.SP_DriveHDIcon,
     "Tabela": QStyle.SP_FileDialogDetailedView,
     "Login": QStyle.SP_DialogUserIcon if hasattr(QStyle, 'SP_DialogUserIcon') else QStyle.SP_FileIcon,
     "Usuário": QStyle.SP_DialogUserIcon if hasattr(QStyle, 'SP_DialogUserIcon') else QStyle.SP_FileIcon,
     "Senha": QStyle.SP_DialogLock if hasattr(QStyle, 'SP_DialogLock') else QStyle.SP_MessageBoxWarning,
     "Memória de Gatilho": QStyle.SP_ArrowUp,
     "Memórias de Gravação": QStyle.SP_ArrowDown, # Ícone de seta para baixo
     "Temporizador": QStyle.SP_BrowserReload,
     "Calculos": QStyle.SP_FileDialogContentsView,
     "Calculo": QStyle.SP_FileDialogInfoView,
     "Local de Gravação": QStyle.SP_DialogSaveButton,
     "MQTT": QStyle.SP_MessageBoxInformation,
     "Notificacao": QStyle.SP_MessageBoxInformation,
     "Evento": QStyle.SP_DialogSaveButton,
     "Info": QStyle.SP_MessageBoxInformation,
     "Erro Crítico": QStyle.SP_MessageBoxCritical,
     "Pasta": QStyle.SP_DirIcon,
     "Arquivo": QStyle.SP_FileIcon,
     "Drive": QStyle.SP_DriveHDIcon,
     # Ícones específicos da Toolbar (fallback)
     "Play": QStyle.SP_MediaPlay,
     "Stop": QStyle.SP_MediaStop,
     "Download": QStyle.SP_ArrowDown,
     "Upload": QStyle.SP_ArrowUp,
     "Logout": QStyle.SP_DialogCloseButton,
     "Change Password": QStyle.SP_DialogSaveButton,
     "Reset Password": QStyle.SP_BrowserReload,
      # Ícones específicos do Menu (fallback)
     "Script Editor": QStyle.SP_FileIcon,
     "Logs Viewer": QStyle.SP_MessageBoxInformation,
     "Properties Viewer": QStyle.SP_FileDialogInfoView,
     "Recarregar": QStyle.SP_BrowserReload # Ícone de recarregar/atualizar (fallback QStyle)

}

# --- Mapeamento de nomes lógicos para nomes de arquivo de ícones coloridos (Prioridade 1) ---
# Estes nomes de arquivo DEVERIAM existir na sua pasta BASE_PATH_IMAGES (C:\In Logic\Imagens)
# Adicione .png, .svg, ou .ico conforme o formato dos seus arquivos.
ICON_FILENAMES = {
    "Address": "icon_address.png",
    "Servidor": "icon_server.png",
    "Caminho Excel": "icon_excel_path.png",
    "Banco de Dados": "icon_database.png",
    "Tabela": "icon_table.png",
    "Login": "icon_login.png",
    "Usuário": "icon_user.png",
    "Senha": "icon_password.png",
    "Memória de Gatilho": "icon_memory_up.png",
    "Memórias de Gravação": "icon_memory_down.png",
    "Temporizador": "icon_timer.png",
    "Calculos": "icon_calculator.png",
    "Calculo": "icon_calculation.png",
    "Local de Gravação": "icon_save_location.png",
    "MQTT": "icon_mqtt.png",
    "Notificacao": "icon_notification.png",
    "Evento": "icon_event.png",
    "Info": "icon_info.png",
    "Erro Crítico": "icon_error.png",
    "Pasta": "icon_folder.png",
    "Arquivo": "icon_file.png",
    "Drive": "icon_drive.png",
    "Play": "icon_play.png",
    "Stop": "icon_stop.png",
    "Download": "icon_download.png",
    "Upload": "icon_upload.png",
    "Logout": "icon_logout.png",
    "Change Password": "icon_change_password.png",
    "Reset Password": "icon_reset.png",
    "Script Editor": "icon_script.png",
    "Logs Viewer": "icon_logs.png",
    "Properties Viewer": "icon_properties.png",
}




# Credenciais e URLs da API do WP Digital License Manager (AJUSTE ESTES VALORES PARA OS SEUS!)
URL_SITE_LICENCA = "https://www.inlogic.com.br" # URL base da API (seu site WP)
CONSUMER_KEY_LICENCA = "ck_82b1a709bdb7b7b2389ae5824acf1f9cb3ff6de1" # Sua Consumer Key para a API REST
CONSUMER_SECRET_LICENCA = "cs_18725269303c64f83ca27e47a0b345ad566a3223" # Sua Consumer Secret para a API REST

# Headers HTTP padrão para as requisições da API de Licença.
HEADERS_API_LICENCA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, como Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7",
    "Connection": "keep-alive",
    "Referer": f"{URL_SITE_LICENCA}/",
    "Origin": URL_SITE_LICENCA,
    "Host": "www.inlogic.com.br"
}


# --- Caminhos e constantes de arquivo (Conforme especificado - REPLICADO EXATAMENTE) ---
if getattr(sys, 'frozen', False):
    BASE_PATH_IMAGES = sys._MEIPASS
else:
    BASE_PATH_IMAGES = r"C:\In Logic\Imagens"

ICON_PATH = os.path.join(BASE_PATH_IMAGES, "icone.ico")
DEFAULT_ICON_PATH = os.path.join(BASE_PATH_IMAGES, "icone.ico")
GIF_PATH = os.path.join(BASE_PATH_IMAGES, "animacao.gif")

PATH = r"C:\In Logic"
CONFIG_PATH = r"C:\In Logic\Setup ativos"
CONFIG_PATH1 = os.path.join(CONFIG_PATH, "Setup.cfg")
# CHAVE_SECRETA já definida acima
BASE_IMAGES = r"C:\In Logic\Imagens"    # Duplicado? Manter por consistência com o original.
caminho_log = r"C:\In Logic\Logs Inlogic\log_service.log"
PIPE_CMD = r'\\.\pipe\InlogicPipeCmd'
LICENSE_FILE = os.path.join(CONFIG_PATH, "Authentication.cfg")

TEST_SERVICE_NAME = "InLogicService"
TEST_SERVICE_BIN_PATH = r"C:\Program Files\In Logic Studio\Service.exe"
TEST_SERVICE_DISPLAY_NAME = "InLogic Service"


ARQUIVO_ATIVACAO = "Authentication_ativacao.cfg"
PATH_ATIVACAO = os.path.join(CONFIG_PATH, ARQUIVO_ATIVACAO)
CAMINHO_ARQUIVO_ATIVACAO = PATH_ATIVACAO
ARQUIVO_VALIDACAO = "Authentication_validacao.cfg"
PATH_VALIDACAO = os.path.join(CONFIG_PATH, ARQUIVO_VALIDACAO)


# --- Dados de versão, nome do software, senha padrão ---
senha_correta_padrao = "1234"  # Senha padrão (variável) - MANTIDA COMO STRING
nome_software = "InLogic Studio"    # Nome do Software
versao = "15.0.0"   # Vesão do Software
status_conexao = False  # Inicia o sistema com o usuario deslogado

log_queue = Queue() # Variavél global para armazenar print queue de logs para interface

# --- Variável global para a senha de autenticação carregada ---
# Esta será a senha USADA pelo sistema, lida do arquivo ou da variável padrão
senha_autenticacao_ativa = senha_correta_padrao # Inicializa com a senha padrão




# --- Funções de criptografia/descriptografia (Adaptadas para usar a flag crypto_available) ---
def criptografar_dados(dados_bytes):
    """Criptografa bytes usando AES CBC se crypto_available for True."""
    if not crypto_available or not hasattr(AES, 'new'):
        print("[AVISO] Criptografia MOCK: Bibliotecas não disponíveis. Retornando bytes originais (NÃO SEGURO).")
        return dados_bytes # Mock: retorna os bytes originais

    try:
        iv = get_random_bytes(16)
        cipher = AES.new(CHAVE_SECRETA, AES.MODE_CBC, iv)
        dados_encriptados = cipher.encrypt(pad(dados_bytes, AES.block_size))
        return b64encode(iv + dados_encriptados)
    except Exception as e:
        print(f"❌ Erro durante a criptografia de dados: {e}")
        log_queue.put(f"❌ Erro durante a criptografia de dados: {e}")
        # Em caso de erro na criptografia real, retornamos bytes originais (NÃO SEGURO!)
        # Para produção, considere levantar a exceção ou retornar None.
        return dados_bytes # Fallback inseguro para manter o fluxo

def descriptografar_dados(conteudo_criptografado_bytes):
    """Descriptografa bytes criptografados se crypto_available for True."""
    if not crypto_available or not hasattr(AES, 'new'):
        print("[AVISO] Descriptografia MOCK: Bibliotecas não disponíveis. Retornando bytes originais (NÃO SEGURO).")
        return conteudo_criptografado_bytes # Mock: retorna os bytes originais

    try:
        dados = b64decode(conteudo_criptografado_bytes)
        if len(dados) < 16:
             print(f"Aviso: Descriptografia: Conteúdo muito curto ({len(dados)} bytes). Retornando bytes originais (Pode ser texto plano?).")
             log_queue.put(f"Aviso: Descriptografia: Conteúdo muito curto ({len(dados)} bytes). Retornando bytes originais (Pode ser texto plano?).")
             return conteudo_criptografado_bytes # Retorna original se for muito curto

        iv = dados[:16]
        dados_encriptados = dados[16:]
        cipher = AES.new(CHAVE_SECRETA, AES.MODE_CBC, iv)
        dados_descriptografados = unpad(cipher.decrypt(dados_encriptados), AES.block_size)
        return dados_descriptografados
    except Exception as e:
        print(f"❌ Erro durante a descriptografia de dados: {e}. Retornando bytes originais (Pode ser texto plano ou corrompido?).")
        log_queue.put(f"❌ Erro durante a descriptografia de dados: {e}. Retornando bytes originais (Pode ser texto plano ou corrompido?).")
        # Em caso de erro na descriptografia real, retornamos bytes originais (PODE SER TEXTO PLANO OU DADOS CORROMPIDOS)
        return conteudo_criptografado_bytes # Fallback inseguro para manter o fluxo
# -------------------------------------------------------------------------
# Funções de criptografia/descriptografia para JSON (Usam as funções de bytes)
def criptografar_json(dados_dict):
     """Criptografa um dicionário JSON."""
     try:
         dados_bytes = json.dumps(dados_dict).encode('utf-8')
         # Use a função de criptografia de bytes
         conteudo_criptografado_bytes = criptografar_dados(dados_bytes)
         # Retorna a representação Base64 como string
         return conteudo_criptografado_bytes.decode('utf-8')
     except Exception as e:
         print(f"❌ Erro durante a criptografia JSON: {e}")
         log_queue.put(f"❌ Erro durante a criptografia JSON: {e}")
         raise # Propaga o erro

def descriptografar_json(conteudo_criptografado_string):
     """Descriptografa conteúdo JSON."""
     try:
         # Converte string base64 -> bytes base64
         conteudo_criptografado_bytes = conteudo_criptografado_string.encode('utf-8')
         # Descriptografa os bytes
         dados_bytes = descriptografar_dados(conteudo_criptografado_bytes)
         # Decodifica bytes -> string (UTF-8) -> parseia JSON
         return json.loads(dados_bytes.decode('utf-8'))
     except Exception as e:
         print(f"❌ Erro durante a descriptografia JSON: {e}")
         log_queue.put(f"❌ Erro durante a descriptografia JSON: {e}")
         # Se a descriptografia ou parsing JSON falhar, retorna um dicionário vazio como fallback.
         return {}
# -------------------------------------------------------------------------


# --- Função responsavel de verificar existencia ou criar pasta de img ---
def verificar_ou_criar_pasta_imagens():
    """Verifica e cria a pasta de imagens se não existir."""
    try:
        # Usa BASE_PATH_IMAGES consistente
        if not os.path.exists(BASE_PATH_IMAGES):
            os.makedirs(BASE_PATH_IMAGES)
            log_message = f"[INFO] Pasta criada: {BASE_PATH_IMAGES}"
            print(log_message)
            log_queue.put(log_message)
      
    except Exception as e:
        log_message = f"[ERRO] Falha ao verificar/criar pasta {BASE_PATH_IMAGES}: {e}"
        print(log_message)
        log_queue.put(log_message)

# --- Função responsavel por obter numero de série da placa mãe do PC ---
def get_system_info():
    """Obtém informações únicas do sistema (Serial da placa-mãe)."""
    try:
        c = wmi.WMI()
        try:
            motherboard_serial = c.Win32_BaseBoard()[0].GetBoardSerial().strip()
        except: # Fallback para SerialNumber se GetBoardSerial falhar
             motherboard_serial = c.Win32_BaseBoard()[0].SerialNumber.strip()
        return motherboard_serial
    except Exception as e:
        error_message = f"[ERRO] Falha ao obter Serial Number: {e}"
        print(error_message)
        log_queue.put(error_message)
        return "SN_DESCONHECIDO"

# --- Função responsavel de criar e validar pastas ---
def recriar_arquivo_validacao_vazio():
    try:
        if not os.path.exists(PATH_VALIDACAO):
            json_vazio = '{}'.encode('utf-8')

            try:
                conteudo_criptografado = criptografar_dados(json_vazio)
            except Exception as e:
                log_queue.put((f"❌ Erro ao criptografar dados vazios: {type(e).__name__} - {e}", "red"))
                return  # Não prossegue se a criptografia falhar

            try:
                with open(PATH_VALIDACAO, 'wb') as f:
                    f.write(conteudo_criptografado)
                log_queue.put(("Criando arquivo de validação... ", "orange"))
            except Exception as e:
                log_queue.put((f"❌ Erro ao escrever arquivo de validação: {type(e).__name__} - {e}", "red"))
        else:
            log_queue.put(("ℹ️ Arquivo de validação de licença encontrado...", "green"))

    except Exception as erro_geral:
        log_queue.put((f"❌ Erro inesperado em recriar_arquivo_validacao_vazio: {type(erro_geral).__name__} - {erro_geral}", "red"))
        log_queue.put((traceback.format_exc(), "gray"))  # Loga traceback técnico completo (opcional)

def inicializar_arquivo_licenca():
    formato_data = "%d-%m-%Y %H:%M:%S"
    agora_str = datetime.now().strftime(formato_data)
    numero_serie = get_system_info()

    # Se o arquivo já existe, preserva valores
    if os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, 'rb') as f:
                conteudo = f.read()
            dados = json.loads(descriptografar_dados(conteudo).decode('utf-8'))

            # Apenas inicializa os campos que ainda não existem
            if "numero_serie" not in dados:
                dados["numero_serie"] = numero_serie

            if "dias" not in dados:
                dados["dias"] = 0

            if "ultima_atualização_dias" not in dados:
                dados["ultima_atualização_dias"] = agora_str

            if "ultima_verificacao_real" not in dados:
                dados["ultima_verificacao_real"] = agora_str

            if "ultimo_registro_validado" not in dados:
                dados["ultimo_registro_validado"] = agora_str

            if "licenca" not in dados:
                dados["licenca"] = False

            if "motivo" not in dados:
                dados["motivo"] = "Inicialização"

        except Exception as e:
            print(f"[ERRO] Falha ao ler/atualizar arquivo existente: {e}")
            dados = {
                "numero_serie": numero_serie,
                "dias": 0,
                "ultima_atualização_dias": agora_str,
                "ultima_verificacao_real": agora_str,
                "ultimo_registro_validado": agora_str,
                "licenca": False,
                "motivo": "Inicialização (fallback)"
            }

    else:
        # Arquivo ainda não existe, cria do zero
        dados = {
            "numero_serie": numero_serie,
            "dias": 0,
            "ultima_atualização_dias": agora_str,
            "ultima_verificacao_real": agora_str,
            "ultimo_registro_validado": agora_str,
            "licenca": False,
            "motivo": "Inicialização"
        }

    # Salva o arquivo (recriptografado)
    conteudo_final = criptografar_dados(json.dumps(dados, indent=4).encode('utf-8'))
    with open(LICENSE_FILE, 'wb') as f:
        f.write(conteudo_final)

def verificar_ou_criar_configuracao():
    """Verifica/cria o arquivo de configuração principal (Setup.cfg)."""
    numero_serial = get_system_info()

    try:
        if not os.path.exists(CONFIG_PATH):
            os.makedirs(CONFIG_PATH)
            log_queue.put(f"Pasta de configuração criada com sucesso!")
        else:
            log_queue.put(f"Pasta de configuração encontrada com sucesso!")

        if not os.path.exists(CONFIG_PATH1):
            log_message = "🚧 Arquivo de configuração principal não encontrado. Criando estrutura genérica..."
            print(log_message)
            log_queue.put(log_message)

            estrutura_generica = {
                "grupos": [
                    {
                        "grupo": "GRUPO_GENÉRICO_MODIFICAVEL",
                        "plc_ip": "192.168.2.1",
                        "tipo_clp": "delta",
                        "diretorio": r"C:\CAMINHO\GENERICO\MODIFICAVEL",
                        "mem_list": [22031, 22028],
                        "gatilho": 1,
                        "intervalo_temporizador": 5,
                        "tabela_sql": "TABELA_GENÉRICA_MODIFICAVEL",
                        "db_config": {
                            "server": "GENÉRICO_MODIFICAVEL",
                            "database": "GENÉRICO_V001_MODIFICAVEL",
                            "username": "SEU_NOME_MODIFICAVEL",
                            "password": "SUA_SENHA"
                        },
                        "calculos": {
                             "CALC_EXEMPLO_SOMA": ["22031", "22028", "tag1 + tag2"]
                         },
                        "local_gravacao": {
                            "sql": True,
                            "excel": False,
                            "mqtt": True,
                            "notificacao": True
                        },
                        "notificacao": {
                            "topico": numero_serial,
                            "titulo": "ATENÇÃO",
                            "mensagem": "Alerta do CLP!"
                        },
                        "ACESSO_MQTT": {
                            "broker_address": "mqtt.exemplo.com",
                            "port": 1883,
                            "client_id": f"cliente_{numero_serial}",
                            "username": "usuario_teste",
                            "password": "senha_forte123",
                            "keep_alive": 60,
                            "qos": 1
                        }
                    }
                ],
            }

            try:
                conteudo_salvar = criptografar_json(estrutura_generica)
                with open(CONFIG_PATH1, "w") as f:
                    f.write(conteudo_salvar)
                log_message = f"✅ Arquivo de configuração criado com sucesso!"
                print(log_message)
                log_queue.put(log_message)
            except Exception as e:
                log_message = f"❌ Erro ao criar e salvar Setup.cfg: {e}"
                print(log_message)
                log_queue.put(log_message)

        else:
            log_message = "✅ Arquivo de configuração encontrado no SISTEMA..."
            print(log_message)
            log_queue.put(log_message)

            # --- NOVO TRECHO: Verificação de grupo válido ---
            try:
                with open(CONFIG_PATH1, "r") as f:
                    conteudo = f.read()
                # Descriptografar se necessário:
                config_data = descriptografar_json(conteudo) # substitua pela sua função real
                # Se grupos não existe, ou é uma lista vazia
                if not config_data.get("grupos") or len(config_data["grupos"]) == 0:
                    # Reutiliza o mesmo grupo genérico
                    grupo_generico = {
                        "grupo": "GRUPO_GENÉRICO_MODIFICAVEL",
                        "plc_ip": "192.168.2.1",
                        "tipo_clp": "delta",
                        "diretorio": r"C:\CAMINHO\GENERICO\MODIFICAVEL",
                        "mem_list": [22031, 22028],
                        "gatilho": 1,
                        "intervalo_temporizador": 5,
                        "tabela_sql": "TABELA_GENÉRICA_MODIFICAVEL",
                        "db_config": {
                            "server": "GENÉRICO_MODIFICAVEL",
                            "database": "GENÉRICO_V001_MODIFICAVEL",
                            "username": "SEU_NOME_MODIFICAVEL",
                            "password": "SUA_SENHA"
                        },
                        "calculos": {
                             "CALC_EXEMPLO_SOMA": ["22031", "22028", "tag1 + tag2"]
                         },
                        "local_gravacao": {
                            "sql": True,
                            "excel": False,
                            "mqtt": True,
                            "notificacao": True
                        },
                        "notificacao": {
                            "topico": numero_serial,
                            "titulo": "ATENÇÃO",
                            "mensagem": "Alerta do CLP!"
                        },
                        "ACESSO_MQTT": {
                            "broker_address": "mqtt.exemplo.com",
                            "port": 1883,
                            "client_id": f"cliente_{numero_serial}",
                            "username": "usuario_teste",
                            "password": "senha_forte123",
                            "keep_alive": 60,
                            "qos": 1
                        }
                    }
                    config_data["grupos"] = [grupo_generico]
                    conteudo_salvo = criptografar_json(config_data)
                    with open(CONFIG_PATH1, "w") as f:
                        f.write(conteudo_salvo)
                    log_message = "⚠️ Nenhum grupo válido encontrado. Grupo genérico adicionado à configuração!"
                    print(log_message)
                    log_queue.put(log_message)
            except Exception as e:
                log_message = f"❌ Erro ao validar grupos no Setup.cfg: {e}"
                print(log_message)
                log_queue.put(log_message)
            # --- FIM DO NOVO TRECHO ---

    except Exception as e:
        log_message = f"❌ Erro geral em verificar_ou_criar_configuracao: {e}"
        print(log_message)
        log_queue.put(log_message)

    try:
        inicializar_arquivo_licenca()
    except Exception as e:
        log_queue.put(("[Erro] No processo de criação do arquivo adicional de licença: [inicializar_arquivo_licenca] >> {e}", "red"))


    verificar_ou_criar_pasta_imagens()



# --- Função responsavel de carregar json ---
def carregar_configuracao():
    """Carrega e descriptografa a configuração principal."""
    log_queue.put("Carregando configurações do sistema...")
    verificar_ou_criar_configuracao() # Garante que a pasta e o arquivo existam

    config = {"grupos": []} # Estrutura de fallback padrão
    try:
        if not os.path.exists(CONFIG_PATH1):
             log_message = f"❌ Erro: Arquivo de configuração não encontrado após tentativa de criação em {CONFIG_PATH1}"
             print(log_message)
             log_queue.put(log_message)
             return config # Retorna fallback

        with open(CONFIG_PATH1, 'r') as f:
            conteudo_lido = f.read()

        try:
            # Tenta descriptografar e parsear JSON
            config = descriptografar_json(conteudo_lido)

            # Validação básica da estrutura
            if not isinstance(config, dict) or not isinstance(config.get("grupos"), list):
                 log_message = "❌ Erro na estrutura do arquivo de configuração: resultado não é um dicionário ou 'grupos' não encontrado ou não é lista."
                 print(log_message)
                 log_queue.put(log_message)
                 return {"grupos": []} # Retorna fallback se a estrutura for inválida

        except Exception as e:
            # Este except captura erros de descriptografia E de json.loads
            log_message = f"❌ Erro ao descriptografar/parsear Setup.cfg: {e}"
            print(log_message)
            log_queue.put(log_message)
            return {"grupos": []} # Retorna fallback vazio em caso de erro

    except FileNotFoundError:
        log_message = f"❌ Erro: Arquivo de configuração não encontrado em {CONFIG_PATH1}"
        print(log_message)
        log_queue.put(log_message)
        return config

    except Exception as e:
        log_message = f"❌ Erro geral ao carregar Setup.cfg: {e}"
        print(log_message)
        log_queue.put(log_message)
        return config

    return config

# --- Função responsavel da gravação e atualização do json ---
def salvar_configuracao(config):
    """Criptografa e salva a configuração principal."""
    try:
        conteudo_salvar = criptografar_json(config)
        with open(CONFIG_PATH1, 'w') as f:
            f.write(conteudo_salvar)

        log_message = "✅ Configuração salva com sucesso."
        print(log_message)
        log_queue.put(log_message)
    except Exception as e:
        log_message = f"❌ Erro ao salvar configuração: {e}"
        print(log_message)
        log_queue.put(log_message)



# --- Funções para Autenticação (Revisadas para sempre manter Authentication.cfg criptografado) ---
def ler_arquivo_autenticacao():
    """
    Lê e descriptografa o arquivo Authentication.cfg.
    Retorna um dicionário com o conteúdo ou um dicionário padrão se o arquivo não existir.
    """
    try:
        with open(LICENSE_FILE, 'rb') as f:
            conteudo_criptografado = f.read()
        conteudo_bytes = descriptografar_dados(conteudo_criptografado)
        conteudo_str = conteudo_bytes.decode('utf-8')
        data = json.loads(conteudo_str)
        return data
    except FileNotFoundError:
        log_queue.put("ler_arquivo_autenticacao: Arquivo Authentication.cfg não encontrado. Retornando estrutura padrão.")
        print("ler_arquivo_autenticacao: Arquivo Authentication.cfg não encontrado. Retornando estrutura padrão.")
        return {
            "email": "",
            "status": "inactive",
            "last_checked": "",
            "serial": "",
        }  # Retorna estrutura padrão
    except Exception as e:
        msg = f"ler_arquivo_autenticacao: Erro ao ler/descriptografar {LICENSE_FILE}: {type(e).__name__} - {e}. Retornando estrutura padrão."
        log_queue.put(msg)
        print(msg)
        return {
            "email": "",
            "status": "inactive",
            "last_checked": "",
            "serial": "",
        }  # Retorna estrutura padrão

def salvar_arquivo_autenticacao(data):
    """
    Criptografa e salva os dados no arquivo Authentication.cfg.
    Retorna True em caso de sucesso, False em caso de erro.
    """
    log_queue.put(f"Criptografando e salvando nova senha...")
    try:
        conteudo_str = json.dumps(data).encode('utf-8')
        conteudo_criptografado = criptografar_dados(conteudo_str)
        with open(LICENSE_FILE, 'wb') as f:
            f.write(conteudo_criptografado)
        return True
    except Exception as e:
        msg = f"salvar_arquivo_autenticacao: Erro ao criptografar/salvar {LICENSE_FILE}: {type(e).__name__} - {e}"
        log_queue.put(msg)
        print(msg)
        return False

def ler_senha_autenticacao():
    """
    Lê a senha do arquivo Authentication.cfg, se existir.
    Caso contrário, usa a senha padrão.
    """
    global senha_autenticacao_ativa

    auth_data = ler_arquivo_autenticacao()
    if auth_data and "senha" in auth_data:
        senha_autenticacao_ativa = str(auth_data["senha"]).strip()
        log_queue.put("Senha do usuario localizada com sucesso...")
    else:
        senha_autenticacao_ativa = str(senha_correta_padrao).strip()
        log_queue.put("Não foi possivel localizar senha configurada no sistema usando senha padrão >> 1234 ")

    return senha_autenticacao_ativa

def salvar_senha_autenticacao(senha):
    """
    Salva a senha no arquivo Authentication.cfg.
    Retorna True em caso de sucesso, False em caso de erro.
    """

    # Ler o arquivo de autenticação
    auth_data = ler_arquivo_autenticacao()
    if auth_data is None:
        log_queue.put("salvar_senha_autenticacao: Não foi possível ler o arquivo de autenticação.")
        return False

    # Adicionar ou atualizar a senha no dicionário
    auth_data["senha"] = str(senha).strip()

    # Salvar o arquivo de autenticação
    success = salvar_arquivo_autenticacao(auth_data)
    if success:
        global senha_autenticacao_ativa
        senha_autenticacao_ativa = str(senha).strip()  # Atualiza a senha em memória
        return True
    else:
        log_queue.put("salvar_senha_autenticacao: Não foi possível salvar a senha no arquivo de autenticação.")
        return False

def resetar_senha_autenticacao():
    """
    Remove a senha do arquivo Authentication.cfg.
    Retorna True em caso de sucesso, False em caso de erro.
    """
    log_queue.put("resetar_senha_autenticacao: Tentando remover a senha do arquivo Authentication.cfg")

    # Ler o arquivo de autenticação
    auth_data = ler_arquivo_autenticacao()
    if auth_data is None:
        log_queue.put("resetar_senha_autenticacao: Não foi possível ler o arquivo de autenticação.")
        return False

    # Remover a senha do dicionário, se existir
    if "senha" in auth_data:
        del auth_data["senha"]

    # Salvar o arquivo de autenticação
    success = salvar_arquivo_autenticacao(auth_data)
    if success:
        global senha_autenticacao_ativa
        senha_autenticacao_ativa = str(senha_correta_padrao).strip() # Redefine a senha na memória
        log_queue.put("resetar_senha_autenticacao: Senha removida com sucesso do arquivo Authentication.cfg.")
        return True
    else:
        log_queue.put("resetar_senha_autenticacao: Não foi possível salvar as alterações no arquivo de autenticação.")
        return False
# ---------------------------------------------------------------------------------------------------


# --- Funções Auxiliares para Carregamento de Ícones (Prioridade: Arquivo Colorido > Qtawesome > QStyle Básico) ---
def get_icon_from_file(icon_name):
     """Tenta carregar um ícone de arquivo da pasta de imagens."""
     filename = ICON_FILENAMES.get(icon_name)
     if filename:
         file_path = os.path.join(BASE_PATH_IMAGES, filename)
         if os.path.exists(file_path):
             try:
                 icon = QIcon(file_path)
                 if not icon.isNull():
                     return icon
                 else:
                     print(f"Aviso: Arquivo de ícone '{filename}' encontrado em {file_path}, mas inválido ou vazio.")
                     log_queue.put(f"Aviso: Arquivo de ícone '{filename}' encontrado em {file_path}, mas inválido ou vazio.")
                     return None # Falha no carregamento do arquivo
             except Exception as e:
                 print(f"Erro ao carregar arquivo de ícone '{filename}' em {file_path}: {e}")
                 log_queue.put(f"Erro ao carregar arquivo de ícone '{filename}' em {file_path}: {e}")
                 return None # Falha no carregamento do arquivo
         # else:
             # print(f"DEBUG: Arquivo de ícone '{filename}' não encontrado.") # Debug se quiser ver quais faltam
     return None # Nome de arquivo não mapeado ou arquivo não encontrado

def get_qtawesome_icon(icon_name, icon_set):
    """Tenta obter um ícone qtawesome."""
    if qtawesome_available:
        try:
            qta_name = None
            if icon_set == "asset": qta_name = QTAWESOME_ASSET_ICONS.get(icon_name)
            elif icon_set == "toolbar": qta_name = QTAWESOME_TOOLBAR_ICONS.get(icon_name)
            elif icon_set == "menu": qta_name = QTAWESOME_MENU_ICONS.get(icon_name)

            if qta_name:
                 # Retorna o ícone qtawesome padrão (que pode ser colorido dependendo da fonte)
                 return awesome.icon(qta_name)
        except Exception as e:
            print(f"Aviso: Falha ao obter ícone qtawesome '{icon_name}' ({icon_set}): {e}. Usando fallback QStyle.")
            log_queue.put(f"Aviso: Falha ao obter ícone qtawesome '{icon_name}' ({icon_set}): {e}")
            pass # Cai para o próximo fallback

    return None # Qtawesome não disponível ou ícone não encontrado/falhou

def get_qstyle_icon(icon_name):
    """
    Tenta obter um ícone QStyle básico, corrigido para evitar o erro de 'name'.
    Mantém a estrutura lógica original da função.
    """
    try:
        # Pega a constante (ex: QStyle.SP_ComputerIcon) do seu dicionário de mapeamento
        qstyle_constant_value = QSTYLE_FALLBACK_ICONS.get(icon_name)

        # 1. Verifica se a chave 'icon_name' estava mapeada no seu dicionário
        if qstyle_constant_value is not None:
             # Se foi encontrada no dicionário, confia que o valor é uma constante válida
             # da enumeração QStyle.StandardPixmap e a passa diretamente.
             # Removemos a verificação hasattr que causava o erro.
             return QApplication.instance().style().standardIcon(qstyle_constant_value)

        # 2. Se a chave 'icon_name' não estava mapeada, usa o fallback.
        else:
             # Opcional: log para debug, se quiser saber quais ícones não estão mapeados
             # print(f"Aviso: Ícone QStyle '{icon_name}' não mapeado em QSTYLE_FALLBACK_ICONS. Usando SP_FileIcon.")
             return QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)
             
    # 3. O bloco except captura QUALQUER outro erro inesperado durante o processo
    except Exception as e:
        print(f"Erro inesperado ao carregar ícone QStyle '{icon_name}': {e}. Usando SP_FileIcon final.")
        if 'log_queue' in globals(): # Acesso seguro à fila de log
            log_queue.put((f"Erro ao carregar ícone QStyle '{icon_name}': {e}", "orange"))
        # Retorna um ícone genérico seguro em caso de QUALQUER erro.
        return QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)

def get_themed_icon(icon_name, icon_set="asset"):
    """
    Tenta obter um ícone na seguinte ordem de prioridade:
    1. Arquivo de imagem colorido (da pasta BASE_PATH_IMAGES)
    2. Qtawesome (se disponível)
    3. QStyle básico (fallback final)
    """
    # Tenta carregar do arquivo primeiro
    icon = get_icon_from_file(icon_name)
    if icon: return icon

    # Se não encontrou ou falhou no arquivo, tenta qtawesome
    icon = get_qtawesome_icon(icon_name, icon_set)
    if icon: return icon

    # Se não encontrou no qtawesome ou qtawesome não disponível, usa QStyle básico
    return get_qstyle_icon(icon_name)


    """Obtém um ícone QStyle padrão com base no nome lógico."""
    try:
        # Pega o VALOR da constante do dicionário (ex: QStyle.SP_ComputerIcon).
        qstyle_constant_value = QSTYLE_FALLBACK_ICONS.get(icon_name)

        if qstyle_constant_value:
             # CHAMA diretamente standardIcon passando o valor da constante.
             # Não precisa verificar hasattr(QStyle, qstyle_constant_value.name).
             return QApplication.instance().style().standardIcon(qstyle_constant_value)
        else:
             # Fallback final se o icon_name não estiver mapeado em QSTYLE_FALLBACK_ICONS.
             print(f"Aviso: Ícone QStyle '{icon_name}' não mapeado. Usando SP_FileIcon.")
             return QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)

    except Exception as e:
        print(f"Erro inesperado ao carregar ícone QStyle '{icon_name}': {e}. Usando SP_FileIcon.")
        return QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)
# -----------------------------------------------------------------------------------------------------------------



# --- Função responsavel pela elevação do AXE para ADM ---
def checar_e_elevacao_admin():    # Reexecutar como administrador, se necessário 
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        # Reexecuta e sai (não continua neste processo)
        script = os.path.abspath(__file__)
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 0)
        sys.exit(0)
# --------------------------------------------------------


# FUNÇOES RESPONSAVEIS PELA VERIFICAÇÃO E CRIAÇÃO DO SERVIÇO NO WINDONS
def run_command(command_args, log_queue: queue.Queue, shell=False, capture_output=True, text=True, check=False):
    """
    Executa um comando e retorna o resultado.
    Envia mensagens para a log_queue.
    """
    # Formata o comando para exibição no log
    if isinstance(command_args, list):
        cmd_display = ' '.join(f'"{arg}"' if ' ' in str(arg) else str(arg) for arg in command_args)
    else:
        cmd_display = command_args # Assume que é uma string de comando para shell=True


    try:
        # --- CORREÇÃO DE ENCODING AQUI ---
        # Especifica a codificação para decodificar a saída dos comandos sc.
        # cp1252 é comum em sistemas Windows com idioma português para a saída de console.
        # errors='replace' para evitar crash se houver algum caracter que mesmo cp1252 não entenda.
        result = subprocess.run(
            command_args,
            shell=shell,
            capture_output=capture_output,
            text=text,
            check=check,
            encoding='cp1252', # <-- Usando cp1252 para tentar corrigir caracteres da saída sc
            errors='replace' # <-- Substitui caracteres problemáticos por '?' ou similar
            # timeout=20 # Opcional: Adicionar um timeout
        )


        # Envia STDOUT e STDERR para a fila, mesmo em sucesso, para debug
        if capture_output:
             stdout_output = result.stdout.strip()
             stderr_output = result.stderr.strip()


        if result.returncode != 0:
            log_queue.put(f"[CMD] Comando falhou.")
            # A função chamadora é responsável por verificar o returncode


        return result
    except FileNotFoundError:
        cmd_name = command_args[0] if isinstance(command_args, list) else command_args.split()[0]
        msg = f"[CMD] ERRO: Comando '{cmd_name}' não encontrado. Certifique-se de que 'sc' está no PATH do sistema."
        log_queue.put(msg)
        return subprocess.CompletedProcess(command_args, 999, stdout='', stderr=msg) # Usar código de erro customizado
    except PermissionError:
        msg = "[CMD] ERRO de Permissão ao tentar executar o subprocesso. O script NÃO ESTÁ RODANDO como Administrador ou há um problema de permissão no arquivo do script/python."
        log_queue.put(msg)
        return subprocess.CompletedProcess(command_args, 998, stdout='', stderr=msg) # Usar código de erro customizado
    except Exception as e:
        msg = f"[CMD] Ocorreu um erro inesperado ao executar o comando: {e}"
        log_queue.put(msg)
        return subprocess.CompletedProcess(command_args, 997, stdout='', stderr=msg) # Usar código de erro customizado

def service_exists(service_name, log_queue: queue.Queue):
    """
    Verifica se um serviço com o nome especificado existe.
    Envia mensagens para a log_queue.
    """
    log_queue.put(f"\n[STATUS] Verificando se o serviço '{service_name}' existe...")
    # sc qc <service_name> retorna 0 se existe, 1060 se não.
    # Usar lista de argumentos para comando simples, shell=False (padrão) é seguro aqui.
    result = run_command(["sc", "qc", service_name], log_queue=log_queue, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        log_queue.put(f"SISTEMA  |  [STATUS] Serviço '{service_name}' encontrado.")
        return True
    # Código 1060: O serviço especificado não existe.
    elif result.returncode == 1060:
         log_queue.put(f"SISTEMA  |  [STATUS] Serviço '{service_name}' NÃO encontrado (Código 1060).")
         return False
    else:
        # Outros erros (ex: permissão negada, embora assumimos admin aqui)
        log_queue.put(f"SISTEMA  |  [STATUS] Erro inesperado ({result.returncode}) ao verificar a existência do serviço: {result.stderr.strip()}")
        # Se não conseguimos consultar, agimos como se não tivesse sido encontrado ou houvesse um erro crítico
        return False

def create_service(service_name, bin_path, display_name, log_queue: queue.Queue):
    """
    Cria um novo serviço do Windows.
    Envia mensagens para a log_queue.
    """
    log_queue.put(f"SISTEMA  |  [CREATE] Tentando criar o serviço '{service_name}'...")
    # --- Usando a sintaxe que você validou manualmente ---
    # `binPath= "C:\..."` com o espaço. Usar shell=True para o CMD parsear corretamente.
    # Mantendo aspas em service_name caso contenha espaços.
    command = f'sc create "{service_name}" binPath= "{bin_path}" start= auto DisplayName= "{display_name}"'

    log_queue.put(f"SISTEMA  |  [CREATE] Comando SC CREATE formatado: {command}")

    # shell=True para interpretar a string completa como no CMD
    result = run_command(command, log_queue=log_queue, shell=True, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        log_queue.put(f"SISTEMA  |  [CREATE] Serviço '{service_name}' criado com sucesso!")
        return True
    elif result.returncode == 1073: # Código 1073: O serviço especificado já existe
         log_queue.put(f"SISTEMA  |  [CREATE] Aviso: Serviço '{service_name}' já existe (Código 1073). Não foi necessário criar.")
         # Se o comando create retorna 1073, significa que o serviço já existe.
         # Para o fluxo principal, isso é um sucesso no sentido de que o serviço 'existe'.
         return True
    else:
        log_queue.put(f"SISTEMA  |  [CREATE] Falha ao criar o serviço '{service_name}'. Código de retorno: {result.returncode}")
        log_queue.put("SISTEMA  |  [CREATE] Causa comum: caminho do binário incorreto, sintaxe do comando, ou permissão persistente (embora assumamos admin).")
        return False

def get_service_status(service_name, log_queue: queue.Queue):
    """
    Verifica o status atual de um serviço e retorna uma string normalizada.
    Envia mensagens para a log_queue.
    Funciona tanto em Windows em português (ESTADO) quanto em inglês (STATE).
    """
    #log_queue.put(f"\n[QUERY] Verificando status do serviço '{service_name}'...")
    # sc query <service_name> retorna status 0 se sucesso (mesmo parado), 1060 se não existe
    result = run_command(
        ["sc", "query", service_name], 
        log_queue=log_queue, 
        capture_output=True, 
        text=True, 
        check=False
    )

    if result.returncode != 0:
        if result.returncode == 1060:
            #log_queue.put(f"SISTEMA  |  [QUERY] Serviço '{service_name}' NÃO encontrado (Código 1060).")
            return "NOT_FOUND"
        elif result.returncode == 5:
            #log_queue.put(f"SISTEMA  |  [QUERY] ERRO: Acesso negado ao consultar serviço '{service_name}' (Código 5). Confirme que a aplicação está rodando como Admin.")
            return "PERMISSION_DENIED_QUERY"
        else:
            #log_queue.put(f"SISTEMA  |  [QUERY] ERRO: Não foi possível obter o status do serviço '{service_name}' (Código {result.returncode}).")
            return "QUERY_FAILED"

    # Analisar a saída para encontrar a linha 'STATE' (inglês) ou 'ESTADO' (português)
    status_line = None
    raw_output = result.stdout

    for line in raw_output.splitlines():
        lstr = line.strip().upper()
        if lstr.startswith("STATE") or lstr.startswith("ESTADO"):
            status_line = line.strip()
            break

    if status_line:
        try:
            # Exemplo: "ESTADO                     : 4  RUNNING"
            parts = status_line.split(':', 1)
            if len(parts) > 1:
                status_info = parts[1].strip().split()
                if len(status_info) > 1:
                    status = status_info[1].upper().strip('.,')
                    return status
                else:
                    return "UNKNOWN_STATUS_PARSE_ERROR_SHORT_LINE"
            else:
                return "UNKNOWN_STATUS_PARSE_ERROR_NO_COLON"
        except Exception as e:
            return "UNKNOWN_STATUS_PARSE_EXCEPTION"
    else:
        #log_queue.put("SISTEMA  |  [QUERY] AVISO: Comando SC QUERY retornou sucesso (0), mas não encontrou a linha 'STATE' ou 'ESTADO'.")
        #log_queue.put(f"SISTEMA  |  [QUERY] RAW STDOUT:\n{raw_output}")
        #log_queue.put(f"SISTEMA  |  [QUERY] RAW STDERR:\n{result.stderr.strip()}")
        return "UNKNOWN_NO_STATE_LINE"

def start_service(service_name, log_queue: queue.Queue):
    """
    Inicia um serviço do Windows e verifica o status final.
    Envia mensagens para a log_queue.
    """
    log_queue.put(f"SISTEMA  |  [START] Tentando iniciar o serviço '{service_name}'...")
    # Comando sc start é simples, lista de argumentos, shell=False (padrão)
    start_command = ["sc", "start", service_name]
    result = run_command(start_command, log_queue=log_queue, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        log_queue.put(f"SISTEMA  |  [START] Comando 'sc start {service_name}' executado com sucesso.")
        log_queue.put("SISTEMA  |  [START] O serviço DEVE estar RODANDO ou em START_PENDING.")
        log_queue.put("SISTEMA  |  [START] Aguardando 5 segundos para verificar o status final...")
        time.sleep(5) # Espera para o serviço realmente iniciar
        # Verifica o status final após a tentativa de iniciar
        final_status = get_service_status(service_name, log_queue) # Passa a queue
        log_queue.put(f"SISTEMA  |  [START] Status final após tentativa de início: {final_status}")
        return final_status # Retorna o status real encontrado
    else:
        log_queue.put(f"SISTEMA  |  [START] Falha no comando 'sc start {service_name}'. Código de retorno: {result.returncode}")
        log_queue.put("SISTEMA  |  [START] Verificando causas comuns...")

        # Código 1056: O serviço especificado já está rodando.
        if result.returncode == 1056:
             log_queue.put("SISTEMA  |  [START] Diagnóstico: Serviço já está rodando (código 1056).")
             # Verificação posterior confirma que está rodando?
             log_queue.put("SISTEMA  |  [START] Verificando status para confirmar que está RUNNING...")
             status_after_failed_start = get_service_status(service_name, log_queue) # Passa a queue
             if status_after_failed_start == "RUNNING":
                  log_queue.put("SISTEMA  |  [START] Verificação confirma: Serviço está RUNNING.")
                  return "RUNNING" # Consideramos sucesso
             else:
                  # Reportou 1056 mas não está RUNNING? Estado inconsistente.
                  log_queue.put(f"SISTEMA  |  [START] ERRO: Verificação reportou status: {status_after_failed_start}. Estado inconsistente após código 1056.")
                  return "START_COMMAND_REPORTED_RUNNING_BUT_STATUS_DIFFERS"

        # Código 1053: O serviço não respondeu à requisição de início...
        elif result.returncode == 1053:
             log_queue.put("SISTEMA  |  [START] Diagnóstico: Serviço não respondeu ao início (código 1053).")
             log_queue.put("SISTEMA  |  [START] Causa comum: O executável do serviço falhou ao iniciar ou travou. Verifique logs de eventos do Windows.")
             # Mesmo com erro 1053, verificar status final pode mostrar STOPPED ou outro estado
             log_queue.put("SISTEMA  |  [START] Verificando status após erro 1053...")
             status_after_failed_start = get_service_status(service_name, log_queue) # Passa a queue
             # Retorna o status real encontrado, a menos que a verificação também falhe
             return status_after_failed_start if status_after_failed_start not in ["NOT_FOUND", "QUERY_FAILED", "PERMISSION_DENIED_QUERY"] else "START_COMMAND_FAILED_SERVICE_DID_NOT_RESPOND"

        # Código 5: Acesso negado (Falta de permissão) - importante reportar
        elif result.returncode == 5:
             log_queue.put("SISTEMA  |  [START] ERRO: Acesso negado (código 5). Confirme que a aplicação está rodando como Administrador.")
             return "PERMISSION_DENIED_START_COMMAND"

        # Outros códigos de erro de start (ex: 2 - binário não encontrado, 1069 - falha na inicialização)
        else:
            log_queue.put(f"SISTEMA  |  [START] Falha no comando start por um motivo desconhecido/não tratado. Código: {result.returncode}")
            # Tenta obter o status para ver onde parou
            log_queue.put("SISTEMA  |  [START] Verificando status após falha...")
            status_after_failed_start = get_service_status(service_name, log_queue) # Passa a queue
            # Retorna o status real encontrado, a menos que a verificação também falhe
            return status_after_failed_start if status_after_failed_start not in ["NOT_FOUND", "QUERY_FAILED", "PERMISSION_DENIED_QUERY"] else f"START_COMMAND_FAILED_CODE_{result.returncode}"

def verificar_servico_criar_start(service_name: str, bin_path: str, display_name: str) -> str:
    """
    Verifica se o serviço existe, cria se necessário, e tenta iniciar.
    Envia todos os logs para a log_queue.
    Assumimos que a aplicação já está rodando com privilégios de Administrador.

    Args:
        log_queue: A fila (Queue) para enviar as mensagens de log.
        service_name: O nome interno do serviço (usado pelos comandos sc).
        bin_path: O caminho completo para o executável do serviço.
        display_name: O nome de exibição do serviço.

    Returns:
        O status final do serviço ('RUNNING', 'STOPPED', 'FAILED_TO_CREATE',
        'START_COMMAND_FAILED', etc.) ou um código de erro específico.
    """
    log_queue.put(f"SISTEMA  |  Gerenciando InLogic Service: {display_name} ({service_name}) ---")


    # 1. Verificar o status inicial do serviço
    log_queue.put(f"SISTEMA  |  Verificando status inicial do serviço '{service_name}'.")
    # Passa a queue para get_service_status
    initial_status = get_service_status(service_name, log_queue)

    # Se o serviço não foi encontrado, tentar criar
    if initial_status == "NOT_FOUND":
        log_queue.put(f"SISTEMA  |  Serviço '{service_name}' não encontrado. Tentando criar...")
        # Passa a queue para create_service
        if create_service(service_name, bin_path, display_name, log_queue):
            log_queue.put("SISTEMA  |  Comando de criação executado. Aguardando e verificando status pós-criação...")
            time.sleep(3) # Pequena espera após a criação
            # Após criar, verificar o status novamente (passando a queue)
            status_after_create = get_service_status(service_name, log_queue)
            log_queue.put(f"SISTEMA  |  Status reportado após criação: {status_after_create}")

            if status_after_create == "RUNNING":
                 log_queue.put("SISTEMA  |  Serviço iniciou automaticamente após a criação (start=auto funcionou). Sucesso!")
                 return "RUNNING"
            elif status_after_create == "STOPPED":
                 log_queue.put("SISTEMA  |  Serviço criado, mas não iniciou automaticamente. Procedendo para tentar iniciar manualmente...")
                 # Continua para a lógica de start abaixo
            # Casos de erro após criação que precisam ser tratados
            elif status_after_create in ["NOT_FOUND", "QUERY_FAILED", "PERMISSION_DENIED_QUERY"]:
                 log_queue.put(f"SISTEMA  |   ERRO CRÍTICO: Comando de criação reportou sucesso/já existente, mas não conseguimos consultar o status logo depois (Status: {status_after_create}). Algo deu errado na criação ou permissões persistentes.")
                 return f"CREATED_COMMAND_SUCCESS_BUT_QUERY_FAILED_AFTER_WITH_{status_after_create}"
            else: # START_PENDING, PAUSED, ou algum parse error
                 log_queue.put(f"SISTEMA  |  Serviço criado, status inesperado ({status_after_create}). Tentando iniciar manualmente mesmo assim.")
                 # Continua para a lógica de start abaixo


        else:
            log_queue.put("SISTEMA  |  Falha crítica: Não foi possível criar o serviço.")
            # create_service já logou os detalhes do erro
            return "FAILED_TO_CREATE" # Retorna falha na criação

    # Se o serviço existe mas não está rodando, tentar iniciar
    elif initial_status != "RUNNING":
        log_queue.put(f"SISTEMA  |  Serviço '{service_name}' existe, mas não está rodando (Status: {initial_status}). Tentando iniciar...")
        # Continua para a lógica de start abaixo (o start_service já verifica o status final)

    # Se o serviço já está rodando, nada a fazer
    else: # initial_status == "RUNNING"
        log_queue.put(f"SISTEMA  |  Serviço '{service_name}' já está rodando (Status: {initial_status}). Nada a fazer.")
        return "RUNNING" # Retorna RUNNING

    # 2. Tentar iniciar o serviço (se o fluxo anterior decidiu que precisa)
    # Este bloco só é alcançado se o initial_status não era RUNNING, e a criação (se necessária) foi bem sucedida/pulada.
    log_queue.put(f"SISTEMA  |  Procedendo para tentar iniciar o serviço '{service_name}'...")
    # Passa a queue para start_service
    final_status = start_service(service_name, log_queue) # start_service já espera e verifica o status final

    log_queue.put(f"SISTEMA  |   Processo de início concluído. Status final reportado: {final_status}")

    return final_status # Retorna o status final reportado pela função start_service

    # Função responsavel por iniciar o service windons , verificar etc
# ----------------------------------------------------------------------




#  FUNÇOES RESPONSAVEL PELO SISTEMA DE GESTÃO DE ATIVAÇÃO DE LICENÇAS ETC 
def _fazer_requisicao_api_licenca(endpoint: str, method: str = 'GET', data: dict = None) -> dict:
    """
    Faz uma requisição HTTP autenticada para a API de licenciamento no servidor.
    Endpoint deve ser a parte específica da API (ex: "/licenses/activate/{chave}").
    Retorna o dicionário JSON da resposta do servidor ou um dicionário com detalhes do erro.
    """
    url_completa = f"{URL_SITE_LICENCA}/wp-json/dlm/v1{endpoint}"
    auth = HTTPBasicAuth(CONSUMER_KEY_LICENCA, CONSUMER_SECRET_LICENCA)
    headers = HEADERS_API_LICENCA.copy() # Usa uma cópia dos headers base

    print(f"[LIC API REQ] Método: {method}, URL: {url_completa}") # Log básico da requisição

    try:
        if method.upper() == 'GET':
            # Parâmetros de GET devem estar no ENDPOINT ou adicionados aqui se não.
            # A API de ativação (v1) usa GET com parâmetros.
            # A string URL 'url_completa' já deve conter os parâmetros para GETs da API v1 como você usa em ativar_licenca.
            resp = requests.get(url_completa, headers=headers, auth=auth)

        elif method.upper() == 'POST':
            # Adicionar header Content-Type para POST/JSON
            headers['Content-Type'] = 'application/json'
            resp = requests.post(url_completa, headers=headers, auth=auth, json=data)

        else:
            return {"sucesso": False, "status_http": "N/A", "codigo_api": "metodo_nao_suportado", "mensagem": f"Método HTTP '{method}' não suportado pela função interna.", "resposta_bruta": None}

        # Levanta uma exceção HTTPError para respostas de erro 4xx/5xx
        resp.raise_for_status()

        # Tenta parsear a resposta como JSON
        try:
            resposta_json = resp.json()
            # Incluir status HTTP na resposta JSON para info adicional
            resposta_json['status_http'] = resp.status_code
            return resposta_json # Retorna o dicionário da resposta JSON do servidor

        except json.JSONDecodeError as jde:
            # Falha ao parsear a resposta como JSON
            return {
                "sucesso": False,
                "status_http": resp.status_code,
                "codigo_api": "json_decode_erro",
                "mensagem": f"Resposta inesperada do servidor: Não é JSON válido. Detalhe: {jde}",
                "resposta_bruta": resp.text # Incluir texto da resposta para diagnóstico
            }

    except requests.exceptions.HTTPError as httperr:
        # Captura erros HTTP (4xx ou 5xx) após raise_for_status()
        # O servidor pode ter retornado um corpo de resposta JSON mesmo com erro HTTP
        error_details = {}
        try:
            error_details = httperr.response.json()
        except json.JSONDecodeError:
            # Resposta de erro HTTP, mas corpo não era JSON
            error_details = {"resposta_bruta_erro": httperr.response.text}

        return {
            "sucesso": False,
            "status_http": httperr.response.status_code if httperr.response else 'N/A',
            "codigo_api": error_details.get("code", "erro_http"), # Tenta pegar código de erro da API se no corpo JSON
            "mensagem": error_details.get("message", f"Erro HTTP: {httperr}. Resposta: {httperr.response.text[:100]}..."), # Tenta pegar mensagem da API
            "resposta_bruta": error_details.get("resposta_bruta_erro", None) # Incluir corpo da resposta bruta se não JSON
        }

    except requests.exceptions.RequestException as reqerr:
        # Captura outros erros requests (rede, timeout, etc.)
        return {
            "sucesso": False,
            "status_http": 'N/A',
            "codigo_api": "erro_requisiticao",
            "mensagem": f"Erro na requisição de rede: {reqerr}",
            "resposta_bruta": None
        }

    except Exception as e:
        # Captura outros erros inesperados
        return {
            "sucesso": False,
            "status_http": 'N/A',
            "codigo_api": "erro_interno",
            "mensagem": f"Erro interno inesperado durante a requisição API: {e}",
            "resposta_bruta": None
        }

def ativar_licenca(chave_licenca: str, instance_id: str) -> dict:
    """
    Chama a API para ativar uma chave de licença com um determinado instance ID.
    Retorna o dicionário resultado de _fazer_requisicao_api_licenca.
    """
    # Note: A API v1 de ativação usa um GET com parâmetros na URL.
    # Construimos o endpoint COMPLETO aqui, incluindo chave e parâmetros.
    endpoint_ativacao = (
        f"/licenses/activate/{chave_licenca}"
        f"?instance={instance_id}&label={instance_id}" # Adicionando instance e label como parâmetros de GET
    )
    return _fazer_requisicao_api_licenca(endpoint_ativacao, method='GET')

def montar_dados_licenca_ativacao(resposta_api: dict, instance_id: str, license_key: str) -> dict:
    """
    Processa a resposta bruta (dict) obtida de 'ativar_licenca' e monta
    um dicionário padronizado para salvamento e exibição na UI.
    Aceita respostas com campos em português ou inglês.
    """
    print("[LIC PROCESSAMENTO] Iniciando processamento da resposta da API...")

    dados_processados = {
        "modo": "ativacao",
        "status": "PROCESSANDO_FALHOU",
        "sucesso": False,
        "instance_id": instance_id,
        "token": None,
        "license_key": license_key,
        "expires_at": None,
        "ativacoes": None,
        "limite_ativacoes": None,
        "mensagem": "Não foi possível determinar o status ou processar a resposta da API de ativação.",
        "status_http": None,
        "codigo_api": None,
    }

    if isinstance(resposta_api, dict):
        # Suporte a campo em inglês ou português
        success = resposta_api.get("success", resposta_api.get("sucesso"))
        message = resposta_api.get("message", resposta_api.get("mensagem"))
        code = resposta_api.get("code", resposta_api.get("codigo_api"))
        status_http = resposta_api.get("status_http")
        # Se status_http vier como string e for número, converte para int
        if isinstance(status_http, str) and status_http.isdigit():
            status_http = int(status_http)

        # Erro técnico (rede, HTTP, parse)
        if "erro" in resposta_api or (
            (success is False) and status_http is not None and isinstance(status_http, int) and status_http >= 400
        ):
            dados_processados["status"] = "ERRO_COMUNICACAO"
            dados_processados["mensagem"] = message or resposta_api.get("erro", "Falha na comunicação ou resposta técnica da API.")
            dados_processados["status_http"] = status_http
            dados_processados["codigo_api"] = code or "N/A_erro_req"
            print("[LIC PROCESSAMENTO] Resposta processada como ERRO TÉCNICO de comunicação/formato.")

        # Resposta da API de licença
        elif success is not None:
            dados_processados["status_http"] = status_http or "N/A_api"
            if success is True:
                dados_payload = resposta_api.get("data", {})
                dados_licenca = dados_payload.get("license", {})
                dados_processados["status"] = "ATIVADA_SUCESSO"
                dados_processados["sucesso"] = True
                dados_processados["token"] = dados_payload.get("token")
                dados_processados["license_key"] = dados_licenca.get("license_key", license_key)
                dados_processados["expires_at"] = dados_licenca.get("expires_at")
                dados_processados["ativacoes"] = dados_licenca.get("times_activated")
                dados_processados["limite_ativacoes"] = dados_licenca.get("activations_limit")
                dados_processados["mensagem"] = message or "Licença ativada e registrada no servidor."
                print("[LIC PROCESSAMENTO] Resposta da API processada como SUCESSO.")
            else:
                dados_processados["status"] = "API_REJEITOU"
                dados_processados["mensagem"] = f"Ativação rejeitada pela API ({code or 'N/A'}): {message or 'Motivo de falha da API não especificado.'}"
                dados_processados["codigo_api"] = code or "N/A"
                dados_payload = resposta_api.get("data", {})
                dados_licenca = dados_payload.get("license", {})
                dados_processados["license_key"] = dados_licenca.get("license_key", license_key)
                print(f"[LIC PROCESSAMENTO] Resposta da API processada como FALHA LÓGICA. Código API: {code or 'N/A'}")

        # Estrutura não reconhecida
        else:
            dados_processados["status"] = "ERRO_PROCESSAMENTO"
            dados_processados["mensagem"] = f"Não foi possível processar o tipo de resposta recebida da API: {type(resposta_api).__name__}. Conteúdo inicial: {str(resposta_api)[:100]}..."
            print(f"[LIC PROCESSAMENTO] Resposta processada como FORMATO INESPERADO. Tipo: {type(resposta_api).__name__}")

    else:
        dados_processados["status"] = "ERRO_PROCESSAMENTO"
        dados_processados["mensagem"] = f"Tipo de resposta inesperado recebido da função 'ativar_licenca': {type(resposta_api).__name__}."
        print(f"[LIC PROCESSAMENTO] ERRO: resposta_api não é dict: {type(resposta_api).__name__}")

    return dados_processados

def salvar_json_licenca(dados_licenca: dict, path_arquivo: str):
    """
    Salva os dados da licença como JSON formatado e criptografado binário em um arquivo.
    Espera um dicionário 'dados_licenca' e o caminho completo 'path_arquivo' para salvar.
    Cria os diretórios pai do arquivo se não existirem.
    **Lança (re-levanta) exceções** se houver falha na serialização JSON,
    criptografia ou operação de escrita no disco.
    Quem chama esta função é responsável por tratar estas exceções.
    """
    # Logs básicos para console ou sistema de log, se log_queue não for diretamente acessível aqui.
    # Em funções globais de I/O/processamento de dados, print() ou a biblioteca 'logging' são comuns.
    print(f"[LIC SALVAR BASE] Tentando serializar, criptografar e salvar dados no arquivo: {path_arquivo}")

    try:
        # 1. Serializa o dicionário Python para uma string JSON.
        # ensure_ascii=False permite caracteres não-ASCII (acentos, etc.) sem escapes.
        # indent=2 torna o JSON mais legível para debug (mesmo sendo criptografado).
        dados_json_string = json.dumps(dados_licenca, ensure_ascii=False, indent=2)
        # 2. Converte a string JSON para bytes usando a codificação UTF-8.
        dados_json_bytes = dados_json_string.encode("utf-8")

        # 3. Criptografa os bytes JSON.
        # Chama a função GLOBAL 'criptografar_dados'.
        # Esta função deve pegar os bytes 'dados_json_bytes', fazer a criptografia AES+IV e
        # possivelmente Base64 encode, retornando BYTES (codificados em Base64 no seu caso).
        # Ela deve lançar exceção se a criptografia falhar (ex: chave inválida, bibliotecas faltantes - embora isso deveria ser pego antes).
        dados_criptografados_bytes = criptografar_dados(dados_json_bytes) # <<< CHAMA SUA FUNÇÃO GLOBAL 'criptografar_dados'!

        # Verifica se a criptografia retornou bytes válidos
        if not isinstance(dados_criptografados_bytes, bytes) or not dados_criptografados_bytes:
             raise RuntimeError("A função 'criptografar_dados' não retornou bytes válidos ou dados criptografados vazios.")

        # 4. Garante que o diretório onde o arquivo será salvo existe.
        diretorio_arquivo = os.path.dirname(path_arquivo)
        # makedirs cria diretórios recursivamente. exist_ok=True evita erro se já existir.
        os.makedirs(diretorio_arquivo, exist_ok=True)

        # 5. Abre o arquivo para escrita em modo binário ('wb').
        # 'wb' é crucial, pois os dados criptografados/Base64 SÃO BINÁRIOS, não texto simples.
        # Usa o bloco 'with open(...):' para garantir que o arquivo é fechado automaticamente.
        with open(path_arquivo, "wb") as f:
            # Escreve os bytes criptografados (Base64) no arquivo.
            f.write(dados_criptografados_bytes)

        # 6. Se chegou até aqui sem levantar exceção, o salvamento base foi um sucesso.
        print(f"[OK LIC SALVAR BASE] Dados salvos com sucesso em: {path_arquivo}")

    except FileNotFoundError:
         # Exceção mais específica se o diretório pai não puder ser criado (improvável com exist_ok=True, mas possível).
         # Ou se o path_arquivo for inválido de alguma forma que impede a abertura.
         print(f"[ERRO LIC SALVAR BASE] Falha no caminho do arquivo ou diretório não criável: {path_arquivo}")
         raise # Re-levanta a exceção para o chamador tratar (salvar_json_licenca_ativacao -> _lidar_com_solicitacao_ativacao).

    except Exception as e:
        # Captura QUALQUER outra exceção que ocorra no try (json.dumps, encode, criptografia, os.makedirs, open, write).
        # Por exemplo: PermissionError (sem permissão de escrita), OSError, etc.
        print(f"[ERRO LIC SALVAR BASE FATAL] Falha crítica inesperada ao salvar arquivo '{path_arquivo}': {e}")
        # É VITAL RE-LEVAR esta exceção. O código que chamou salvar_json_licenca (salvar_json_licenca_ativacao)
        # não sabe se o salvamento REALMENTE ocorreu a menos que esta função indique sucesso ou falha.
        raise e # <<< RE-LEVANTA A EXCEÇÃO! O chamador (salvar_json_licenca_ativacao) ou quem a chamou (_lidar_com_solicitacao_ativacao) DEVE CATCH!

def salvar_json_licenca_ativacao(dados_licenca_atuais: dict, path_arquivo: str):
    """
    Salva os dados processados de ativação (retornados por montar_dados_licenca_ativacao).
    Implementa lógica para PRESERVAR TOKEN e talvez outros campos (como key, instance_id)
    do arquivo antigo caso a tentativa de ativação ATUAL não tenha sido um sucesso
    E o arquivo antigo existia com esses dados.
    Chama salvar_json_licenca base para a escrita final.
    Lança exceções se ler_json_licenca ou salvar_json_licenca lançarem.
    """
    print(f"[LIC SALVAR ATIVACAO] Preparando para salvar arquivo de ativação: {path_arquivo}")
    token_antigo_valido = None
    dados_antigos_validos = None

    # Tenta ler o arquivo existente APENAS se ele existe no disco
    if os.path.isfile(path_arquivo):
        # ler_json_licenca lida com erros internos (corrompido/vazio/não descriptografável) e retorna {} ou None.
        dados_antigos_lidos = ler_json_licenca(path_arquivo) # <<< Chama GLOBAL!

        # Verifica se a leitura do arquivo antigo foi bem-sucedida e resultou em um dicionário populado
        if isinstance(dados_antigos_lidos, dict) and dados_antigos_lidos:
             dados_antigos_validos = dados_antigos_lidos
             if dados_antigos_validos.get("token"):
                 token_antigo_valido = dados_antigos_validos["token"]
                 print("[LIC SALVAR ATIVACAO] Encontrado token válido no arquivo antigo lido.")
             else:
                  print("[LIC SALVAR ATIVACAO] Arquivo antigo lido, mas sem token válido.")
        else:
             # ler_json_licenca retornou None ou {}. Loga isso internamente.
            print(f"[AVISO LIC SALVAR ATIVACAO] Arquivo '{path_arquivo}' encontrado, mas a leitura (ler_json_licenca) falhou (retornou None ou {{}}). Não preservando dados antigos.")

    # Lógica de preservação de dados:
    # VERIFICAÇÃO CHAVE: Os dados QUE VÊM da *última tentativa de ativação*
    # (passados como dados_licenca_atuais) INDICAM SUCESSO GERAL ("sucesso": True) OU NÃO?
    # E se NÃO indicam sucesso, EXISTIA um token antigo VÁLIDO no arquivo anterior?
    if not dados_licenca_atuais.get("sucesso") and token_antigo_valido:
        # A ATIVAÇÃO ATUAL FALHOU (seja falha da API ou comunicação/processamento),
        # mas existia um token válido antes. Preservar o token antigo.
        # Este é o token que talvez possa ser usado para VALIDAR offline depois.
        dados_licenca_atuais["token"] = token_antigo_valido
        # Você PODE querer preservar outros campos essenciais aqui (como a license_key, expires_at)
        # se a ativação atual falhou e você confia nos dados antigos.
        # if dados_antigos_validos: # Apenas copie se os dados antigos foram lidos com sucesso
        #     if not dados_licenca_atuais.get("license_key") and dados_antigos_validos.get("license_key"):
        #        dados_licenca_atuais["license_key"] = dados_antigos_validos["license_key"]
        #     if not dados_licenca_atuais.get("expires_at") and dados_antigos_validos.get("expires_at"):
        #        dados_licenca_atuais["expires_at"] = dados_antigos_validos.get("expires_at")

        print("[LIC SALVAR ATIVACAO] Ativação ATUAL falhou. Preservando dados (token/key/expires) do arquivo antigo nos dados A SEREM SALVOS.")


    # 3. Chama a função base salvar_json_licenca para a escrita final no arquivo.
    # Passa os dados (potencialmente modificados com dados antigos) e o caminho do arquivo.
    # Se salvar_json_licenca falhar (ex: erro de permissão, disco cheio), ela vai RE-LEVANTER
    # a exceção. A função chamadora (_lidar_com_solicitacao_ativacao) DEVE pegar esta exceção.
    print("[LIC SALVAR ATIVACAO] Chamando função base para salvar...")
    salvar_json_licenca(dados_licenca_atuais, path_arquivo) # <<< Chama a função GLOBAL BASE SALVAR_JSON_LICENCA!
    # Se chegou aqui sem exceção, a escrita ocorreu. Log OK já está na base.

def ler_json_licenca(path_arquivo: str) -> dict | None:
    """
    Tenta ler, descriptografar e carregar um arquivo JSON de licença genérico (.cfg).
    Assume que o arquivo contém dados CRIPTOGRAFADOS e CODIFICADOS EM Base64.
    Usa a função global 'descriptografar_json(string_b64_lida) -> dict'.
    Retorna o dicionário da licença em caso de sucesso.
    Retorna:
      - None: Se o arquivo NÃO for encontrado.
      - {}: Se o arquivo foi encontrado mas está vazio, o conteúdo criptografado
            ou Base64 está inválido/ilegível, a descriptografia falhou,
            ou o resultado não é um JSON válido ou não é um dicionário esperado.
          (Ou seja, algo no conteúdo ou criptografia/parsing está ruim, mas o arquivo existe).
    Não lança exceções (exceto por erros muito graves no open/read de baixo nível, que são menos comuns).
    Loga erros internamente no console (adapte para log_queue se chamar de contexto GUI).
    """
    print(f"[LIC LER BASE] Tentando ler de: {path_arquivo}")
    try:
        if not os.path.isfile(path_arquivo):
            print(f"[ERRO LIC LER BASE] Arquivo não encontrado: {path_arquivo}")
            return None # Retorna None se o arquivo não existe.

        # Abre o arquivo em modo BINÁRIO ('rb') para ler os BYTES codificados em Base64.
        # Isso é crucial, pois o Base64 lida com dados binários.
        with open(path_arquivo, "rb") as f:
            # Lê o conteúdo BINÁRIO do arquivo. Pode ser Base64 codificado.
            conteudo_bytes_lidos = f.read()

        if not conteudo_bytes_lidos or not conteudo_bytes_lidos.strip():
            # Se o arquivo foi lido, mas o conteúdo em bytes está vazio ou só espaços binários.
            print(f"[AVISO LIC LER BASE] Arquivo '{path_arquivo}' encontrado, mas está vazio.")
            return {} # Retorna dicionário vazio para arquivo encontrado, mas vazio.


        # O conteúdo lido SÃO OS BYTES CODIFICADOS em BASE64.
        # Para descriptografar, precisamos que descriptografar_json aceite esses BYTES (ou a string deles).
        # Sua função `descriptografar_json` na implementação global original recebia uma STRING, encodificava
        # para bytes UTF-8 e passava para `descriptografar_dados`. Isso era incorreto para Base64.

        # VAMOS CORRIGIR:
        # Assumimos que `descriptografar_dados` GLOBAL RECEBE BYTES Base64 e retorna BYTES descriptografados.
        # A `ler_json_licenca` ABRE em 'rb', OBTÉM BYTES. ESSES BYTES *PODEM SER* OS BYTES BASE64 DIRETAMENTE.
        # (Ex: se o arquivo foi escrito por `open('wb') + .write(b64encode(...))` ).

        # Tenta passar os bytes lidos DIRETAMENTE para a função global `descriptografar_json`,
        # ASSUMINDO QUE `descriptografar_json` foi corrigida para lidar com ESSES BYTES (B64).
        # *MELHOR:* Assumimos que `descriptografar_json` global *anterior* RECEBIA a string Base64
        # e fazia tudo dentro (b64decode, etc). Vamos reverter para o que era o intento.
        # Ou seja, ler_json_licenca LÊ BINÁRIO, DECODIFICA BINÁRIO->STRING BASE64 (UTF-8),
        # e passa essa string para descriptografar_json.

        try:
            # Tenta decodificar os bytes lidos como STRING UTF-8 (Assumindo que os dados no arquivo BINÁRIO eram texto UTF-8 Base64).
            conteudo_string_b64 = conteudo_bytes_lidos.decode("utf-8", errors='replace') # Decodifica bytes para string.
            # if not conteudo_string_b64.strip(): # String estava vazia ou só espaços
            #      print(f"[AVISO LIC LER BASE] Arquivo '{path_arquivo}' vazio após decodificar para string.")
            #      return {} # Trata como vazio


            # Chama a função GLOBAL `descriptografar_json` passando a STRING.
            # Essa função GLOBAL agora tem a responsabilidade de lidar com Base64 decode, descriptografia, JSON parse, etc.
            # Assume que `descriptografar_json` NÃO LANÇA EXCEÇÃO SE FALHAR INTERNAMENTE NA CRIPTOGRAFIA/JSON, E SIM RETORNA {} (dicionário vazio) ou None.
            dados_dicionario = descriptografar_json(conteudo_string_b64) # <<< CHAMA SUA FUNÇÃO GLOBAL que processa STRING Base64 -> DICT.

            # `descriptografar_json` deveria retornar DICT ({}) em caso de falha INTERNA (corrompido/não JSON/etc).
            # OU None se string Base64 inválida ou vazia passada a ela (embora já tratamos vazio acima).
            # Se ela retornou {} (dicionário vazio) ou None, significa que o conteúdo criptografado não pôde ser parseado.
            if not isinstance(dados_dicionario, dict) or not dados_dicionario:
                print(f"[ERRO LIC LER BASE] Conteúdo descriptografado/parseado de '{path_arquivo}' inválido (retornou None/{{}}).")
                return {} # Retorna {} para conteúdo inválido.

            # Se chegou aqui, `descriptografar_json` retornou um dicionário populado.
            print(f"[OK LIC LER BASE] Sucesso ao ler, descriptografar e parsear '{path_arquivo}'.")
            return dados_dicionario # Retorna o dicionário lido.


        except Exception as e:
            # Captura exceções durante a decodificação BINÁRIO->STRING (.decode) ou a chamada/erro SEVERO de `descriptografar_json` se ela levantar algo.
            # Erros dentro de descriptografar_json (como Base64, AES, JSON parse) DEVERIAM ser pegos por ela E FAZER ELA RETORNAR {}.
            # Mas este é um catch FINAL.
            print(f"[ERRO LIC LER BASE] Falha inesperada durante o processamento (decodificação ou descriptografia): {e}")
            return {} # Em caso de qualquer falha no processamento do conteúdo, retorna {}.

    except Exception as e:
        # Captura EXCEÇÕES que aconteçam na abertura ou leitura do arquivo BINÁRIO (open/read).
        # Ex: PermissionError. FileNotFoundError já tratada acima pelo os.path.isfile.
        print(f"[ERRO LIC LER BASE FATAL] Falha na leitura base do arquivo '{path_arquivo}': {e}")
        return None # Retorna None para erros GRAVES na leitura.

    return cor if isinstance(cor, QColor) else QColor(cor)

def _garante_qcolor(cor):
    """Garante que a cor é um objeto QColor, mesmo que venha como string HEX."""
    return cor if isinstance(cor, QColor) else QColor(cor)

def montar_dados_licenca_validacao(resposta_validacao):
    """
    Extrai dados essenciais de validação para uso e armazenamento.
    """
    dados = {
        "modo": "validacao",
        "status": "falha",
        "token": None,
        "license_key": None,
        "expires_at": None,
        "ativacoes": None,
        "limite_ativacoes": None,
        "deactivated_at": None,
        "mensagem": None,
        "sucesso": False,
    }
    if isinstance(resposta_validacao, dict) and resposta_validacao.get("success"):
        data = resposta_validacao.get("data", {})
        lic = data.get("license", {})
        dados["status"] = "sucesso"
        dados["token"] = data.get("token")
        dados["license_key"] = lic.get("license_key")
        dados["expires_at"] = lic.get("expires_at")
        dados["ativacoes"] = lic.get("times_activated")
        dados["limite_ativacoes"] = lic.get("activations_limit")
        dados["deactivated_at"] = data.get("deactivated_at")
        if data.get("deactivated_at") is None:
            dados["mensagem"] = "Licença ativa e válida."
            dados["sucesso"] = True
        else:
            dados["mensagem"] = f"Licença desativada em {data.get('deactivated_at')}"
    else:
        dados["mensagem"] = resposta_validacao.get("message", str(resposta_validacao))
    return dados

def validar_licenca_token(activation_token: str) -> dict:
    endpoint = f"/licenses/validate/{activation_token}"
    return _fazer_requisicao_api_licenca(endpoint, method='GET')

def analisar_licenca(dados_validacao):
    """
    Analisa a licença, detecta inconsistências (inclusive múltiplas),
    sempre atualiza o último registro validado se houve avanço de data/hora,
    e registra todos os motivos de falha.
    """
    from datetime import datetime
    import json

    motivos = []  # Lista de todos os motivos de falha/inconsistência
    licenca_valida = True
    agora = datetime.now()

    try:
        # --- 1. Extrai dados recebidos ---
        status = dados_validacao.get("sucesso")
        expires_at_str = dados_validacao.get("expires_at")
        mensagem = dados_validacao.get("mensagem")


        # --- 2. Lê arquivo de licença, se existir ---
        try:
            with open(LICENSE_FILE, 'rb') as f:
                conteudo_cfg = f.read()
            conteudo_descriptografado = descriptografar_dados(conteudo_cfg)
            dados_cfg = json.loads(conteudo_descriptografado.decode('utf-8'))
        except Exception:
            dados_cfg = {}


        # Dentro da função de validação:
        campos_obrigatorios = ["numero_serie", "dias", "ultima_atualização_dias", "ultima_verificacao_real", "ultimo_registro_validado"]
        campos_ausentes = [campo for campo in campos_obrigatorios if campo not in dados_cfg]

        if campos_ausentes:
            print(f"[INFO] Campos ausentes detectados: {campos_ausentes}. Inicializando arquivo de licença.")
            inicializar_arquivo_licenca()
            # Recarregue os dados após inicialização!
            try:
                with open(LICENSE_FILE, 'rb') as f:
                    conteudo_cfg = f.read()
                conteudo_descriptografado = descriptografar_dados(conteudo_cfg)
                dados_cfg = json.loads(conteudo_descriptografado.decode('utf-8'))
            except Exception:
                dados_cfg = {}


        # --- 3. Valida status da licença ---
        if not status:
            motivos.append(f"Status inválido. Mensagem: {mensagem}")
            licenca_valida = False

        # --- 4. Valida expiração ---
        try:
            expira_em = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
            if expira_em < agora:
                motivos.append(f"Licença expirada em {expires_at_str}")
                licenca_valida = False
        except Exception:
            motivos.append("Campo 'expires_at' ausente ou inválido")
            licenca_valida = False

        # --- 5. Valida campos internos (se não houve erros bloqueantes acima) ---
        if licenca_valida or True:  # Sempre tenta rodar para pegar todos os motivos possíveis!
            dias_restantes = None
            try:
                dias_restantes = (datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S") - agora).days
            except Exception:
                pass

            dias_utilizados = dados_cfg.get("dias")
            numero_serie_armazenado = dados_cfg.get("numero_serie")
            global numero_serie
            numero_serie_atual = numero_serie

            if numero_serie_atual == "SN_DESCONHECIDO":
                motivos.append("Falha ao obter número de série atual")
                licenca_valida = False

            if numero_serie_armazenado is None:
                motivos.append("Campo 'numero_serie' ausente")
                licenca_valida = False

            if numero_serie_atual and numero_serie_armazenado and numero_serie_atual != numero_serie_armazenado:
                motivos.append("Número de série divergente (armazenado: %s, atual: %s)" % (numero_serie_armazenado, numero_serie_atual))
                licenca_valida = False

            if dias_utilizados is None:
                motivos.append("Campo 'dias' ausente")
                licenca_valida = False
            elif dias_restantes is not None and dias_utilizados > dias_restantes:
                motivos.append(f"Dias utilizados ({dias_utilizados}) ultrapassam dias restantes ({dias_restantes})")
                licenca_valida = False

        # --- 6. Anti-fraude: data/hora ---
        formato_data = "%d-%m-%Y %H:%M:%S"
        ultimo_registro_str = dados_cfg.get("ultima_verificacao_real")
        ultimo_validado_str = dados_cfg.get("ultimo_registro_validado")
        atualizou_validado = False

        if ultimo_registro_str:
            try:
                data_ultimo = datetime.strptime(ultimo_registro_str, formato_data)
                if ultimo_validado_str:
                    data_validado = datetime.strptime(ultimo_validado_str, formato_data)
                    if data_ultimo < data_validado:
                        motivos.append(
                            f"Detectado retrocesso de data/hora: "
                            f"'ultima_verificacao_real' ({ultimo_registro_str}) < 'ultimo_registro_validado' ({ultimo_validado_str})"
                        )
                        licenca_valida = False
                        # NÃO atualiza o registro validado (retrocesso!)
                    elif data_ultimo > data_validado:
                        # Sempre atualiza se avançou, mesmo com licença inválida!
                        dados_cfg["ultimo_registro_validado"] = ultimo_registro_str
                        atualizou_validado = True
                else:
                    # Primeira validação, cria o campo
                    dados_cfg["ultimo_registro_validado"] = ultimo_registro_str
                    atualizou_validado = True
            except Exception as e:
                motivos.append(f"Erro ao comparar datas: {str(e)}")
                licenca_valida = False
        else:
            motivos.append("Campo 'ultima_verificacao_real' ausente")
            licenca_valida = False

        # --- 7. Atualiza status e motivos em dados_cfg ---
        dados_cfg["licenca"] = licenca_valida
        dados_cfg["motivo"] = " | ".join(motivos) if not licenca_valida else "Licença válida."
        # (use "|" ou "\n" para separar múltiplos motivos conforme sua preferência)

        # --- 8. Salva arquivo atualizado ---
        try:
            novo_json = json.dumps(dados_cfg, indent=4).encode('utf-8')
            novo_conteudo = criptografar_dados(novo_json)
            with open(LICENSE_FILE, 'wb') as f:
                f.write(novo_conteudo)
        except Exception as e:
            print(f"[ERRO] Falha ao salvar Authentication.cfg: {e}")
            log_queue.put((f"[ERRO] Falha ao salvar Authentication.cfg: {e}", "red"))

        # --- 9. Prints para debugging ---
        print(f"[INFO] Licença válida? {licenca_valida}")
        if motivos:
            print("[MOTIVOS]:")
            for m in motivos:
                print(f" - {m}")
                log_queue.put((f"[INFO]: {m}", "black"))
        if atualizou_validado:
            print(f"[INFO] 'ultimo_registro_validado' do arquivo validação atualizado para: {dados_cfg.get('ultimo_registro_validado')}")
            log_queue.put((f"[INFO] 'ultimo_registro_validado' do arquivo validação atualizado para: {dados_cfg.get('ultimo_registro_validado')}", "blue"))

    except Exception as e:
        print(f"[ERRO] Falha geral na análise da licença: {e}")
        log_queue.put((f"[ERRO] Falha geral na análise da licença: {e}", "red"))

def monitorar_licenca():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n[{timestamp}] Verificando licença...")
    #log_queue.put((f"\n[{timestamp}] Iniciando sistema [monitorar_licenca] >> Verificando...", "orange"))

    try:
        # --- Leitura do arquivo de ativação (criptografado) ---
        with open(CAMINHO_ARQUIVO_ATIVACAO, 'rb') as arquivo:
            conteudo_criptografado_ativacao = arquivo.read()

        # --- Descriptografar conteúdo e carregar JSON ---
        conteudo_descriptografado_ativacao = descriptografar_dados(conteudo_criptografado_ativacao)
        dados_json_ativacao = json.loads(conteudo_descriptografado_ativacao.decode('utf-8'))

        # --- Validar token obtido ---
        token = dados_json_ativacao.get("token")
        if not token:
            raise ValueError("Token não encontrado no arquivo de ativação.")

        try:
            resultado_validacao = validar_licenca_token(token)
            dados_licenca = montar_dados_licenca_validacao(resultado_validacao)
            salvar_json_licenca(dados_licenca, PATH_VALIDACAO)
        except Exception as e:
            log_queue.put((f"[ERRO] Falha ao validar token da licença: {type(e).__name__} - {e}", "red"))
            log_queue.put((traceback.format_exc(), "gray"))
            return  # Sai da função — validação falhou

        # --- Releitura do arquivo de validação salvo ---
        with open(PATH_VALIDACAO, 'rb') as arquivo:
            conteudo_criptografado = arquivo.read()

        conteudo_descriptografado = descriptografar_dados(conteudo_criptografado)
        dados_json = json.loads(conteudo_descriptografado.decode('utf-8'))

        # --- Analisar e aplicar dados de licença ---
        analisar_licenca(dados_json)

    except Exception as e:
        log_queue.put((f"[ERRO] Falha ao processar arquivo de licença: {type(e).__name__} - {e}", "red"))
        #log_queue.put((traceback.format_exc(), "gray"))
        print(f"[ERRO] Falha ao processar arquivo de licença: {e}")

def monitorar_dias_e_serial():
    global numero_serie

    print(f"\n[{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}] monitorar_dias_e_serial >> Verificando...")
    #log_queue.put((f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Iniciando sistema [monitorar_dias_e_serial] Verificando...", "orange"))

    try:
        with open(LICENSE_FILE, 'rb') as arquivo:
            conteudo_criptografado = arquivo.read()

        conteudo_descriptografado = descriptografar_dados(conteudo_criptografado)
        dados_json = json.loads(conteudo_descriptografado.decode('utf-8'))

        agora = datetime.now()
        formato_data = "%d-%m-%Y %H:%M:%S"


        # Cria ou atualiza ultima_verificacao_real
        dados_json["ultima_verificacao_real"] = agora.strftime(formato_data)
        print(f"[DEBUG] Salvando ultima_verificacao_real: {dados_json['ultima_verificacao_real']}")

        # Cria ou atualiza numero_serie
        if "numero_serie" not in dados_json:
            dados_json["numero_serie"] = numero_serie
            print(f"[INFO] Campo 'numero_serie' adicionado: {dados_json['numero_serie']}")

        # Inicializa dias e ultimo_registro se não existir
        if "dias" not in dados_json or "ultima_atualização_dias" not in dados_json:
            dados_json["dias"] = 1
            dados_json["ultima_atualização_dias"] = agora.strftime(formato_data)
            print(f"[INFO] Campo 'dias' inicializado com 1.")
        else:
            # Verifica se já passou 24h
            ultimo_registro = datetime.strptime(dados_json["ultima_atualização_dias"], formato_data)
            diferenca = agora - ultimo_registro

            if diferenca.total_seconds() >= 86400:  # 24 horas >> 86400
                dados_json["dias"] += 1
                dados_json["ultima_atualização_dias"] = agora.strftime(formato_data)
                print(f"[INFO] Incrementado 'dias' para {dados_json['dias']}.")
            else:
                horas_restantes = 24 - (diferenca.total_seconds() // 3600)
                print(f"[INFO] Ainda não passou 24h desde o último registro. Dias: {dados_json['dias']} - Próximo incremento em ~{int(horas_restantes)}h")
                #log_queue.put((f"[INFO] Ainda não passou 24h desde o último registro. Dias: {dados_json['dias']} - Próximo incremento em ~{int(horas_restantes)}h", "black"))

        # Recriptografa e salva
        json_atualizado_bytes = json.dumps(dados_json, indent=4).encode('utf-8')
        novo_conteudo_criptografado = criptografar_dados(json_atualizado_bytes)

        with open(LICENSE_FILE, 'wb') as arquivo:
            arquivo.write(novo_conteudo_criptografado)

    except Exception as e:
        print(f"[ERRO] Falha ao processar Authentication.cfg: {e}")
        log_queue.put((f"[ERRO] Falha ao processar arquivo  Authentication.cfg de licença: {e}", "red"))
# --------------------------------------------------------------------------


# --- Classes Janela de Calculos GUI ---
class JanelaCalculos(QDialog):

    def __init__(self, mem_list, operadores, parent=None, nome="", formula="", memoria_selecionada=""):
        super().__init__(parent)
        self.setWindowTitle("Editar Cálculo")
        self.layout = QVBoxLayout()

        # Campo para o nome do cálculo
        self.nome_input = QLineEdit(nome)
        self.nome_input.setPlaceholderText("Nome do Cálculo")
        self.layout.addWidget(QLabel("Nome:"))
        self.layout.addWidget(self.nome_input)

        # Lista suspensa para selecionar a memória
        self.memoria_combo = QComboBox()
        
        # Converte os valores de mem_list para strings
        mem_list_str = [str(mem) for mem in mem_list]
        self.memoria_combo.addItems(mem_list_str)
        
        # Define o valor selecionado, se houver
        if memoria_selecionada and str(memoria_selecionada) in mem_list_str:
            self.memoria_combo.setCurrentText(str(memoria_selecionada))
        
        self.layout.addWidget(QLabel("Memória:"))
        self.layout.addWidget(self.memoria_combo)

        # Campo para a fórmula
        self.formula_input = QLineEdit(formula)
        self.formula_input.setPlaceholderText("Ex: memoria + 2")
        self.layout.addWidget(QLabel("Fórmula:"))
        self.layout.addWidget(self.formula_input)

        # Botões de confirmação
        button_box = QHBoxLayout()
        save_button = QPushButton("Salvar")
        cancel_button = QPushButton("Cancelar")
        button_box.addWidget(save_button)
        button_box.addWidget(cancel_button)
        self.layout.addLayout(button_box)

        # Conecta os sinais dos botões
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)

        self.setLayout(self.layout)

    def get_dados(self):
        """
        Este método retorna os dados da janela, como o nome do cálculo e a fórmula.
        """
        return {
            'nome': self.nome_input.text(),
            'formula': self.formula_input.text(),
            'memoria': self.memoria_combo.currentText()  # Retorna o item selecionado da combo box
        } 
    
    @property
    def nome_calculo(self):
        return self.nome_input.text().strip()

    @property
    def expressao(self):
        return self.formula_input.text().strip()

    @property
    def memoria_selecionada(self):
        return self.memoria_combo.currentText().strip()
# --------------------------------------

# --- Classes Progressbar GUI ---
class Progressbar(QMainWindow): #  LASSE RESPONSAVEL PELA EXIBIÇÃO DO PROGRESSBAR
    
    def __init__(self, tempo=5000):
        """
        Inicializa a janela do ProgressBar.
        :param tempo: Tempo em milissegundos para exibir o ProgressBar antes de fechá-lo automaticamente.
        """
        super().__init__()
        self.setWindowTitle("Progresso")
        self.setGeometry(100, 100, 400, 150)
        self.setFixedSize(400, 150)  # Tamanho fixo
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)  # Janela sem bordas
        self.setAttribute(Qt.WA_TranslucentBackground)  # Fundo transparente

        # Central widget e layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Label de status
        self.label = QLabel("Processando...")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("color: black; font-size: 16px; font-weight: bold;")
        self.layout.addWidget(self.label)

        # ProgressBar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid black;
                border-radius: 5px;
                background-color: rgba(255, 255, 255, 50);
            }
            QProgressBar::chunk {
                background-color: #63b1fa;  /* Azul claro */
                border-radius: 5px;
            }
        """)
        self.layout.addWidget(self.progress_bar)

        # Label de porcentagem
        self.percentage_label = QLabel("0%")
        self.percentage_label.setAlignment(Qt.AlignCenter)
        self.percentage_label.setStyleSheet("color: black; font-size: 16px;")
        self.layout.addWidget(self.percentage_label)

        # Timer para oscilação do ProgressBar
        self.oscillation_timer = QTimer(self)
        self.oscillation_timer.timeout.connect(self.oscillate_progress)
        self.progress_value = 0

        # Tempo para fechar automaticamente
        self.tempo = tempo

    def center_on_screen(self):
        """Centraliza a janela na tela."""
        screen_geometry = self.screen().geometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)

    def start_task(self):
        """Inicia a animação do ProgressBar."""
        self.progress_bar.setValue(0)
        self.progress_value = 0
        self.oscillation_timer.start(50)  # Inicia a oscilação
        QTimer.singleShot(self.tempo, self.close_window)  # Fecha após o tempo especificado

    def oscillate_progress(self):
        """Mantém o ProgressBar oscilando continuamente."""
        self.progress_value += 5
        if self.progress_value > 100:
            self.progress_value = 0
        self.progress_bar.setValue(self.progress_value)
        self.percentage_label.setText(f"{self.progress_value}%")  # Atualiza o texto da porcentagem

    def close_window(self):
        """Fecha a janela do ProgressBar."""
        self.oscillation_timer.stop()
        self.progress_bar.setValue(100)
        self.percentage_label.setText("100%")
        self.close()
# -------------------------------

# --- Classes responsavel pela janela de edição de ativos ---
class NumeroLinhaWidget(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
    def sizeHint(self):
        digits = len(str(max(1, self.editor.blockCount())))
        return QSize(3 + self.editor.fontMetrics().width('9') * digits, 0)
    def paintEvent(self, event):
        self.editor.numero_linha_paint_event(event)

class EditorCodigo(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""QPlainTextEdit { background: #1e1e1e; color: #d4d4d4; font-family: Consolas, monospace; font-size: 14px; border: none; selection-background-color: #264f78;}""")
        self.setFont(QFont("Consolas", 12))
        self.numero_linha_widget = NumeroLinhaWidget(self)
        self.blockCountChanged.connect(self.atualizar_largura_numeros_linha)
        self.updateRequest.connect(self.atualizar_numeros_linha)
        self.cursorPositionChanged.connect(self.highlight_linha_atual)
        self.atualizar_largura_numeros_linha(0)
        self.highlight_linha_atual()
    def numero_linha_paint_event(self, event):
        painter = QPainter(self.numero_linha_widget)
        painter.fillRect(event.rect(), QColor("#232323"))
        block = self.firstVisibleBlock()
        blockNumber = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()
        altura = self.fontMetrics().height()
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                cor = QColor("#858585") if self.textCursor().blockNumber() != blockNumber else QColor("#4fc3f7")
                painter.setPen(cor)
                painter.drawText(0, int(top), self.numero_linha_widget.width()-4, altura, Qt.AlignRight, str(blockNumber + 1))
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            blockNumber += 1
    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.numero_linha_widget.setGeometry(QRect(cr.left(), cr.top(), self.numero_linha_widget.sizeHint().width(), cr.height()))
    def atualizar_largura_numeros_linha(self, _):
        self.setViewportMargins(self.numero_linha_widget.sizeHint().width(), 0, 0, 0)
    def atualizar_numeros_linha(self, rect, dy):
        if dy:
            self.numero_linha_widget.scroll(0, dy)
        else:
            self.numero_linha_widget.update(0, rect.y(), self.numero_linha_widget.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.atualizar_largura_numeros_linha(0)
    def highlight_linha_atual(self):
        from PyQt5.QtWidgets import QTextEdit
        extraSelections = []
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            linhaColor = QColor("#333842")
            selection.format.setBackground(linhaColor)
            selection.format.setProperty(QTextFormat.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extraSelections.append(selection)
        self.setExtraSelections(extraSelections)

class HighlighterJson(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Padrão de cor do VSCode para JSON
        self.formats = {
            'chave': self.formatar(QColor("#40A3F3"), negrito=True),           # Amarelo claro (chave)
            'string': self.formatar(QColor("#FAE633")),                        # Verde amarelado (valor string)
            'number': self.formatar(QColor("#FAFCF8")),                        # Azul claro (valor numérico)
            'boolean': self.formatar(QColor("#31F13A")),                       # Azul VSCode (true/false)
            'null': self.formatar(QColor("#569CD6")),                          # Igual booleano
            'pontuacao': self.formatar(QColor("#D4D4D4")),                     # Cinza claro (vírgulas, chaves, etc)
        }
        self.regras = [
            (re.compile(r'"([^"]*)"\s*:'), 'chave'),         # chave
            (re.compile(r'(?<=:\s)"[^"]*"'), 'string'),      # valor string (só após :)
            (re.compile(r'(?<=:\s)-?\d+(\.\d+)?([eE][+-]?\d+)?'), 'number'), # valor numérico
            (re.compile(r'\btrue\b|\bfalse\b', re.IGNORECASE), 'boolean'),
            (re.compile(r'\bnull\b', re.IGNORECASE), 'null'),
            (re.compile(r'[:,{}\[\]]'), 'pontuacao'),
        ]
    def formatar(self, cor, negrito=False, italico=False):
        fmt = QTextCharFormat()
        fmt.setForeground(cor)
        if negrito:
            fmt.setFontWeight(QFont.Bold)
        if italico:
            fmt.setFontItalic(True)
        return fmt
    def highlightBlock(self, text):
        for regex, nome in self.regras:
            for match in regex.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, self.formats[nome])
# -----------------------------------------------------------


# --- Classe responsavel pela ativação da Licença em Thread ---
class WidgetConfiguracaoLicenca(QWidget):
    """
    Widget customizado para a tela de Configuração de Licença do InLogic Studio.
    Exibe os dados da licença, permite inserir uma nova chave e emite sinal para ativação.
    Layout moderno, responsivo, colorido e seguro para diferentes cenários de uso.
    """
    solicitacaoAtivacao = pyqtSignal(str)

    def __init__(self, dados_iniciais: dict, parent=None):
        """
        Inicializa o widget de configuração de licença.
        - Garante que todas as cores usadas serão do tipo QColor.
        - Prepara logging e mapeamento de cores.
        - Monta interface e exibe dados iniciais.
        """
        super().__init__(parent)
        self._parent = parent
        self._dados_licenca_atual = dados_iniciais

        # Garante que todas as cores são sempre QColor
        self.COR_VERDE = _garante_qcolor(getattr(self._parent, "COR_VERDE", "#2ecc71"))
        self.COR_VERMELHO = _garante_qcolor(getattr(self._parent, "COR_VERMELHO", "#e74c3c"))
        self.COR_LARANJA = _garante_qcolor(getattr(self._parent, "COR_LARANJA", "#e67e22"))
        self.COR_AZUL = _garante_qcolor(getattr(self._parent, "COR_AZUL", "#3498db"))
        self.COR_TEXTO_ESCURO = _garante_qcolor(getattr(self._parent, "COLOR_DARK_TEXT", "#333333"))
        self.COR_FUNDO_PAINEL = _garante_qcolor(getattr(self._parent, "COR_FUNDO_PAINEL", "#e8e8e8"))
        self.COR_CINZA_MEDIO = _garante_qcolor(getattr(self._parent, "COR_CINZA_MEDIO", "#a0a0a0"))
        self.COR_FUNDO_CLARO = _garante_qcolor(getattr(self._parent, "COLOR_LIGHT_BACKGROUND", "#f0f0f0"))
        self.COR_AMARELO_DESTAQUE = _garante_qcolor(getattr(self._parent, "COLOR_AMARELO_DESTAQUE", "#f1c40f"))

        # Mapa de cores para formatação condicional (opcional, ajuste conforme app principal)
        self._mapa_cores = getattr(self._parent, "_color_map", {
            'green': self.COR_VERDE,
            'red': self.COR_VERMELHO,
            'orange': self.COR_LARANJA,
            'blue': self.COR_AZUL,
        })

        # Setup de logging (usa fila de log do parent, se existir)
        self.fila_log = getattr(self._parent, "log_queue", print)

        # No __init__ do seu widget, depois de garantir as cores principais
        for cor_nome in self._mapa_cores:
            self._mapa_cores[cor_nome] = _garante_qcolor(self._mapa_cores[cor_nome])

        # Monta interface e exibe dados iniciais
        self.configurar_interface()
        self.exibir_dados_licenca(self._dados_licenca_atual)
        self.fila_log(("Configuração de Licença inicializado e UI configurada.", self.COR_AZUL))

    def configurar_interface(self):
        layout_principal = QVBoxLayout(self)
        layout_principal.setSpacing(15)
        layout_principal.setContentsMargins(20, 20, 20, 20)

        # --- Seção de exibição dos dados ---
        frame_exibicao = QFrame()
        layout_formulario = QFormLayout(frame_exibicao)
        layout_formulario.setSpacing(10)
        layout_formulario.setContentsMargins(15, 15, 15, 15)
        frame_exibicao.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {self.COR_CINZA_MEDIO.name()};
                border-radius: 8px;
                background-color: {self.COR_FUNDO_PAINEL.name()};
                padding: 0px;
            }}
            QLabel {{
                color: {self.COR_TEXTO_ESCURO.name()};
                font-weight: bold;
            }}
            QLineEdit[readOnly="true"] {{
                background-color: {self.COR_FUNDO_PAINEL.name()};
                color: {self.COR_TEXTO_ESCURO.name()};
                border: 1px solid {self.COR_CINZA_MEDIO.name()};
                border-radius: 4px; padding: 4px;
            }}
        """)

        self._campos_exibicao = {}
        campos_a_exibir = [
            ("Status da Licença Atual:", "status"),
            ("Modo (Arquivo):", "modo"),
            ("Instance ID (Máquina):", "instance_id"),
            ("Token de Ativação (parcial):", "token"),
            ("Chave de Licença (Key):", "license_key"),
            ("Data/Hora de Expiração:", "expires_at"),
            ("Ativações Usadas:", "ativacoes"),
            ("Limite de Ativações:", "limite_ativacoes"),
            ("Mensagem do Servidor/Processo:", "mensagem"),
            ("Resultado 'sucesso' do Processo:", "sucesso")
        ]
        for texto_label, chave_json in campos_a_exibir:
            label = QLabel(texto_label)
            campo_edicao = QLineEdit()
            campo_edicao.setReadOnly(True)
            campo_edicao.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            campo_edicao.setObjectName(f"campoExibicao_{chave_json}")
            layout_formulario.addRow(label, campo_edicao)
            self._campos_exibicao[chave_json] = campo_edicao
        layout_principal.addWidget(frame_exibicao)

        # --- Seção para ativação de nova licença ---
        frame_ativacao = QFrame()
        layout_v_ativacao = QVBoxLayout(frame_ativacao)
        layout_v_ativacao.setSpacing(10)
        layout_v_ativacao.setContentsMargins(15, 15, 15, 15)
        frame_ativacao.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {self.COR_CINZA_MEDIO.name()};
                border-radius: 8px;
                background-color: {self.COR_FUNDO_PAINEL.name()};
                padding: 0px;
            }}
            QLabel {{
                color: {self.COR_TEXTO_ESCURO.name()};
            }}
            QPushButton {{
                background-color: {self.COR_AZUL.name()};
                color: {self.COR_FUNDO_CLARO.name()};
                border: none; border-radius: 5px; padding: 8px 20px;
                font-weight: bold; min-width: 80px;
            }}
            QPushButton:hover {{ background-color: {self.COR_AZUL.darker(120).name()}; }}
            QPushButton:pressed {{ background-color: {self.COR_AZUL.darker(150).name()}; }}
            QPushButton:disabled {{
                background-color: {self.COR_CINZA_MEDIO.name()}; color: {self.COR_FUNDO_PAINEL.name()};
            }}
            QLineEdit {{
                background-color: {self.COR_FUNDO_CLARO.name()};
                color: {self.COR_TEXTO_ESCURO.name()};
                border: 1px solid {self.COR_CINZA_MEDIO.name()};
                border-radius: 4px; padding: 5px;
                selection-background-color: {self.COR_AMARELO_DESTAQUE.name()};
                selection-color: {self.COR_TEXTO_ESCURO.name()};
            }}
            QLineEdit:focus {{ border-color: {self.COR_AZUL.name()}; }}
        """)
        titulo_ativacao = QLabel("Ativar Nova Licença:")
        titulo_ativacao.setStyleSheet(f"QLabel {{ color: {self.COR_TEXTO_ESCURO.name()}; font-size: 15px; font-weight: bold; }}")
        layout_v_ativacao.addWidget(titulo_ativacao)
        layout_v_ativacao.addSpacing(5)

        layout_chave_botao = QHBoxLayout()
        layout_chave_botao.setSpacing(10)
        label_nova_chave = QLabel("Chave para Ativar:")
        label_nova_chave.setStyleSheet(f"QLabel {{ color: {self.COR_TEXTO_ESCURO.name()}; font-weight: bold; }}")
        self._campo_nova_chave = QLineEdit()
        self._campo_nova_chave.setPlaceholderText("Insira sua chave de licença aqui...")
        self._campo_nova_chave.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._campo_nova_chave.setObjectName("campoNovaChave")
        self._botao_ativar = QPushButton("Ativar Licença")
        self._botao_ativar.setObjectName("botaoAtivar")
        self._botao_ativar.clicked.connect(self._ao_clicar_botao_ativar)
        layout_chave_botao.addWidget(label_nova_chave)
        layout_chave_botao.addWidget(self._campo_nova_chave)
        layout_chave_botao.addWidget(self._botao_ativar)
        layout_v_ativacao.addLayout(layout_chave_botao)
        layout_principal.addWidget(frame_ativacao)
        layout_principal.setStretchFactor(frame_exibicao, 1)
        layout_principal.setStretchFactor(frame_ativacao, 0)

    def exibir_dados_licenca(self, dados: dict):
        self.fila_log(("Atualizando exibição de dados da licença na UI...", self.COR_AZUL))
        if not isinstance(dados, dict):
            self.fila_log((f"AVISO ao tentar exibir dados: Esperado um dicionário de dados de licença, mas recebido {type(dados).__name__}.", self.COR_LARANJA))
            self.limpar_exibicao()
            return
        for chave_json, campo_edicao in self._campos_exibicao.items():
            campo_edicao.setStyleSheet(f"""
                QLineEdit[readOnly="true"] {{
                    background-color: {self.COR_FUNDO_PAINEL.name()};
                    color: {self.COR_TEXTO_ESCURO.name()};
                    border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                }}
            """)
            campo_edicao.setText("")
            valor = dados.get(chave_json)
            if valor is not None:
                try:
                    if chave_json == "sucesso":
                        texto_valor = "Sim" if valor is True else "Não" if valor is False else str(valor)
                        cor_texto = self._mapa_cores.get('green', self.COR_VERDE) if valor is True else (
                            self._mapa_cores.get('red', self.COR_VERMELHO) if valor is False else self.COR_TEXTO_ESCURO)
                        campo_edicao.setText(texto_valor)
                        campo_edicao.setStyleSheet(f"""
                            QLineEdit[readOnly="true"] {{
                                background-color: {self.COR_FUNDO_PAINEL.name()};
                                color: {cor_texto.name()};
                                font-weight: bold;
                                border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                            }}
                        """)
                    if chave_json == "status":
                        texto_valor = str(valor).upper().strip()
                        if texto_valor == "API_REJEITOU":
                            cor_texto = self._mapa_cores.get('red', self.COR_VERMELHO)
                        elif "SUCESSO" in texto_valor:
                            cor_texto = self._mapa_cores.get('green', self.COR_VERDE)
                        elif any(s in texto_valor for s in ["INATIVO", "PENDENTE", "EXPIRADO"]):
                            cor_texto = self._mapa_cores.get('red', self.COR_VERMELHO)
                        elif any(s in texto_valor for s in ["FALHA", "AVISO", "ATENÇÃO", "ERRO", "CRÍTICO"]):
                            cor_texto = self._mapa_cores.get('orange', self.COR_LARANJA)
                        else:
                            cor_texto = self.COR_TEXTO_ESCURO
                        campo_edicao.setText(texto_valor)
                        campo_edicao.setStyleSheet(f"""
                            QLineEdit[readOnly="true"] {{
                                background-color: {self.COR_FUNDO_PAINEL.name()};
                                color: {cor_texto.name()};
                                font-weight: bold;
                                border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                            }}
                        """)
                    elif chave_json == "expires_at" and isinstance(valor, str) and valor.strip():
                        try:
                            data_exp = datetime.strptime(valor.strip(), "%Y-%m-%d %H:%M:%S")
                            texto_valor = data_exp.strftime("%d/%m/%Y %H:%M:%S")
                            agora = datetime.now()
                            tempo_restante = data_exp - agora
                            if tempo_restante.total_seconds() <= 0:
                                cor_texto = self._mapa_cores.get('red', self.COR_VERMELHO)
                            elif tempo_restante < timedelta(days=30):
                                cor_texto = self._mapa_cores.get('orange', self.COR_LARANJA)
                            else:
                                cor_texto = self.COR_TEXTO_ESCURO
                            campo_edicao.setText(texto_valor)
                            campo_edicao.setStyleSheet(f"""
                                QLineEdit[readOnly="true"] {{
                                    background-color: {self.COR_FUNDO_PAINEL.name()};
                                    color: {cor_texto.name()};
                                    border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                                }}
                            """)
                        except (ValueError, TypeError) as e:
                            self.fila_log((f"AVISO: Formato de data/hora inesperado para 'expires_at' nos dados ({type(valor).__name__}, '{valor}'). Erro: {e}", self.COR_LARANJA))
                            campo_edicao.setText(str(valor) + " (Formato Inválido)")
                            campo_edicao.setStyleSheet(f"""
                                QLineEdit[readOnly="true"] {{
                                    background-color: {self.COR_FUNDO_PAINEL.name()};
                                    color: {self.COR_LARANJA.name()};
                                    border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                                }}
                            """)
                        except Exception as e:
                            self.fila_log((f"ERRO inesperado ao processar data/hora para 'expires_at' ({type(valor).__name__}, '{valor}'): {type(e).__name__} - {e}", self.COR_VERMELHO))
                            campo_edicao.setText("Erro Interno Data")
                            campo_edicao.setStyleSheet(f"""
                                QLineEdit[readOnly="true"] {{
                                    background-color: {self.COR_FUNDO_PAINEL.name()};
                                    color: {self.COR_VERMELHO.name()};
                                    border: 1px solid {self.COR_VERMELHO.name()}; border-radius: 4px; padding: 4px;
                                }}
                            """)
                    elif chave_json == "token" and isinstance(valor, str) and len(valor) > 12:
                        texto_valor = valor[:8].strip() + "..." + valor[-4:].strip()
                        campo_edicao.setText(texto_valor)
                    elif chave_json == "license_key" and isinstance(valor, str) and valor.strip():
                        campo_edicao.setText(valor.strip())
                        campo_edicao.setStyleSheet(f"""
                            QLineEdit[readOnly="true"] {{
                                background-color: {self.COR_FUNDO_PAINEL.name()};
                                color: {self.COR_TEXTO_ESCURO.name()};
                                font-weight: bold;
                                border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                            }}
                        """)
                    elif chave_json in ["ativacoes", "limite_ativacoes"] and isinstance(valor, (int, float)):
                        campo_edicao.setText(str(int(valor)) if isinstance(valor, float) else str(valor))
                    elif chave_json == "mensagem" and isinstance(valor, str):
                        campo_edicao.setText(valor)
                    elif chave_json == "instance_id" and isinstance(valor, str) and valor.strip():
                        campo_edicao.setText(valor.strip())
                    elif chave_json == "modo" and isinstance(valor, str) and valor.strip():
                        campo_edicao.setText(valor.strip().title())
                    else:
                        campo_edicao.setText(str(valor))
                except Exception as e:
                    self.fila_log((f"ERRO INESPERADO ao processar/formatar valor para campo '{chave_json}' (valor lido = {str(valor)[:50]}...): {type(e).__name__} - {e}", self.COR_VERMELHO))
                    campo_edicao.setText("Erro interno")
                    campo_edicao.setStyleSheet(f"""
                        QLineEdit[readOnly="true"] {{
                            background-color: {self.COR_FUNDO_PAINEL.name()};
                            color: {self.COR_VERMELHO.name()};
                            border: 1px solid {self.COR_VERMELHO.name()}; border-radius: 4px; padding: 4px;
                        }}
                    """)
            else:
                campo_edicao.setText("N/A")
                campo_edicao.setStyleSheet(f"""
                    QLineEdit[readOnly="true"] {{
                        background-color: {self.COR_FUNDO_PAINEL.name()};
                        color: {self.COR_CINZA_MEDIO.name()};
                        border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                    }}
                """)
        self.fila_log(("Exibição de dados da licença atualizada na UI finalizada.", self.COR_AZUL))

    def limpar_exibicao(self):
        for campo_edicao in self._campos_exibicao.values():
            campo_edicao.setText("")
            campo_edicao.setStyleSheet(f"""
                QLineEdit[readOnly="true"] {{
                    background-color: {self.COR_FUNDO_PAINEL.name()};
                    color: {self.COR_TEXTO_ESCURO.name()};
                    border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 4px;
                }}
            """)
        self.fila_log(("Campos de exibição de dados da licença limpos.", self.COR_AZUL))

    def limpar_input_chave(self):
        self._campo_nova_chave.clear()
        self.fila_log(("Campo de input da nova chave limpo.", self.COR_AZUL))
        self._campo_nova_chave.setStyleSheet(f"""
            QLineEdit {{
                background-color: {self.COR_FUNDO_CLARO.name()}; color: {self.COR_TEXTO_ESCURO.name()};
                border: 1px solid {self.COR_CINZA_MEDIO.name()}; border-radius: 4px; padding: 5px;
                selection-background-color: {self.COR_AMARELO_DESTAQUE.name()}; selection-color: {self.COR_TEXTO_ESCURO.name()};
            }}
            QLineEdit:focus {{ border-color: {self.COR_AZUL.name()}; }}
        """)

    def _ao_clicar_botao_ativar(self):
        self.fila_log(("Botão 'Ativar Licença' clicado no widget.", self.COR_AZUL))
        chave_licenca = self._campo_nova_chave.text().strip()
        if not chave_licenca:
            QMessageBox.warning(self._parent, "Chave Vazia", "Por favor, insira uma chave de licença para ativar.")
            self.fila_log(("Tentativa de ativação com chave vazia. Validação do widget falhou.", self.COR_LARANJA))
            return

        # Mensagem explicativa ao usuário
        mensagem = (
            "ATENÇÃO!\n\n"
            "Ao ativar uma nova licença neste sistema:\n"
            "• A licença anterior será substituída;\n"
            "• O sistema irá se conectar ao servidor de licenças;\n"
            "• O processo é crítico e inreversivel.\n\n"
            "Deseja realmente continuar e ativar uma nova licença?"
        )
        resposta = QMessageBox.question(
            self._parent,
            "Confirmação de Ativação",
            mensagem,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if resposta != QMessageBox.Yes:
            self.fila_log(("Usuário cancelou o processo de ativação após confirmação.", self.COR_LARANJA))
            return

        self.solicitacaoAtivacao.emit(chave_licenca)
        self.fila_log((f"Sinal 'solicitacaoAtivacao' emitido com chave: {chave_licenca[:8]}...", self.COR_AZUL))

    def definir_estado_botao_ativacao(self, habilitado: bool):
        self._botao_ativar.setEnabled(habilitado)
        self.fila_log((f"Botão de ativação definido para habilitado={habilitado}.", self.COR_AZUL))

    # Função responsavel pela exibição do progressbar de carregamento na interface
    def start_progressbar(self):
        """Método para iniciar a Progressbar."""
        self.progress_window = Progressbar(tempo=5000)  # Tempo em milissegundos
        self.progress_window.center_on_screen()
        self.progress_window.show()
        self.progress_window.start_task()

class ThreadAtivarLicenca(QThread):
    resultado = pyqtSignal(object)

    def __init__(self, chave, instance_id):
        super().__init__()
        self.chave = chave
        self.instance_id = instance_id

    def tem_internet(self, timeout=3):
        """Retorna True se houver conexão com a internet, False caso contrário."""
        try:
            # Tenta conectar no DNS do Google (8.8.8.8) na porta 53
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            return True
        except Exception:
            return False

    def run(self):
        # Verifica se há conexão com a internet antes de prosseguir
        if not self.tem_internet():
            QMessageBox.critical(self._parent, "Sem Internet", "Não foi detectada conexão com a internet (Thread). Conecte-se e tente novamente.")
            log_queue.put(("Ativação abortada: sem conexão com a internet.", self.COR_VERMELHO))
            return
        resposta = ativar_licenca(self.chave, self.instance_id)
        self.resultado.emit(resposta)
# -------------------------------------------------------------




class WidgetAssistente(QWidget):
    solicitacaoAtivacao = pyqtSignal(str)
    assistenteConcluido = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self.fila_log = getattr(self._parent, "log_queue", print)
        
        self._carregar_recursos_ui()
        self._animacao_em_andamento = False
        self._indice_pagina_atual = 0

        self.configurar_interface()
        self.fila_log(("Assistente de Configuração inicializado.", self.COR_AZUL))

    def _carregar_recursos_ui(self):
        """Carrega cores, fontes e outros recursos do widget pai."""
        # Seus atributos de cor... (garantir que estejam definidos como objetos QColor)
        self.COR_AZUL_BOTAO = _garante_qcolor(getattr(self._parent, "COR_AZUL_BOTAO", "#007bff"))
        self.COR_TEXTO_ESCURO = _garante_qcolor(getattr(self._parent, "COLOR_DARK_TEXT", "#212529"))
        self.COR_FUNDO_JANELA = _garante_qcolor(getattr(self._parent, "COLOR_LIGHT_BACKGROUND", "#f8f9fa"))
        self.COR_FUNDO_PAINEL_LATERAL = _garante_qcolor(getattr(self._parent, "COLOR_PANEL_BACKGROUND", "#ffffff"))
        self.COR_CINZA_SUTIL = _garante_qcolor(getattr(self._parent, "COLOR_MEDIUM_GRAY", "#ced4da"))
        self.COR_VERDE_SUCESSO = _garante_qcolor(getattr(self._parent, "COR_VERDE", "#28a745"))
        self.COR_AZUL_DESTAQUE = _garante_qcolor(getattr(self._parent, "COLOR_PRIMARY_BABY_BLUE", "#e0f7fa"))

        self._base_path_imagens = getattr(self._parent, "BASE_PATH_IMAGES", ".")
        self.fonte_titulo = QFont("Segoe UI Semibold", 26)
        self.fonte_texto = QFont("Segoe UI", 11)

    def configurar_interface(self):
        """Constrói o layout principal do assistente, dividindo-o em painel lateral e conteúdo."""
        layout_principal = QHBoxLayout(self)
        layout_principal.setSpacing(0)
        layout_principal.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet(f"background-color: {self.COR_FUNDO_JANELA.name()};")

        # --- Painel Lateral ---
        self._painel_indicador = QFrame()
        self._painel_indicador.setObjectName("PainelIndicador")
        self._painel_indicador.setFixedWidth(250)
        self._painel_indicador.setStyleSheet(f"background-color: {self.COR_FUNDO_PAINEL_LATERAL.name()};")
        sombra_painel = QGraphicsDropShadowEffect(self)
        sombra_painel.setBlurRadius(20); sombra_painel.setXOffset(5); sombra_painel.setColor(QColor(0, 0, 0, 30))
        self._painel_indicador.setGraphicsEffect(sombra_painel)
        layout_indicador = QVBoxLayout(self._painel_indicador)
        layout_indicador.setContentsMargins(15, 30, 15, 30)
        layout_indicador.setSpacing(20)
        layout_indicador.setAlignment(Qt.AlignTop)
        layout_principal.addWidget(self._painel_indicador)

        # --- Painel Principal ---
        painel_conteudo = QFrame()
        layout_conteudo = QVBoxLayout(painel_conteudo)
        layout_conteudo.setContentsMargins(60, 40, 60, 20)
        layout_conteudo.setSpacing(20)
        
        self._stacked_widget = QStackedWidget(self)
        layout_conteudo.addWidget(self._stacked_widget, 1)
        layout_principal.addWidget(painel_conteudo, 1)

        layout_navegacao = self._criar_barra_navegacao()
        layout_conteudo.addLayout(layout_navegacao)
        
        self._paginas = []
        self._widgets_indicadores = []
        self._criar_paginas_e_indicadores()
        self.navegar_para_pagina(0, animar=False) # Garante que a primeira página é mostrada

    def _criar_barra_navegacao(self):
        """Cria e estiliza a barra de navegação com os botões."""
        layout = QHBoxLayout()
        estilo_botao_nav = f"..." # seu estilo de botão aqui
        self._botao_anterior = QPushButton(" Anterior"); self._botao_anterior.setIcon(self.style().standardIcon(QStyle.SP_ArrowLeft)); self._botao_anterior.setStyleSheet(estilo_botao_nav); self._botao_anterior.clicked.connect(self._ir_para_anterior)
        self._botao_proximo = QPushButton("Próximo "); self._botao_proximo.setLayoutDirection(Qt.RightToLeft); self._botao_proximo.setIcon(self.style().standardIcon(QStyle.SP_ArrowRight)); self._botao_proximo.setStyleSheet(estilo_botao_nav); self._botao_proximo.clicked.connect(self._ir_para_proximo_ou_finalizar)
        layout.addStretch()
        layout.addWidget(self._botao_anterior)
        layout.addWidget(self._botao_proximo)
        return layout
    
# =================================================================================




class StepProgressBar(QWidget):
    """Custom widget: step progress bar with animated indicator and dots."""
    def __init__(self, total_steps, parent=None):
        super().__init__(parent)
        self.total_steps = total_steps
        self.current_step = 0
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.color_active = QColor('#007bff')
        self.color_inactive = QColor('#cccccc')
        self.color_bg = QColor('#f8f9fa')
        self.color_text = QColor('#222222')

    def set_step(self, step):
        self.current_step = step
        self.update()

    def paintEvent(self, event):
        w, h = self.width(), self.height()
        margin = 32
        available_w = w - 2*margin
        dot_radius = 13
        line_y = h//2
        step_w = 0 if self.total_steps==1 else available_w // (self.total_steps-1)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # Draw Line
        painter.setPen(Qt.NoPen)
        painter.setBrush(self.color_inactive)
        painter.drawRect(margin, line_y-2, available_w, 4)
        # Draw Progress
        painter.setBrush(self.color_active)
        painter.drawRect(margin, line_y-2, step_w*self.current_step, 4)
        # Draw Dots
        for i in range(self.total_steps):
            color = self.color_active if i <= self.current_step else self.color_inactive
            painter.setBrush(color)
            x = margin + i*step_w
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(x-dot_radius, line_y-dot_radius, 2*dot_radius, 2*dot_radius)
        painter.end()

class WidgetAssistente(QWidget):
    solicitacaoAtivacao = pyqtSignal(str)
    assistenteConcluido = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self.fila_log = log_queue.put
        self._carregar_cores_e_fontes()
        self._animacao_em_andamento = False
        self._indice_pagina_atual = 0
        self._step_titles = [
            "Boas-vindas", "Adquirir Licença", "Ativar Licença",
            "Configurar Ativo", "Verificar Serviço", "Conclusão"
        ]
        self.configurar_interface()
        log_queue.put(("Assistente de Configuração inicializado.", "blue"))

        # Variaveis do serviço do windons
        global TEST_SERVICE_NAME, TEST_SERVICE_BIN_PATH, TEST_SERVICE_DISPLAY_NAME
        self.service_name=TEST_SERVICE_NAME
        self.bin_path=TEST_SERVICE_BIN_PATH
        self.display_name=TEST_SERVICE_DISPLAY_NAME

    def _carregar_cores_e_fontes(self):
        self.COR_AZUL = _garante_qcolor(getattr(self._parent, "COR_AZUL_BOTAO", "#007bff"))
        self.COR_VERDE = _garante_qcolor(getattr(self._parent, "COR_VERDE", "#28a745"))
        self.COR_TEXTO = _garante_qcolor(getattr(self._parent, "COLOR_DARK_TEXT", "#212529"))
        self.COR_BG = _garante_qcolor(getattr(self._parent, "COLOR_LIGHT_BACKGROUND", "#f8f9fa"))
        self.COR_CINZA = _garante_qcolor(getattr(self._parent, "COLOR_MEDIUM_GRAY", "#ced4da"))
        self._base_path_imagens = getattr(self._parent, "BASE_PATH_IMAGES", ".")
        self.fonte_titulo = QFont("Segoe UI Semibold", 22)
        self.fonte_texto = QFont("Segoe UI", 11)

    def configurar_interface(self):
        layout_principal = QVBoxLayout(self)
        layout_principal.setContentsMargins(36, 36, 36, 36)
        layout_principal.setSpacing(12)
        self.setStyleSheet(f"background-color: {self.COR_BG.name()};")

        # --- Barra de progresso do topo ---
        self._progressbar = StepProgressBar(len(self._step_titles))
        layout_principal.addWidget(self._progressbar, alignment=Qt.AlignTop)

        # --- Títulos das etapas no topo ---
        steps_row = QHBoxLayout()
        steps_row.setContentsMargins(26, 0, 26, 0)
        steps_row.setSpacing(0)
        for t in self._step_titles:
            lbl = QLabel(t)
            lbl.setFont(QFont("Segoe UI", 10))
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color: #666666;")
            steps_row.addWidget(lbl)
            if t != self._step_titles[-1]:
                steps_row.addSpacing(18)
        layout_principal.addLayout(steps_row)

        # --- Conteúdo centralizado ---
        self._stacked_widget = QStackedWidget(self)
        layout_principal.addStretch(1)
        layout_principal.addWidget(self._stacked_widget, stretch=10, alignment=Qt.AlignVCenter)
        layout_principal.addStretch(1)
      

        # --- Barra de Navegação Inferior (centralizada) ---
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(36, 36, 36, 36)
        nav_layout.setSpacing(20)
        nav_layout.addStretch()
        self._botao_anterior = QPushButton("Anterior")
        self._botao_anterior.setIcon(self.style().standardIcon(QStyle.SP_ArrowLeft))
        self._botao_anterior.setMinimumHeight(38)
        self._botao_anterior.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self._botao_anterior.setStyleSheet(f"QPushButton{{background:{self.COR_CINZA.name()};color:#fff;border-radius:8px;padding:8px 24px;}} QPushButton:disabled{{background:#e0e0e0;}}")
        self._botao_anterior.clicked.connect(self._ir_para_anterior)
        nav_layout.addWidget(self._botao_anterior)
        self._botao_proximo = QPushButton("Próximo")
        self._botao_proximo.setIcon(self.style().standardIcon(QStyle.SP_ArrowRight))
        self._botao_proximo.setMinimumHeight(38)
        self._botao_proximo.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self._botao_proximo.setStyleSheet(f"QPushButton{{background:{self.COR_AZUL.name()};color:#fff;border-radius:8px;padding:8px 32px;}} QPushButton:disabled{{background:#b0b0b0;}}")
        self._botao_proximo.clicked.connect(self._ir_para_proximo_ou_finalizar)
        nav_layout.addWidget(self._botao_proximo)
        nav_layout.addStretch()
        layout_principal.addLayout(nav_layout)

        # --- Páginas ---
        self._paginas = [
            self._criar_pagina_boas_vindas(),
            self._criar_pagina_loja_licenca(),
            self._criar_pagina_ativacao(),
            self._criar_pagina_ativos(),
            self._criar_pagina_servico(),
            self._criar_pagina_conclusao(),
        ]
        for pag in self._paginas:
            self._stacked_widget.addWidget(pag)
        self.navegar_para_pagina(0)

    def _criar_pagina_boas_vindas(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        logo_path = os.path.join(self._base_path_imagens, "icone.ico")
        lbl_logo = QLabel()
        if os.path.exists(logo_path):
            pix = QPixmap(logo_path)
            lbl_logo.setPixmap(pix.scaled(112, 112, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        lbl_logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl_logo)
        titulo = QLabel("Bem-vindo ao InLogic Studio")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Este guia rápido ajudará você a configurar o sistema em poucos passos. Clique em \"Próximo\" para começar.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    def _criar_pagina_loja_licenca(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        titulo = QLabel("1. Adquira sua Chave de Licença")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Para utilizar todos os recursos, você precisa de uma licença.\n\nAcesse nossa loja online para ver os planos e adquirir sua chave.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        botao_loja = QPushButton(" Ir para a Loja de Licenças")
        botao_loja.setIcon(get_themed_icon("Login", "menu") or self.style().standardIcon(QStyle.SP_CommandLink))
        botao_loja.setStyleSheet(f"QPushButton {{ background-color: {self.COR_VERDE.name()}; font-size: 14px; padding: 12px 30px; border-radius: 6px; color: white; font-weight: bold; }} QPushButton:hover {{ background-color: {self.COR_VERDE.darker(115).name()}; }}")
        botao_loja.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.inlogic.com.br/loja/")))
        layout.addWidget(botao_loja, alignment=Qt.AlignCenter)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    def _criar_pagina_ativacao(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        titulo = QLabel("2. Ative sua Licença")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Cole a chave de licença e clique em \"Ativar\". O botão \"Próximo\" será liberado após ativação bem-sucedida.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        self._campo_nova_chave = QLineEdit()
        self._campo_nova_chave.setPlaceholderText("Cole sua chave de licença aqui...")
        self._campo_nova_chave.setFixedWidth(320)
        self._campo_nova_chave.setStyleSheet(f"QLineEdit {{ padding: 10px; font-size: 14px; border: 1px solid {self.COR_CINZA.name()}; border-radius: 5px; }} QLineEdit:focus {{ border: 2px solid {self.COR_AZUL.name()}; }}")
        layout.addWidget(self._campo_nova_chave, alignment=Qt.AlignCenter)
        self._botao_ativar = QPushButton(" Ativar Licença")
        self._botao_ativar.setIcon(get_themed_icon("Properties Viewer", "menu"))
        self._botao_ativar.setStyleSheet(f"QPushButton{{background:{self.COR_AZUL.name()};color:#fff;border-radius:8px;padding:8px 32px;}}")
        self._botao_ativar.clicked.connect(self._iniciar_ativacao_da_ui)
        layout.addWidget(self._botao_ativar, alignment=Qt.AlignCenter)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    def _criar_pagina_ativos(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        titulo = QLabel("3. Configurar Ativos")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Selecione onde seus dados/ativos serão salvos. Você pode mudar isso depois nas preferências.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        self._pasta_edit = QLineEdit()
        self._pasta_edit.setPlaceholderText("Selecione a pasta de dados")
        self._pasta_edit.setFixedWidth(320)
        botao_pasta = QPushButton("Procurar...")
        botao_pasta.clicked.connect(self._selecionar_pasta)
        h = QHBoxLayout()
        h.setAlignment(Qt.AlignCenter)
        h.addWidget(self._pasta_edit)
        h.addWidget(botao_pasta)
        layout.addLayout(h)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    def _selecionar_pasta(self):
        pasta = QFileDialog.getExistingDirectory(self, "Selecione a pasta de dados")
        if pasta:
            self._pasta_edit.setText(pasta)

    def _criar_pagina_servico(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        titulo = QLabel("4. Verificar Serviço")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Clique para verificar se o serviço do InLogic está rodando.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        botao_verificar = QPushButton("Verificar Serviço")
        botao_verificar.setStyleSheet(f"QPushButton{{background:{self.COR_VERDE.name()};color:#fff;border-radius:8px;padding:8px 32px;}}")
        botao_verificar.clicked.connect(self._verificar_servico)
        layout.addWidget(botao_verificar, alignment=Qt.AlignCenter)
        self._label_status_servico = QLabel("")
        self._label_status_servico.setFont(self.fonte_texto)
        self._label_status_servico.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._label_status_servico)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    # Iniciar Serviço do windons e verificar 
    def inicia_service(self):
        """ Verificar existencia, criar serviço do windons"""

        # Chama a função principal para gerenciar o serviço DO WINDONS
        verificar_servico_criar_start(
            self.service_name,
            self.bin_path,
            self.display_name
        )
        self.status_service()


    # Verificar Status do Serviço do windons
    def status_service(self):
        """ Verificar status do serviço do windons"""

        # Verifica o status final após a tentativa de iniciar
        final_status = get_service_status(self.service_name, log_queue) # Passa a queue
        log_queue.put(f"SISTEMA  |  [START] Status final após tentativa de início: {final_status}")
        if final_status == "RUNNING":
            QMessageBox.warning(self, "InLogic Service", f"Status: {final_status}")
            self._label_status_servico.setText(f"Status: {final_status}✅"  )
            self._label_status_servico.setStyleSheet("color: green; font-weight: bold;")
            
        else:
            self._label_status_servico.setText(f"[ERRO]: {final_status} ")
            self._label_status_servico.setStyleSheet("color: red; font-weight: bold;")
            # Mensagem explicativa ao usuário
            mensagem = (
                "ATENÇÃO!\n\n"
                "Gostaria de iniciar o sistema\n"
                "• O sistema estará apto a ser utilizado;\n"
                "• O sistema irá se configurar automaticamente;\n\n\n"
                "Deseja realmente continuar e ativar?"
            )
            resposta = QMessageBox.question(
                self._parent,
                "Confirmação de Ativação",
                mensagem,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if resposta != QMessageBox.Yes:
                log_queue.put(("Usuário cancelou o processo de ativação após confirmação.", "red"))
                return
            self.inicia_service()

    def _verificar_servico(self):
        self.status_service()


    def _criar_pagina_conclusao(self):
        pagina = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        icone = QLabel()
        check_icon = self.style().standardIcon(QStyle.SP_DialogApplyButton)
        icone.setPixmap(check_icon.pixmap(64, 64))
        icone.setAlignment(Qt.AlignCenter)
        layout.addWidget(icone)
        titulo = QLabel("Configuração Concluída!")
        titulo.setFont(self.fonte_titulo)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)
        texto = QLabel("Tudo pronto! Clique em Finalizar para começar a usar o sistema.")
        texto.setFont(self.fonte_texto)
        texto.setWordWrap(True)
        texto.setAlignment(Qt.AlignCenter)
        texto.setMaximumWidth(480)
        layout.addWidget(texto)
        layout.addStretch()
        pagina.setLayout(layout)
        return pagina

    # ==== Lógica de navegação e ativação ====
    def ativacao_concluida(self, sucesso: bool, mensagem: str):
        self._botao_ativar.setEnabled(True)
        self._botao_ativar.setText(" Ativar Licença")
        if sucesso:
            QMessageBox.information(self, "Sucesso!", "Sua licença foi ativada! Você já pode avançar.")
            self._botao_proximo.setEnabled(True)
        else:
            QMessageBox.warning(self, "Falha na Ativação", mensagem)
            self._botao_proximo.setEnabled(False)

    def _iniciar_ativacao_da_ui(self):
        chave = self._campo_nova_chave.text().strip()
        if not chave:
            QMessageBox.warning(self, "Chave Vazia", "Por favor, insira a chave de licença.")
            return
        self._botao_ativar.setEnabled(False)
        self._botao_ativar.setText("Ativando...")
        self.solicitacaoAtivacao.emit(chave)

    def _ir_para_anterior(self):
        if self._indice_pagina_atual > 0:
            self.navegar_para_pagina(self._indice_pagina_atual - 1)

    def _ir_para_proximo_ou_finalizar(self):
        if self._indice_pagina_atual < len(self._paginas) - 1:
            self.navegar_para_pagina(self._indice_pagina_atual + 1)
        else:
            self._finalizar_assistente()

    def _finalizar_assistente(self):
        self.assistenteConcluido.emit()

    def navegar_para_pagina(self, novo_indice: int, animar=False):
        self._indice_pagina_atual = novo_indice
        self._stacked_widget.setCurrentIndex(novo_indice)
        self._progressbar.set_step(novo_indice)
        self._atualizar_estado_navegacao()

    def _atualizar_estado_navegacao(self):
        self._botao_anterior.setEnabled(self._indice_pagina_atual > 0)
        if self._indice_pagina_atual == 2:
            self._botao_proximo.setEnabled(False)
        else:
            self._botao_proximo.setEnabled(True)
        if self._indice_pagina_atual == len(self._paginas) - 1:
            self._botao_proximo.setText("Finalizar")
            self._botao_proximo.setIcon(QIcon())
        else:
            self._botao_proximo.setText("Próximo")
            self._botao_proximo.setIcon(self.style().standardIcon(QStyle.SP_ArrowRight))


# --- Classes Principal GUI - Studio ---
class SupervisoryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{nome_software} - V{versao}")
        self.showMaximized()  # Maximiza a janela sem torná-la em tela cheia

        #  inicializar modulo de download, upload e atualização 
        self.backup_manager = BackupManager()

        # Variaveis de comando do named pipe
        global PIPE_CMD
        self.PIPE_CMD = PIPE_CMD
        
        # Variaveis do serviço do windons
        global TEST_SERVICE_NAME, TEST_SERVICE_BIN_PATH, TEST_SERVICE_DISPLAY_NAME
        self.service_name=TEST_SERVICE_NAME
        self.bin_path=TEST_SERVICE_BIN_PATH
        self.display_name=TEST_SERVICE_DISPLAY_NAME


        self.MAX_LOG_HISTORY_SIZE = 5000 #  (ADICIONAR)
        self.log_history = [] # Stores (message, color) tuples (ADICIONAR)
        self.logs_area = None # QTextEdit widget for logs (ADICIONAR)
        self.logs_window = None # QMdiSubWindow for logs (ADICIONAR)

        # Janela do assistente de configuração
        self._janela_assistente = None
        self._widget_assistente = None
        global BASE_IMAGES
        self.BASE_PATH_IMAGES = BASE_IMAGES

        # --- Definição de Cores ---
        # ESTE BLOCO PRECISA ESTAR NO SEU __init__
        self.COLOR_PRIMARY_BABY_BLUE = "#ADD8E6"
        self.COLOR_LIGHT_BACKGROUND = "#f0f0f0"
        self.COLOR_PANEL_BACKGROUND = "#e8e8e8"
        #self.COLOR_DARK_PANEL_HEADER = "#c0c0c0"
        self.COLOR_DARK_PANEL_HEADER = "#63b1fa"
        self.COLOR_MEDIUM_GRAY = "#a0a0a0"
        self.COLOR_DARK_GRAY_BORDER = "#707070"
        self.COLOR_DARK_TEXT = "#333333"
        self.COLOR_LIGHT_TEXT = "#ecf0f1"
        self.COLOR_ACCENT_YELLOW = "#f1c40f"
        self.COLOR_ACCENT_PURPLE = "#7c04ac" # Used for disconnected status
        self.COLOR_GREEN = "#03be51" # Used for connected status
        self.COLOR_RED = "#da1c07" # Used for errors
        self.COLOR_ORANGE = "#e67e22" # Used for warnings/info
        self.COLOR_BLUE = "#5236f1" # Used for system messages/info
        self.COLOR_PRIMARY_BORDER = self.COLOR_PRIMARY_BABY_BLUE


        self._color_map = {
            "black": self.COLOR_DARK_TEXT,
            "red": self.COLOR_RED, 
            "orange": self.COLOR_ORANGE,
            "blue": self.COLOR_BLUE,
            "green": self.COLOR_GREEN,
            "purple": self.COLOR_ACCENT_PURPLE,
            
        }

        # Cores para o destacador de sintaxe (usando cores do tema)
        self._highlighter_colors = {
            'key': self.COLOR_ACCENT_PURPLE, # Exemplo: usar roxo para chaves
            'string': self.COLOR_GREEN,      # Exemplo: usar verde para strings
            'number': self.COLOR_BLUE,       # Exemplo: usar azul para números
            'boolean': self.COLOR_ORANGE,    # Exemplo: usar laranja para bool/None
            'null': self.COLOR_RED,          # Exemplo: usar vermelho para null (pprint usa None, mas JSON usa null)
            'operator': self.COLOR_DARK_TEXT # Exemplo: usar texto escuro para operadores
            # 'background' pode ser definido no stylesheet abaixo usando self.COLOR_PANEL_BACKGROUND
        }
        # --------------------------------------------------


        # Cores do indicador oscilante tela inicial
        self.status_variavel_critica = False  # ou True, conforme o padrão desejado
        self._estado_oscilacao_indicador = False  # também inicialize o estado de oscilação
        self._cor_indicador_verde_claro = "#025502"      # escolha a cor que quiser
        self._cor_indicador_verde_escuro = "#1dfc00"
        self._cor_indicador_vermelho_claro = "#700101"
        self._cor_indicador_vermelho_escuro = "#fc0202"
        # -----------------------------------------------



        # --- Referências para editores, destacadores e áreas de numeração ---
        # Inicializadas como None. Armazenam as instâncias dos widgets MDI quando estão abertos.
        self._properties_area_editor = None # Editor de configuração
        self._properties_highlighter = None # Destacador para o editor de configuração (JSON)
        self._lineNumberArea = None # Área de numeração para o editor de configuração.

        self._script_area_editor = None # Editor de script.
        self._script_highlighter = None # <--- ADICIONAR ESTA REFERÊNCIA para o destacador de script (Python)
        self._script_lineNumberArea = None # Área de numeração para o editor de script.

        # --- Estilo Visual (CSS-like) ---
        self.setStyleSheet(f"""
            /* Estilo Geral da Janela Principal */
            QMainWindow {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
            }}

            

                QTabBar::tab {{
                background: {self.COLOR_PRIMARY_BABY_BLUE};
                color: {self.COLOR_DARK_TEXT};
                padding: 8px 20px;
                border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                min-width: 150px;
            }}
            QTabBar::tab:selected {{
                background: {self.COLOR_DARK_PANEL_HEADER};
                color: {self.COLOR_LIGHT_TEXT};
                font-weight: bold;
            }}
            QTabWidget::pane {{
                border-top: 2px solid {self.COLOR_PRIMARY_BABY_BLUE};
                top: -1px;
                background: {self.COLOR_LIGHT_BACKGROUND};
            }}

            

            QMenuBar {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                border-bottom: 1px solid {self.COLOR_MEDIUM_GRAY};
            }}
            QMenuBar::item {{
                padding: 4px 8px;
                background-color: transparent;
            }}
            QMenuBar::item:selected {{
                background-color: {self.COLOR_MEDIUM_GRAY};
                color: {self.COLOR_LIGHT_TEXT};
            }}
            QMenu {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
                padding: 3px;
            }}
            QMenu::item {{
                padding: 4px 20px 4px 25px;
                margin: 1px;
                border-radius: 2px;
            }}
            QMenu::item:selected {{
                background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                color: {self.COLOR_DARK_TEXT};
            }}
            QMenu::separator {{
                height: 1px;
                background: {self.COLOR_MEDIUM_GRAY};
                margin: 4px 8px;
            }}
             QMenu::icon {{
                width: 16px;
                height: 16px;
            }}


            QToolBar {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                border-bottom: 1px solid {self.COLOR_MEDIUM_GRAY};
                spacing: 6px;
                padding: 4px;
            }}


            /* Estilo para o Label do Indicador (a "bolinha") */
            QLabel#indicadorStatusLabel {{
                min-width: 14px; max-width: 14px;
                min-height: 14px; max-height: 14px;
                border-radius: 7px;
                /* Background-color será definido dinamicamente */
                margin: 0 5px;
            }}

             /* Estilo específico para o QTextEdit do Editor de Configuração */
             /* Usa o objectName definido no método open_properties_window */
             QTextEdit#configEditor {{
                 /* CORRIGIDO AQUI: Referenciar uma variável de cor existente */
                 background-color: {self.COLOR_PANEL_BACKGROUND}; /* Fundo cinza claro para o editor */
                 color: {self.COLOR_DARK_TEXT}; /* Cor padrão do texto */
                 border: 1px solid {self.COLOR_MEDIUM_GRAY};
                 border-radius: 5px;
                 font-family: Consolas, 'Courier New', monospace;
                 font-size: 13px;
                 padding: 8px;
                 selection-background-color: {self.COLOR_ACCENT_YELLOW};
                 selection-color: {self.COLOR_DARK_TEXT};
             }}
             QTextEdit#configEditor:read-only {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                border-color: {self.COLOR_MEDIUM_GRAY};
            }}

            /* ... (restante dos seus estilos) ... */
           

    /* --- Estilo para o Label do Indicador (a "bolinha") --- */
            QLabel#indicadorStatusLabel {{
                min-width: 14px; /* Tamanho da bolinha */
                max-width: 14px;
                min-height: 14px;
                max-height: 14px;
                border-radius: 7px; /* Metade do tamanho para ser circular */
                /* Background-color será definido dinamicamente pelo método _atualizar_indicador_oscilante */
                margin: 0 5px; /* Espaço ao redor */
            }}

            QToolButton {{
                background-color: transparent;
                border: none;
                padding: 4px;
                border-radius: 3px;
                color: {self.COLOR_DARK_TEXT}; /* Cor padrão para ícones em toolbars claras */
            }}
            QToolButton:hover {{
                background-color: {self.COLOR_MEDIUM_GRAY};
            }}
             QToolButton:pressed {{
                background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                color: {self.COLOR_DARK_TEXT};
            }}
            QToolBar::separator {{
                width: 1px;
                background-color: {self.COLOR_MEDIUM_GRAY};
                margin: 0 8px;
            }}


            QMdiArea {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
            }}

             QMdiSubWindow {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
            }}
            QMdiSubWindow::title {{
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                 stop: 0 {self.COLOR_PRIMARY_BABY_BLUE}, stop: 1 {self.COLOR_MEDIUM_GRAY});
                color: {self.COLOR_DARK_TEXT};
                padding: 4px;
                border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
                border-bottom: none;
            }}


            QDockWidget {{
                 border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
            }}
            QDockWidget::title {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                padding: 5px;
                border: 1px solid {self.COLOR_DARK_GRAY_BORDER};
                border-bottom: none;
                font-weight: bold;
            }}
            QDockWidget > QWidget {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
            }}


            QTreeWidget {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                border: none;
                font-size: 13px;
                padding: 3px;
                alternate-background-color: {self.COLOR_LIGHT_BACKGROUND};
                show-decoration-selected: 1;
            }}
            QTreeWidget::item {{
                 padding: 2px 0;
                 border-bottom: 1px solid {self.COLOR_MEDIUM_GRAY};
            }}
             QTreeWidget::item:hover {{
                 background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                 color: {self.COLOR_DARK_TEXT};
             }}
            QTreeWidget::item:selected {{
                background-color: {self.COLOR_ACCENT_YELLOW};
                color: {self.COLOR_DARK_TEXT};
            }}
             /* Ícones de expansión para TreeView (opcional, requiere imágenes) */
             /* QTreeWidget::branch:open:has-children {{ image: url({os.path.join(BASE_PATH_IMAGES, 'arrow_down_dark.png').replace(os.sep, '/')}); }} */
             /* QTreeWidget::branch:closed:has-children {{ image: url({os.path.join(BASE_PATH_IMAGES, 'arrow_right_dark.png').replace(os.sep, '/')}); }} */


            QHeaderView::section {{
                background-color: {self.COLOR_DARK_PANEL_HEADER};
                color: {self.COLOR_DARK_TEXT};
                padding: 5px;
                border: none;
                border-bottom: 1px solid {self.COLOR_DARK_GRAY_BORDER};
                font-weight: bold;
            }}
             QHeaderView::section:hover {{
                background-color: {self.COLOR_MEDIUM_GRAY};
            }}


            QSplitter::handle {{
                background-color: {self.COLOR_MEDIUM_GRAY};
                margin: 0px;
            }}
            QSplitter::handle:hover {{
                 background-color: {self.COLOR_PRIMARY_BABY_BLUE};
            }}
            QSplitter::handle:horizontal {{
                width: 4px;
            }}
             QSplitter::handle:vertical {{
                height: 4px;
            }}


            QTextEdit {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                border: 1px solid {self.COLOR_MEDIUM_GRAY};
                border-radius: 5px;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 13px;
                padding: 8px;
                selection-background-color: {self.COLOR_ACCENT_YELLOW};
                selection-color: {self.COLOR_DARK_TEXT};
            }}
             QTextEdit:read-only {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
                border-color: {self.COLOR_MEDIUM_GRAY};
            }}


            QLabel {{
                color: {self.COLOR_DARK_TEXT};
            }}
            QPushButton {{
                background-color: {self.COLOR_MEDIUM_GRAY};
                color: {self.COLOR_DARK_TEXT};
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: normal;
            }}
            QPushButton:hover {{
                background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                color: {self.COLOR_DARK_TEXT};
            }}
            QPushButton:pressed {{
                background-color: {self.COLOR_ACCENT_PURPLE};
                color: {self.COLOR_LIGHT_TEXT};
            }}
             QPushButton:disabled {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
                color: {self.COLOR_MEDIUM_GRAY};
            }}

            QLineEdit, QComboBox, QSpinBox, QDateEdit {{
                 background-color: {self.COLOR_LIGHT_BACKGROUND};
                 color: {self.COLOR_DARK_TEXT};
                 border: 1px solid {self.COLOR_MEDIUM_GRAY};
                 border-radius: 4px;
                 padding: 4px;
                 selection-background-color: {self.COLOR_ACCENT_YELLOW};
                 selection-color: {self.COLOR_DARK_TEXT};
            }}
             QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDateEdit:focus {{
                 border: 1px solid {self.COLOR_PRIMARY_BABY_BLUE};
             }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 18px;
                border-left-width: 1px;
                border-left-color: {self.COLOR_MEDIUM_GRAY};
                border-left-style: solid;
                border-top-right-radius: 3px;
                border-bottom-right-radius: 3px;
            }}
             /* QComboBox::down-arrow {{ image: url({os.path.join(BASE_PATH_IMAGES, 'arrow_down_dark.png').replace(os.sep, '/')}); }} */
            QComboBox QAbstractItemView {{
                background-color: {self.COLOR_LIGHT_BACKGROUND};
                color: {self.COLOR_DARK_TEXT};
                selection-background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                selection-color: {self.COLOR_DARK_TEXT};
                border: 1px solid {self.COLOR_MEDIUM_GRAY};
            }}


            QProgressBar {{
                background-color: {self.COLOR_PANEL_BACKGROUND};
                border: 1px solid {self.COLOR_MEDIUM_GRAY};
                border-radius: 5px;
                text-align: center;
                color: {self.COLOR_DARK_TEXT};
                margin: 2px;
            }}
            QProgressBar::chunk {{
                background-color: {self.COLOR_PRIMARY_BABY_BLUE};
                border-radius: 4px;
            }}

            QSlider::groove:horizontal {{
                border: 1px solid {self.COLOR_MEDIUM_GRAY};
                height: 6px;
                background: {self.COLOR_PANEL_BACKGROUND};
                margin: 2px 0;
                border-radius: 3px;
            }}
            QSlider::handle:horizontal {{
                background: {self.COLOR_ACCENT_YELLOW};
                border: 1px solid {self.COLOR_ACCENT_YELLOW};
                width: 16px;
                margin: -5px 0;
                border-radius: 8px;
            }}
             QSlider::add-page:horizontal {{
                background: {self.COLOR_MEDIUM_GRAY};
                border-radius: 3px;
            }}
            QSlider::sub-page:horizontal {{
                background: {self.COLOR_PRIMARY_BABY_BLUE};
                 border-radius: 3px;
            }}

            QCheckBox, QRadioButton {{
                color: {self.COLOR_DARK_TEXT};
                padding: 2px;
            }}
            /* QCheckBox::indicator, QRadioButton::indicator {{ ... }} */


            QScrollBar:vertical {{
                border: none;
                background: {self.COLOR_PANEL_BACKGROUND};
                width: 10px;
                margin: 18px 0 18px 0;
            }}
            QScrollBar::handle:vertical {{
                background: {self.COLOR_MEDIUM_GRAY};
                min-height: 15px;
                border-radius: 5px;
                margin: 0 1px;
            }}
             QScrollBar::handle:vertical:hover {{
                 background: {self.COLOR_PRIMARY_BABY_BLUE};
             }}
             QScrollBar::add-line:vertical {{
                border: none;
                background: {self.COLOR_DARK_PANEL_HEADER};
                height: 18px;
                subcontrol-position: bottom;
                subcontrol-origin: margin;
                border-bottom-left-radius: 5px; border-bottom-right-radius: 5px;
            }}
            QScrollBar::sub-line:vertical {{
                border: none;
                background: {self.COLOR_DARK_PANEL_HEADER};
                height: 18px;
                subcontrol-position: top;
                subcontrol-origin: margin;
                border-top-left-radius: 5px; border-top-right-radius: 5px;
            }}
             /* QScrollBar::up-arrow:vertical {{ image: url(...arrow_up_dark.png...) }} */
             /* QScrollBar::down-arrow:vertical {{ image: url(...arrow_down_dark.png...) }} */
             QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: none;
            }}

             QScrollBar:horizontal {{
                border: none;
                background: {self.COLOR_PANEL_BACKGROUND};
                height: 10px;
                margin: 0px 18px 0 18px;
            }}
            QScrollBar::handle:horizontal {{
                background: {self.COLOR_MEDIUM_GRAY};
                min-width: 15px;
                border-radius: 5px;
                margin: 1px 0;
            }}
             QScrollBar::handle:horizontal:hover {{
                background: {self.COLOR_PRIMARY_BABY_BLUE};
             }}
             QScrollBar::add-line:horizontal {{
                border: none;
                background: {self.COLOR_DARK_PANEL_HEADER};
                width: 18px;
                subcontrol-position: right;
                subcontrol-origin: margin;
                border-top-right-radius: 5px;
            }}
             QScrollBar::sub-line:horizontal {{
                border: none;
                background: {self.COLOR_DARK_PANEL_HEADER};
                width: 18px;
                subcontrol-position: left;
                subcontrol-origin: margin;
                 border-top-left-radius: 5px; border-bottom-left-radius: 5px;
            }}
             /* QScrollBar::left-arrow:horizontal {{ image: url(...arrow_left_dark.png...) }} */
             /* QScrollBar::right-arrow:horizontal {{ image: url(...arrow_right_dark.png...) }} */
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: none;
            }}

        """) # Fim do stylesheet completo.


        # --- Propriedades de Autenticação ---
        self.login_status = False # Começa desconectado



        # Obtém o Instance ID da máquina (serial). Essencial para a ativação.
        try:
            self.numero_serie = get_system_info() # Chama a função GLOBAL.
        except Exception as e:
             # Logs iniciais podem não ir para a log_queue da GUI se ela não está pronta,
             # mas podemos imprimir e armazenar um fallback.
             print(f"[INIT] Aviso: Falha ao obter numero de serie na inicialização: {e}. Usando valor fallback.")
             self.numero_serie = "SN_INDISPONIVEL" # Define um valor de fallback para que o atributo exista.
             # Log para a queue se ela já estiver pronta, ou use um sistema de logging diferente para inicialização.
             # if hasattr(self, 'log_queue'): self.log_queue((f"[INIT] Aviso: Falha ao obter SN: {e}. SN_INDISPONIVEL", "orange"))



        # ===== Barra de Menus =====
        menu_bar = self.menuBar()
        arquivo_menu = menu_bar.addMenu("Arquivo")

        editar_menu = menu_bar.addMenu("Editar")
        add_action = QAction(get_themed_icon("Logs Viewer", "menu"), "Add Novo Ativo", self)
        add_action.triggered.connect(self.add_ativo)
        editar_menu.addAction(add_action)

        exibir_menu = menu_bar.addMenu("Exibir")
        logs_action = QAction(get_themed_icon("Logs Viewer", "menu"), "Visualizar Logs", self)
        logs_action.triggered.connect(self.open_logs_window)
        exibir_menu.addAction(logs_action)

        service1_action = QAction(get_themed_icon("Logs Viewer", "menu"), "Status Supervisório", self)
        service1_action.triggered.connect(self.status_service)
        exibir_menu.addAction(service1_action)

        ferramentas_menu = menu_bar.addMenu("Ferramentas")
        

        # --- Menu de Autenticação ---
        auth_menu = menu_bar.addMenu("Autenticação")
        self.action_login = QAction(get_themed_icon("Login", "toolbar"), "Login...", self)
        self.action_login.triggered.connect(self.show_login_dialog)
        auth_menu.addAction(self.action_login)

        self.action_logout = QAction(get_themed_icon("Logout", "toolbar"), "Logout", self)
        self.action_logout.triggered.connect(self.logout)
        auth_menu.addAction(self.action_logout)
        auth_menu.addSeparator()

        self.action_change_password = QAction(get_themed_icon("Change Password", "toolbar"), "Alterar Senha...", self)
        self.action_change_password.triggered.connect(self.show_change_password_dialog)
        auth_menu.addAction(self.action_change_password)

        self.action_reset_password = QAction(get_themed_icon("Reset Password", "toolbar"), "Resetar Senha (para padrão)", self)
        self.action_reset_password.triggered.connect(self.reset_password_to_default)
        auth_menu.addAction(self.action_reset_password)

        ajuda_menu = menu_bar.addMenu("Ajuda")
        ajuda_action = QAction(get_themed_icon("Properties Viewer", "menu"), "Manual", self)
        ajuda_action.triggered.connect(lambda: log_queue.put(("Ação: Manual requisitado", "blue")))
        ajuda_menu.addAction(ajuda_action)

        assitencia_action = QAction(get_themed_icon("Properties Viewer", "menu"), "Asistente de configuração", self)
        assitencia_action.triggered.connect(lambda: log_queue.put(("Iniciando assistencia de configuração rapida...", "blue")))
        assitencia_action.triggered.connect(lambda: self.abrir_assistente_configuracao())
        ajuda_menu.addAction(assitencia_action)


        # ===== Barra de Ferramentas =====
        toolbar = QToolBar("Toolbar Principal")
        toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(toolbar)



        # ADICIONAR ESTA AÇÃO DE RECARREGAR/ATUALIZAR
        # Usa o nome lógico "Recarregar" com o conjunto de ícones "toolbar"
        reload_icon_qstyle = QApplication.instance().style().standardIcon(QStyle.SP_BrowserReload)
        reload_action = QAction(reload_icon_qstyle, "Recarregar Configuração", self)        # Conecta a ação a uma função que você quer que seja executada (ex: self.reiniciar_clps, self.carregar_configuracao_e_arvore)
        reload_action.triggered.connect(self.enviar_comandos) # Exemplo, substitua pela lógica real
        toolbar.addAction(reload_action) # Adiciona a nova ação à toolbar

        play_icon_qstyle = QApplication.instance().style().standardIcon(QStyle.SP_MediaPlay)
        play_action = QAction(play_icon_qstyle, "Play", self)
        play_action.triggered.connect(lambda: log_queue.put(("Ação Toolbar: Play triggered (ícone QStyle)", "blue"))) # Exemplo de log
        # >> SUBSTITUA A LAMBDA ACIMA PELA FUNÇÃO REAL QUE DEVE EXECUTAR O PLAY <<
        toolbar.addAction(play_action) # Adiciona a ação à toolbar

        stop_icon_qstyle = QApplication.instance().style().standardIcon(QStyle.SP_MediaStop)
        stop_action = QAction(stop_icon_qstyle, "Stop", self)
        stop_action.triggered.connect(lambda: log_queue.put(("Ação Toolbar: Stop triggered (ícone QStyle)", "blue"))) # Exemplo de log
        # >> SUBSTITUA A LAMBDA ACIMA PELA FUNÇÃO REAL QUE DEVE EXECUTAR O STOP <<
        toolbar.addAction(stop_action) # Adiciona a ação à toolbar

        download_action = QAction(get_themed_icon("Download", "toolbar"), "Download", self)
        download_action.triggered.connect(self.realizar_download) # Exemplo
        toolbar.addAction(download_action)

        upload_action = QAction(get_themed_icon("Upload", "toolbar"), "Upload", self)
        upload_action.triggered.connect(self.realizar_upload_completo) # Exemplo
        toolbar.addAction(upload_action)


        # --- Adicionar Separador após as ações padrão ---
        toolbar.addSeparator()

        # Cria um container vertical com centralização total
        status_container = QWidget()
        status_layout = QVBoxLayout()
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(0)
        status_layout.setAlignment(Qt.AlignCenter)  # Centraliza tudo no container

        # Título pequeno, centralizado e preto
        titulo_status = QLabel("Usuário")
        titulo_status.setAlignment(Qt.AlignCenter)
        titulo_status.setStyleSheet("font-size: 9px; color: gray; font-weight: normal;")

        # Label de status, centralizado
        self.login_status_label = QLabel("Desconectado")
        self.login_status_label.setAlignment(Qt.AlignCenter)
        self.login_status_label.setStyleSheet(f"color: {self.COLOR_ACCENT_PURPLE};")

        # Adiciona os widgets ao layout
        status_layout.addWidget(titulo_status)
        status_layout.addWidget(self.login_status_label)
        status_container.setLayout(status_layout)

        # Adiciona o container na toolbar
        toolbar.addWidget(status_container)

        toolbar.addSeparator()
        # ----------------------------------------------

        # --- Espaçador à esquerda ---
        espacador_esquerda = QWidget()
        espacador_esquerda.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(espacador_esquerda)

        # --- Widget central com layout vertical ---
        widget_central = QWidget()
        layout_vertical = QVBoxLayout()
        layout_vertical.setContentsMargins(0, 0, 0, 0)
        layout_vertical.setAlignment(Qt.AlignCenter)

        # --- Título acima ---
        label_titulo = QLabel("InLogic – Nº de Série")  # Seu título desejado
        label_titulo.setStyleSheet("font-size: 9px; color: gray; font-weight: normal;")
        label_titulo.setAlignment(Qt.AlignCenter)

        # --- Texto dinâmico abaixo ---
        self.label_texto_dinamico = QLabel(self.numero_serie)
        self.label_texto_dinamico.setStyleSheet("margin-top: 2px; font-weight: bold;")
        self.label_texto_dinamico.setAlignment(Qt.AlignCenter)

        # --- Adiciona os dois ao layout vertical ---
        layout_vertical.addWidget(label_titulo)
        layout_vertical.addWidget(self.label_texto_dinamico)

        widget_central.setLayout(layout_vertical)
        toolbar.addWidget(widget_central)

        # --- Espaçador à direita ---
        espacador_direita = QWidget()
        espacador_direita.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(espacador_direita)

        # --- Adicionar o Espaçador que empurra para a direita ---
        self.espacador_toolbar = QWidget()
        self.espacador_toolbar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(self.espacador_toolbar)



        # --- Widget contêiner que vai abrigar o texto + bolinha ---
        widget_com_texto_e_bolinha = QWidget()
        layout_vertical = QVBoxLayout()
        layout_vertical.setContentsMargins(0, 0, 0, 0)  # Remove margens
        layout_vertical.setSpacing(2)  # Espaçamento entre o texto e a bolinha

        # --- Texto acima da bolinha ---
        label_texto_cima = QLabel("Status")
        label_texto_cima.setStyleSheet("font-size: 9px; color: gray; font-weight: normal;")
        label_texto_cima.setAlignment(Qt.AlignCenter)
        layout_vertical.addWidget(label_texto_cima, alignment=Qt.AlignCenter)

        # --- Label da Bolinha Indicadora ---
        self.label_indicador_status = QLabel()
        self.label_indicador_status.setObjectName("indicadorStatusLabel")
        self.label_indicador_status.setToolTip("Processando...")
        layout_vertical.addWidget(self.label_indicador_status, alignment=Qt.AlignCenter)

        # Aplica o layout ao widget container
        widget_com_texto_e_bolinha.setLayout(layout_vertical)

        # Adiciona o container à toolbar
        toolbar.addWidget(widget_com_texto_e_bolinha)


        # --- Timer para a Oscilação do Indicador (Inicialize AQUI, após criar o label) ---
        self.timer_indicador_oscilante = QTimer(self)
        # Conecta o timeout do timer ao método que atualiza a cor da bolinha
        # ESTE METODO PRECISA ESTAR DENTRO DA CLASSE E ACESSÍVEL VIA self.
        self.timer_indicador_oscilante.timeout.connect(self._atualizar_indicador_oscilante)
        # Inicia o timer. Intervalo em milissegundos (ex: 500ms = 0.5 segundos por cor)
        self.timer_indicador_oscilante.start(500)

        # --- Configuração Inicial do Indicador (Chame AQUI, após iniciar o timer) ---
        # Chama o método de atualização uma vez imediatamente para definir a cor inicial
        # ESTE METODO PRECISA ESTAR DENTRO DA CLASSE E ACESSÍVEL VIA self.
        self._atualizar_indicador_oscilante()
        # ----------------------------------------------------------------------------------



        # ===== Área Central (QMdiArea) =====
        self.mdi_area = QMdiArea()
        self.setCentralWidget(self.mdi_area)
        self.mdi_area.setViewMode(QMdiArea.TabbedView)
        self.mdi_area.setTabsClosable(True)
        self.mdi_area.setTabsMovable(True)

        # ===== Painel Lateral (DockWidget) com Árvores =====
        splitter = QSplitter(Qt.Vertical)

        self.tree_ativos = QTreeWidget()
        self.tree_ativos.setHeaderLabel("Ativos")
        self.tree_ativos.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_ativos.customContextMenuRequested.connect(self.exibir_menu_contexto)

        splitter.addWidget(self.tree_ativos)

        self.tree_arquivos = QTreeWidget()
        self.tree_arquivos.setHeaderLabel("Estrutura de Arquivos")
        splitter.addWidget(self.tree_arquivos)

        dock_tree = QDockWidget("Painel de Ativos", self)
        dock_tree.setWidget(splitter)
        dock_tree.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.LeftDockWidgetArea, dock_tree)
        self.dock_tree = dock_tree  # <-- GUARDE AQUI!

        # ===== Métodos para abrir janelas =====
        self.create_menu_actions(menu_bar)

        # --- Configuração Inicial ---
        # Carregar configuração ANTES de popular as árvores
        self.config = carregar_configuracao()

        # Populando as árvores APÓS carregar a configuração e definir o status de login
        self.carregar_ativos()
        self.populate_file_tree(r"C:\In Logic")




        # --- Configuração da janela de licença ---
        global PATH_ATIVACAO # Garante que acessa a constante global.
        self._janela_licenca = None  # QMdiSubWindow ou None
        self._caminho_arquivo_ativacao = PATH_ATIVACAO  # Referência ao caminho global do arquivo de ativação
        # Exemplo: carregando de um método auxiliar da sua classe
        dados_licenca_do_arquivo = self._carregar_dados_arquivo_licenca()
        self._widget_licenca = WidgetConfiguracaoLicenca(dados_licenca_do_arquivo, parent=self)





        # --- Outras inicializações ---
        if not hasattr(self, 'tray_icon'):
             try:
                 self.tray_icon = QSystemTrayIcon(self)
                 self.tray_icon.setIcon(self.windowIcon())
                 self.tray_icon.setToolTip(nome_software)
                 self.tray_icon.show()
             except Exception as e:
                 print(f"Aviso: Falha ao criar QSystemTrayIcon: {e}. Funções de tray_icon podem não funcionar.")
                 log_queue.put(f"Aviso: Falha ao criar QSystemTrayIcon: {e}")
                 self.tray_icon = None

        if not hasattr(self, 'reiniciar_clps'):
             self.reiniciar_clps = lambda: print("Mock: Reiniciando CLPs...")

        # Inicializar o status de login visualmente APÓS a UI ser criada
        self.update_login_ui()

        # Iniciar a thread de monitoramento de log
        self.log_thread = threading.Thread(target=self.monitorar_log_rotativo, daemon=True)
        self.log_thread.start()

        # Iniciar o timer para processar os logs da fila
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.processar_logs)
        self.log_timer.start(100)  # Atualiza a cada 100ms

        self.led_timer = QTimer()
        self.led_timer.timeout.connect(self.triger_status_service)
        self.led_timer.start(9000)

    # --- Métodos responsavél pela bolinha do indicador de status d atela inicial ---
    def atualizar_texto_dinamico(self, texto):
        """
        Atualiza o texto no label dinamico da toolbar.
        :param texto: A string com o novo texto a ser exibido.
        """
        # Verificação de hasattr é boa, mas em um método da classe, label_texto_dinamico
        # deve ser um atributo após o __init__. A verificação pode ser simplificada
        # se tiver certeza que o __init__ rodou completamente.
        if hasattr(self, 'label_texto_dinamico') and self.label_texto_dinamico:
             self.label_texto_dinamico.setText(str(texto))
        else:
             print("Aviso: label_texto_dinamico não inicializado ao tentar atualizar.")
             log_queue.put(("Aviso: label_texto_dinamico não inicializado.", "orange"))

    def definir_status_variavel_critica(self, status_booleano):
        """
        Define o status da variável critica que controla a cor base do indicador.
        A oscilação entre claro/escuro é tratada pelo timer.
        :param status_booleano: True para status "ok" (verde), False para status "critico" (vermelho).
        """
        if isinstance(status_booleano, bool):
            # Apenas atualiza a variável de estado
            self.status_variavel_critica = status_booleano
            # O timer _atualizar_indicador_oscilante lerá esta variável na próxima vez que disparar.
            # Para uma atualização instantânea, chame o método do timer uma vez:
            self._atualizar_indicador_oscilante()
            log_queue.put(f"Status variável crítica alterado para: {'True (Verde)' if status_booleano else 'False (Vermelho)'}", "blue")
        else:
            print(f"Aviso: Tentativa de definir status variavel critica com valor não booleano: {status_booleano}")
            log_queue.put(f"Aviso: Status variável crítica recebeu valor inválido: {status_booleano}", "orange")

    def _atualizar_indicador_oscilante(self):
        """
        Slot para o timer. Alterna a cor da bolinha indicadora para criar o efeito de oscilação.
        A cor base (verde/vermelho) depende de self.status_variavel_critica.
        O estado de oscilação (claro/escuro) depende de self._estado_oscilacao_indicador.
        """
        # Verificação de hasattr é necessária pois este método pode ser chamado
        # pelo timer antes do __init__ estar completamente pronto se o timer for iniciado muito cedo.
        if not hasattr(self, 'label_indicador_status') or not self.label_indicador_status:
            # Não faz nada se o label ainda não foi criado
            return

        if self.status_variavel_critica:
            # Status é True: Usa cores verdes
            cor_atual = self._cor_indicador_verde_claro if self._estado_oscilacao_indicador else self._cor_indicador_verde_escuro
        else:
            # Status é False: Usa cores vermelhas
            cor_atual = self._cor_indicador_vermelho_claro if self._estado_oscilacao_indicador else self._cor_indicador_vermelho_escuro

        # Aplica a cor usando o objectName para garantir que o estilo se aplique especificamente a este label
        # É importante que o objectName "indicadorStatusLabel" esteja definido no QLabel no __init__
        self.label_indicador_status.setStyleSheet(f"""
            QLabel#indicadorStatusLabel {{
                min-width: 14px;
                max-width: 14px;
                min-height: 14px;
                max-height: 14px;
                border-radius: 7px;
                background-color: {cor_atual};
                margin: 0 5px;
            }}
        """)

        # Alterna o estado de oscilação para a próxima vez que o timer disparar
        self._estado_oscilacao_indicador = not self._estado_oscilacao_indicador
    # -------------------------------------------------------------------------------



    # --- Métodos da GUI Principal ---
    def carregar_ativos(self):
        """
        Popula a árvore de ativos com base na configuração carregada,
        replicando a estrutura da versão antiga fornecida.
        Usa ícones coloridos de arquivos, qtawesome ou QStyle básico.
        """

        def salvar_estado_expansao(item, estado):
            if item is None: return
            item_text = item.text(0)
            estado[item_text] = {
                "expanded": item.isExpanded(),
                "children": {}
            }
            for i in range(item.childCount()):
                child = item.child(i)
                salvar_estado_expansao(child, estado[item_text]["children"])

        def restaurar_estado_expansao(item, estado):
            if item is None or not estado: return
            item_text = item.text(0)
            if item_text in estado:
                if estado[item_text]["expanded"]:
                    item.setExpanded(True)
                for i in range(item.childCount()):
                    child = item.child(i)
                    restaurar_estado_expansao(child, estado[item_text]["children"])

        expanded_state = {}
        if hasattr(self, 'tree_ativos') and self.tree_ativos and self.tree_ativos.invisibleRootItem():
            root = self.tree_ativos.invisibleRootItem()
            for i in range(root.childCount()):
                grupo_item = root.child(i)
                salvar_estado_expansao(grupo_item, expanded_state)
            self.tree_ativos.clear()
        else:
             log_queue.put("Aviso: tree_ativos não inicializado ao tentar salvar/limpar estado.")


        if isinstance(self.config, dict) and isinstance(self.config.get("grupos"), list):
            for grupo in self.config["grupos"]:
                try:
                    # Nível 1: Grupo
                    grupo_item = QTreeWidgetItem([grupo.get("grupo", "Grupo sem nome")])
                    try:
                        grupo_icon = QIcon(ICON_PATH) # Tenta carregar o ícone da logo
                        grupo_icon_themed = get_themed_icon("Pasta", "asset") # Ícone temático de pasta
                        # Prioridade: Ícone da logo > Ícone temático de pasta > Fallbacks automáticos dentro de get_themed_icon
                        grupo_item.setIcon(0, grupo_icon if not grupo_icon.isNull() else grupo_icon_themed)
                    except Exception:
                        grupo_item.setIcon(0, get_themed_icon("Pasta", "asset")) # Fallback final para ícone temático

                    grupo_item.setData(0, Qt.UserRole, ("grupo", grupo))
                    self.tree_ativos.addTopLevelItem(grupo_item)

                    # Nível 2: IP do ativo e tipo_clp (diretamente sob o Grupo)
                    ip = grupo.get('plc_ip', 'N/A')
                    tipo_clp = grupo.get('tipo_clp', 'Desconhecido')
                    ip_item = QTreeWidgetItem([f"ADDRESS: {ip}"])
                    ip_item.setIcon(0, get_themed_icon("Address", "asset"))
                    ip_item.setData(0, Qt.UserRole, ("ip", grupo))
                    grupo_item.addChild(ip_item)
                    # Define a dica com o tipo de CLP
                    ip_item.setToolTip(0, f"{tipo_clp}")

                    # ITENS SOB O NÍVEL DE IP, CONFORME A VERSÃO ANTIGA FORNECIDA
                    gatilho_item = QTreeWidgetItem([f"GATILHO: {grupo.get('gatilho', 'N/A')}"])
                    gatilho_item.setIcon(0, get_themed_icon("Memória de Gatilho", "asset"))
                    gatilho_item.setData(0, Qt.UserRole, ("gatilho", grupo))
                    ip_item.addChild(gatilho_item)

                    temporizador_item = QTreeWidgetItem([f"TEMPORIZADOR: {grupo.get('intervalo_temporizador', 'N/A')} segundos"])
                    temporizador_item.setIcon(0, get_themed_icon("Temporizador", "asset"))
                    temporizador_item.setData(0, Qt.UserRole, ("intervalo_temporizador", grupo))
                    ip_item.addChild(temporizador_item)

                    grava_mem_item = QTreeWidgetItem(["MEMORIA DE GRAVAÇÃO"])
                    grava_mem_item.setIcon(0, get_themed_icon("Memórias de Gravação", "asset"))
                    grava_mem_item.setData(0, Qt.UserRole, ("memorias_gravacao", grupo))
                    ip_item.addChild(grava_mem_item)

                    for mem in grupo.get("mem_list", []):
                        mem_item = QTreeWidgetItem([f"{mem}"])
                        # Opcional: Ícone para cada memória individual?
                        mem_item.setData(0, Qt.UserRole, ("mem_list", grupo, mem))
                        grava_mem_item.addChild(mem_item)


                    # --- Configurações de Local de Gravação (SQL, MQTT, Excel, Notificação) - DIRETAMENTE SOB O GRUPO ---
                    local_gravacao = grupo.get("local_gravacao", {})

                    if local_gravacao.get("sql", False):
                        sql_item = QTreeWidgetItem(["SQL"])
                        sql_item.setIcon(0, get_themed_icon("Banco de Dados", "asset"))
                        sql_item.setData(0, Qt.UserRole, ("sql", grupo))
                        grupo_item.addChild(sql_item)

                        db_config = grupo.get("db_config", {})
                        server_name = db_config.get("server", "N/A")
                        server_item = QTreeWidgetItem([f"SERVIDOR: {server_name}"])
                        server_item.setIcon(0, get_themed_icon("Servidor", "asset"))
                        server_item.setData(0, Qt.UserRole, ("server", grupo))
                        sql_item.addChild(server_item)

                        database_name = db_config.get("database", "N/A")
                        database_item = QTreeWidgetItem([f"BANCO DE DADOS: {database_name}"])
                        database_item.setIcon(0, get_themed_icon("Banco de Dados", "asset"))
                        database_item.setData(0, Qt.UserRole, ("database", grupo))
                        server_item.addChild(database_item)

                        tabela_item = QTreeWidgetItem([f"TABELA: {grupo.get('tabela_sql', 'N/A')}"])
                        tabela_item.setIcon(0, get_themed_icon("Tabela", "asset"))
                        tabela_item.setData(0, Qt.UserRole, ("tabela", grupo))
                        database_item.addChild(tabela_item)

                        login_item_parent = QTreeWidgetItem(["LOGIN"])
                        login_item_parent.setIcon(0, get_themed_icon("Login", "asset"))
                        login_item_parent.setData(0, Qt.UserRole, ("login", grupo))
                        database_item.addChild(login_item_parent)

                        username_item = QTreeWidgetItem([f"Usuário: {db_config.get('username', 'N/A')}"])
                        username_item.setIcon(0, get_themed_icon("Usuário", "asset"))
                        username_item.setData(0, Qt.UserRole, ("username", grupo))
                        login_item_parent.addChild(username_item)

                        password_item = QTreeWidgetItem([f"Senha: {'********' if db_config.get('password') else 'N/A'}"])
                        password_item.setIcon(0, get_themed_icon("Senha", "asset"))
                        password_item.setData(0, Qt.UserRole, ("password", grupo))
                        login_item_parent.addChild(password_item)


                    if local_gravacao.get("mqtt", False):
                        mqtt_item = QTreeWidgetItem(["MQTT"])
                        mqtt_item.setIcon(0, get_themed_icon("MQTT", "asset"))
                        mqtt_item.setData(0, Qt.UserRole, ("ACESSO_MQTT", grupo))
                        grupo_item.addChild(mqtt_item)

                        mqtt_config = grupo.get("ACESSO_MQTT", {})
                        if mqtt_config:
                            broker_address_item = QTreeWidgetItem([f"Broker Address: {mqtt_config.get('broker_address', 'N/A')}"])
                            broker_address_item.setIcon(0, get_themed_icon("Address", "asset"))
                            broker_address_item.setData(0, Qt.UserRole, ("mqtt_broker_address", grupo))
                            mqtt_item.addChild(broker_address_item)

                            port_item = QTreeWidgetItem([f"Porta: {mqtt_config.get('port', 'N/A')}"])
                            port_item.setIcon(0, get_themed_icon("Address", "asset"))
                            port_item.setData(0, Qt.UserRole, ("mqtt_port", grupo))
                            mqtt_item.addChild(port_item)

                            client_id_item = QTreeWidgetItem([f"Client ID: {mqtt_config.get('client_id', 'N/A')}"])
                            client_id_item.setIcon(0, get_themed_icon("Address", "asset"))
                            client_id_item.setData(0, Qt.UserRole, ("mqtt_client_id", grupo))
                            mqtt_item.addChild(client_id_item)

                            username_item = QTreeWidgetItem([f"Username: {mqtt_config.get('username', 'N/A')}"])
                            username_item.setIcon(0, get_themed_icon("Usuário", "asset"))
                            username_item.setData(0, Qt.UserRole, ("mqtt_username", grupo))
                            mqtt_item.addChild(username_item)

                            password_item = QTreeWidgetItem([f"Password: {'********' if mqtt_config.get('password') else 'N/A'}"])
                            password_item.setIcon(0, get_themed_icon("Senha", "asset"))
                            password_item.setData(0, Qt.UserRole, ("mqtt_password", grupo))
                            mqtt_item.addChild(password_item)

                            keep_alive_item = QTreeWidgetItem([f"Keep Alive: {mqtt_config.get('keep_alive', 'N/A')} segundos"])
                            keep_alive_item.setIcon(0, get_themed_icon("Temporizador", "asset"))
                            keep_alive_item.setData(0, Qt.UserRole, ("mqtt_keep_alive", grupo))
                            mqtt_item.addChild(keep_alive_item)

                            qos_item = QTreeWidgetItem([f"QoS: {mqtt_config.get('qos', 'N/A')}"])
                            qos_item.setIcon(0, get_themed_icon("Info", "asset"))
                            qos_item.setData(0, Qt.UserRole, ("mqtt_qos", grupo))
                            mqtt_item.addChild(qos_item)

                    if local_gravacao.get("excel", False):
                        excel_pai_item = QTreeWidgetItem(["EXCEL"])
                        excel_pai_item.setIcon(0, get_themed_icon("Caminho Excel", "asset"))
                        excel_pai_item.setData(0, Qt.UserRole, ("excel", grupo))
                        grupo_item.addChild(excel_pai_item)

                        excel_item = QTreeWidgetItem([grupo.get("diretorio", "N/A")])
                        excel_item.setIcon(0, get_themed_icon("Caminho Excel", "asset"))
                        excel_item.setData(0, Qt.UserRole, ("diretorio", grupo))
                        excel_pai_item.addChild(excel_item)

                    if local_gravacao.get("notificacao", False):
                        notificacao_item = QTreeWidgetItem(["NOTIFICAÇÃO"])
                        notificacao_item.setIcon(0, get_themed_icon("Notificacao", "asset"))
                        notificacao_item.setData(0, Qt.UserRole, ("notificacao_parent", grupo))
                        grupo_item.addChild(notificacao_item)

                        notif_config = grupo.get("notificacao", {})
                        topico_item = QTreeWidgetItem([f"Nº de Série: {notif_config.get('topico', 'N/A')}"])
                        topico_item.setData(0, Qt.UserRole, ("notificacao_topico", grupo))
                        notificacao_item.addChild(topico_item)

                        titulo_item = QTreeWidgetItem([f"TÍTULO: {notif_config.get('titulo', 'N/A')}"])
                        titulo_item.setData(0, Qt.UserRole, ("notificacao_titulo", grupo))
                        notificacao_item.addChild(titulo_item)

                        mensagem_item = QTreeWidgetItem([f"MENSAGEM: {notif_config.get('mensagem', 'N/A')}"])
                        mensagem_item.setData(0, Qt.UserRole, ("notificacao_mensagem", grupo))
                        notificacao_item.addChild(mensagem_item)


                    # Nível "EVENTOS" (Locais de Gravação Ativos) - SOB O GRUPO
                    storage_item = QTreeWidgetItem(["EVENTOS"])
                    storage_item.setIcon(0, get_themed_icon("Evento", "asset"))
                    storage_item.setData(0, Qt.UserRole, ("storage_parent", grupo))
                    grupo_item.addChild(storage_item)

                    for metodo, ativo in grupo.get("local_gravacao", {}).items():
                         if ativo:
                            metodo_item = QTreeWidgetItem([metodo.upper()])
                            if metodo == "sql": metodo_icon = get_themed_icon("Banco de Dados", "asset")
                            elif metodo == "mqtt": metodo_icon = get_themed_icon("MQTT", "asset")
                            elif metodo == "excel": metodo_icon = get_themed_icon("Caminho Excel", "asset")
                            elif metodo == "notificacao": metodo_icon = get_themed_icon("Notificacao", "asset")
                            else: metodo_icon = get_themed_icon("Genérico", "asset")
                            metodo_item.setIcon(0, metodo_icon)
                            metodo_item.setData(0, Qt.UserRole, ("storage_method", grupo, metodo))
                            storage_item.addChild(metodo_item)

                    # Adiciona o item "SISTEMA DE CALCULOS" - SOB O GRUPO
                    calculos_item = QTreeWidgetItem(["SISTEMA DE CALCULOS"])
                    calculos_item.setIcon(0, get_themed_icon("Calculos", "asset"))
                    calculos_item.setData(0, Qt.UserRole, ("calculos_parent", grupo))
                    grupo_item.addChild(calculos_item)

                    if grupo.get("calculos"):
                        for nome_calculo, calc_detalhes in grupo["calculos"].items():
                            if isinstance(calc_detalhes, dict):
                                memoria = calc_detalhes.get("memoria", "")
                                formula = calc_detalhes.get("formula", "")
                                formula_text = f"{memoria} {formula}" if memoria else formula
                            else:
                                formula_text = 'Fórmula Inválida/Estrutura Antiga?'

                            # Cria o item na árvore com o nome do cálculo
                            calculo_item = QTreeWidgetItem([nome_calculo])
                            calculo_item.setIcon(0, get_themed_icon("Calculo", "asset"))
                            calculo_item.setData(0, Qt.UserRole, ("calculo", grupo, nome_calculo))

                            # Define a dica (tooltip) com a fórmula completa
                            calculo_item.setToolTip(0, formula_text)

                            # Adiciona o item como filho do item "SISTEMA DE CALCULOS"
                            calculos_item.addChild(calculo_item)





                except Exception as e:
                    log_message = f"❌ Erro ao processar grupo '{grupo.get('grupo', 'Nome Desconhecido')}': {e}"
                    print(log_message)
                    log_queue.put(log_message)
                    if hasattr(self, 'tree_ativos') and self.tree_ativos:
                         error_item = QTreeWidgetItem([f"ERRO ao carregar grupo: {grupo.get('grupo', 'Nome Desconhecido')} - {e}"])
                         error_item.setIcon(0, get_themed_icon("Erro Crítico", "asset"))
                         self.tree_ativos.addTopLevelItem(error_item)
                    else:
                         log_queue.put("Aviso: tree_ativos não inicializado ao tentar adicionar item de erro de grupo.")

        else:
            log_message = "Aviso: Configuração não carregada corretamente ou sem grupos válidos ('grupos' não é lista/dicionário). Árvore de ativos vazia."
            print(log_message)
            log_queue.put(log_message)

        if hasattr(self, 'tree_ativos') and self.tree_ativos and self.tree_ativos.invisibleRootItem():
            root = self.tree_ativos.invisibleRootItem()
            for i in range(root.childCount()):
                grupo_item = root.child(i)
                restaurar_estado_expansao(grupo_item, expanded_state)
        else:
             log_queue.put("Aviso: tree_ativos não inicializado ao tentar restaurar expansão.")

    def populate_file_tree(self, path):
        """
        Popula a segunda árvore (self.tree_arquivos) com a estrutura de arquivos
        a partir do caminho_inicial especificado, usando ícones QStyle nativos
        e carregamento preguiçoso (Lazy Loading) para subdiretórios.
        """
        caminho_inicial =  path
        # Registra a ação no log da aplicação (usando a tupla mensagem, cor)
        #log_queue.put((f"Preenchendo árvore de arquivos para: {caminho_inicial} com ícones QStyle nativos.", "blue"))

        # Desconecta o sinal itemExpanded temporariamente antes de limpar a árvore
        # para evitar que o Lazy Loading seja acionado durante a limpeza.
        # (self.tree_arquivos precisa ser inicializado no __init__)
        if hasattr(self, 'tree_arquivos') and self.tree_arquivos:
             try:
                  # Tenta desconectar o sinal, pode falhar se não estiver conectado ainda
                  self.tree_arquivos.itemExpanded.disconnect(self._carregar_diretorio_sob_demanda)
             except TypeError: # Captura o erro caso o sinal não esteja conectado
                  pass
             # Limpa todos os itens existentes na árvore de arquivos
             self.tree_arquivos.clear()
        else:
             # Registra um aviso se tree_arquivos não estiver inicializado
             log_queue.put(("Aviso: tree_arquivos não inicializado ao tentar limpar.", "orange")) # Usando tupla
             return # Sai da função se a árvore não estiver pronta

        # Verifica se o caminho inicial é um diretório válido
        if not os.path.isdir(caminho_inicial):
            # Se o caminho não for um diretório ou não existir, adiciona um item de erro na raiz
            if hasattr(self, 'tree_arquivos') and self.tree_arquivos:
                item_erro_raiz = QTreeWidgetItem(self.tree_arquivos, [f"Caminho raiz não encontrado ou inválido: {caminho_inicial}"])
                # Usando ícone QStyle nativo para erro crítico
                item_erro_raiz.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))
            # Registra o erro no log
            log_queue.put((f"Erro ao preencher árvore de arquivos: Caminho raiz inválido - {caminho_inicial}", "red")) # Usando tupla
            return # Sai da função

        # Obtém o caminho absoluto para consistência e o nome base/completo para o item raiz
        caminho_raiz = os.path.abspath(caminho_inicial)
        nome_raiz = os.path.basename(caminho_raiz)
        # Cria o item raiz da árvore
        item_raiz = QTreeWidgetItem(self.tree_arquivos, [nome_raiz])
        # Ajusta o texto do item raiz se for um drive (ex: C:\)
        if not item_raiz.text(0) and caminho_raiz:
             item_raiz.setText(0, caminho_raiz)
        elif not item_raiz.text(0): # Fallback se caminho_raiz for vazio ou algo inesperado
             item_raiz.setText(0, caminho_inicial)


        # Usando ícone QStyle nativo para o drive/raiz (ícone de HD)
        icone_raiz = QApplication.instance().style().standardIcon(QStyle.SP_DriveHDIcon)
        item_raiz.setIcon(0, icone_raiz)
        # Armazena o caminho completo do item raiz em seus dados para uso posterior (Lazy Loading)
        item_raiz.setData(0, Qt.UserRole, caminho_raiz)


        try:
            # Lista os itens (pastas e arquivos) APENAS do primeiro nível do caminho raiz
            lista_itens = []
            try:
                 # Lista diretórios e arquivos separadamente e os combina (opcional, para ordenar pastas primeiro)
                 diretorios = [d for d in os.listdir(caminho_raiz) if os.path.isdir(os.path.join(caminho_raiz, d))]
                 arquivos = [f for f in os.listdir(caminho_raiz) if os.path.isfile(os.path.join(caminho_raiz, f))]
                 diretorios.sort() # Ordena diretórios alfabeticamente
                 arquivos.sort() # Ordena arquivos alfababeticamente
                 lista_itens = diretorios + arquivos # Combina, com diretórios na frente

            except Exception as erro_listagem:
                 # Registra erro se houver problema ao listar o primeiro nível
                 log_queue.put((f"Erro ao listar conteúdo do primeiro nível para '{caminho_raiz}': {erro_listagem}", "red")) # Usando tupla
                 item_erro_init = QTreeWidgetItem(item_raiz, [f"ERRO ao listar conteúdo: {erro_listagem}"])
                 # Usando ícone QStyle nativo para erro crítico
                 item_erro_init.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))


            # Itera sobre os itens do primeiro nível
            for nome_item in lista_itens:
                 caminho_item = os.path.join(caminho_raiz, nome_item)
                 # Cria um novo item na árvore sob o item raiz
                 item_arvore_atual = QTreeWidgetItem(item_raiz, [nome_item])
                 # Armazena o caminho completo do item em seus dados
                 item_arvore_atual.setData(0, Qt.UserRole, caminho_item)

                 if os.path.isdir(caminho_item):
                     # Se for um diretório, usa o ícone QStyle nativo de pasta
                     icone_diretorio = QApplication.instance().style().standardIcon(QStyle.SP_DirIcon)
                     item_arvore_atual.setIcon(0, icone_diretorio)
                     # Adiciona um item filho "fantasma" ("Loading...") para mostrar a seta de expansão,
                     # MAS SOMENTE SE o diretório NÃO ESTIVER VAZIO.
                     try:
                          # Verifica eficientemente se o diretório tem algum conteúdo (arquivos ou subdiretórios)
                          if any(True for _ in os.scandir(caminho_item)):
                               item_loading = QTreeWidgetItem(item_arvore_atual, ["Loading..."]) # Item fantasma
                               # Define a cor do texto como cinza médio (self.COLOR_MEDIUM_GRAY precisa ser definido no __init__)
                               item_loading.setForeground(0, QColor(self.COLOR_MEDIUM_GRAY))
                          # else: se o diretório estiver vazio, nenhuma seta de expansão ou item fantasma é adicionado
                     except Exception as erro_verificacao:
                          # Registra erro se houver problema ao verificar o conteúdo (permissão, etc.)
                          log_queue.put((f"Aviso: Erro ao verificar conteúdo do subdiretório '{caminho_item}' para lazy load: {erro_verificacao}. Não adicionando dummy.", "orange")) # Usando tupla


                 else:
                     # Se for um arquivo, usa o ícone QStyle nativo de arquivo genérico
                     icone_arquivo = QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)
                     item_arvore_atual.setIcon(0, icone_arquivo)

            # Conecta o sinal itemExpanded da árvore ao método de Lazy Loading,
            # para que _carregar_diretorio_sob_demanda seja chamado quando uma pasta for expandida.
            self.tree_arquivos.itemExpanded.connect(self._carregar_diretorio_sob_demanda)


        except Exception as erro:
            # Captura erros gerais durante o preenchimento inicial da árvore
            log_message = f"Erro inicial em preencher_arvore_arquivos para caminho {caminho_inicial}: {erro}"
            log_queue.put((log_message, "red")) # Usando tupla
            if hasattr(self, 'tree_arquivos') and self.tree_arquivos:
                 item_erro_init = QTreeWidgetItem(item_raiz, [f"ERRO ao preencher: {erro}"])
                 # Usando ícone QStyle nativo para erro crítico
                 item_erro_init.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))

        # Expande o item raiz por padrão
        item_raiz.setExpanded(True)
        # Registra a conclusão no log
        #log_queue.put(("Árvore de arquivos preenchida (carregamento sob demanda) com ícones QStyle.", "blue")) # Usando tupla

    def _carregar_diretorio_sob_demanda(self, item_arvore):
        """
        Carrega os subdiretórios e arquivos de um diretório específico
        quando seu item correspondente na árvore é expandido (Lazy Loading),
        usando ícones QStyle nativos.
        """
        # Verifica se o item expandido é um diretório que ainda precisa ser carregado
        # (ou seja, se ele tem o item filho "Loading..." e nenhum outro)
        if item_arvore.childCount() == 1 and item_arvore.child(0).text(0) == "Loading...":
            # Remove o item filho "fantasma" ("Loading...")
            item_arvore.removeChild(item_arvore.child(0))

            # Obtém o caminho completo do diretório a ser carregado a partir dos dados do item
            # (Assumimos que este caminho foi armazenado em preencher_arvore_arquivos ou em uma chamada anterior deste método)
            caminho_diretorio = item_arvore.data(0, Qt.UserRole)
            # Verifica se o caminho é válido
            if not caminho_diretorio or not isinstance(caminho_diretorio, str):
                 log_queue.put((f"Erro carregamento sob demanda: Caminho do item da árvore de arquivos não encontrado ou inválido nos dados para '{item_arvore.text(0)}'.", "red")) # Usando tupla
                 item_erro = QTreeWidgetItem(item_arvore, ["Erro: Caminho inválido nos dados."])
                 # Usando ícone QStyle nativo para erro crítico
                 item_erro.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))
                 return # Sai da função

            # Verifica se o caminho ainda é um diretório real no sistema de arquivos
            if not os.path.isdir(caminho_diretorio):
                 item_erro = QTreeWidgetItem(item_arvore, [f"Erro: Caminho '{caminho_diretorio}' não é mais um diretório."])
                 # Usando ícone QStyle nativo para erro crítico
                 item_erro.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))
                 log_queue.put((f"Erro carregamento sob demanda: Caminho '{caminho_diretorio}' não é um diretório.", "red")) # Usando tupla
                 return # Sai da função


            try:
                 # Lista e popula o conteúdo real (subdiretórios e arquivos) do diretório
                 diretorios = [d for d in os.listdir(caminho_diretorio) if os.path.isdir(os.path.join(caminho_diretorio, d))]
                 arquivos = [f for f in os.listdir(caminho_diretorio) if os.path.isfile(os.path.join(caminho_diretorio, f))]
                 diretorios.sort()
                 arquivos.sort()
                 lista_itens = diretorios + arquivos

                 # Se a lista de itens estiver vazia, adiciona um indicador "<Diretório Vazio>"
                 if not lista_itens:
                      item_vazio = QTreeWidgetItem(item_arvore, ["<Diretório Vazio>"])
                      # Define a cor do texto como cinza médio (self.COLOR_MEDIUM_GRAY precisa ser definido no __init__)
                      item_vazio.setForeground(0, QColor(self.COLOR_MEDIUM_GRAY))
                      log_queue.put((f"DEBUG: Diretório vazio: {caminho_diretorio}", "blue")) # Usando tupla


                 # Itera sobre os itens encontrados no diretório
                 for nome_sub_item in lista_itens:
                      caminho_sub_item = os.path.join(caminho_diretorio, nome_sub_item)
                      # Cria um novo item na árvore sob o item pai (o diretório que foi expandido)
                      item_sub_arvore = QTreeWidgetItem(item_arvore, [nome_sub_item])
                      # Armazena o caminho completo do sub-item em seus dados
                      item_sub_arvore.setData(0, Qt.UserRole, caminho_sub_item)


                      if os.path.isdir(caminho_sub_item):
                          # Se for um subdiretório, usa o ícone QStyle nativo de pasta
                          icone_diretorio = QApplication.instance().style().standardIcon(QStyle.SP_DirIcon)
                          item_sub_arvore.setIcon(0, icone_diretorio)
                          # Adiciona o item "fantasma" ("Loading...") para o Lazy Loading nos níveis mais baixos,
                          # MAS SOMENTE SE o subdiretório NÃO ESTIVER VAZIO.
                          try:
                               if any(True for _ in os.scandir(caminho_sub_item)): # Verifica eficientemente se o subdiretório tem conteúdo
                                    item_loading = QTreeWidgetItem(item_sub_arvore, ["Loading..."])
                                    item_loading.setForeground(0, QColor(self.COLOR_MEDIUM_GRAY))
                          except Exception as erro_verificacao:
                               # Registra erro se houver problema ao verificar o conteúdo do subdiretório
                               log_queue.put((f"Aviso: Erro ao verificar conteúdo do subdiretório '{caminho_sub_item}' para lazy load: {erro_verificacao}. Não adicionando dummy.", "orange")) # Usando tupla


                      else:
                          # Se for um arquivo, usa o ícone QStyle nativo de arquivo genérico
                          icone_arquivo = QApplication.instance().style().standardIcon(QStyle.SP_FileIcon)
                          item_sub_arvore.setIcon(0, icone_arquivo)

            except Exception as erro:
                # Captura erros gerais durante o carregamento do conteúdo de um diretório expandido
                item_erro = QTreeWidgetItem(item_arvore, [f"Erro ao carregar conteúdo: {erro}"])
                # Usando ícone QStyle nativo para erro crítico
                item_erro.setIcon(0, QApplication.instance().style().standardIcon(QStyle.SP_MessageBoxCritical))
                log_queue.put((f"Erro ao listar conteúdo do diretório '{caminho_diretorio}' durante carregamento sob demanda: {erro}", "red")) # Usando tupla
    # --------------------------------

    # Criar menu flutuante do ferramentas
    def create_menu_actions(self, menu_bar):
        ferramentas_menu = None
        for action in menu_bar.actions():
             if action.text() == "Ferramentas":
                 ferramentas_menu = action.menu()
                 break

        if ferramentas_menu is None:
             ferramentas_menu = menu_bar.addMenu("Ferramentas")

        script_action = QAction(get_themed_icon("Script Editor", "menu"), "Editor de Script", self)
        script_action.triggered.connect(self.open_script_window)
        ferramentas_menu.addAction(script_action)


        propriedades_action = QAction(get_themed_icon("Script Editor", "menu"), "Editor de Ativos", self)
        propriedades_action.triggered.connect(self.open_properties_window)
        ferramentas_menu.addAction(propriedades_action)


        self.acao_abrir_config_licenca = QAction(get_themed_icon("Script Editor", "menu"), "Configuração de Licença", self)
        self.acao_abrir_config_licenca.triggered.connect(self.abrir_config_licenca)
        ferramentas_menu.addAction(self.acao_abrir_config_licenca)

        service_action = QAction(get_themed_icon("Script Editor", "menu"), "Start Serviço", self)
        service_action.triggered.connect(self.inicia_service)
        ferramentas_menu.addAction(service_action)


    def open_script_window(self):
        script_window = QMdiSubWindow()
        script_window.setWindowTitle("Editor de Script")
        script_window.setAttribute(Qt.WA_DeleteOnClose, True)

        script_editor = QTextEdit()
        script_editor.setPlaceholderText("Digite seu código aqui...")
        script_window.setWidget(script_editor)

        self.mdi_area.addSubWindow(script_window)
        script_window.showMaximized()
        log_queue.put("Abrindo Editor de Script...")



    def abrir_assistente_configuracao(self):
        """
        Gerencia a abertura e reativação da janela do Assistente de Configuração.
        Configura todas as conexões de sinal/slot necessárias para o funcionamento,
        ativação e fechamento correto da janela.
        """
        # Acessa a fila de log.
        log_q = log_queue.put

        # Fecha a janela lateral de ativos e arquivos
        self.dock_tree.setVisible(False)
        

        # 1. Verifica se a janela já está aberta. Se sim, ativa-a e retorna.
        # Usa um bloco try...except para lidar com a condição de 'objeto C++ deletado'.
        if hasattr(self, '_janela_assistente') and self._janela_assistente is not None:
            try:
                # Se a referência Python ainda existe, mas o objeto C++ foi destruído, tentar acessá-lo dará RuntimeError.
                if self._janela_assistente.widget() is self._widget_assistente:
                    self.mdi_area.setActiveSubWindow(self._janela_assistente)
                    log_q(("Assistente de Configuração já estava aberto. Ativando janela.", "blue"))
                    return # Sai para não criar uma nova.
            except RuntimeError:
                # O objeto foi destruído, mas a referência não foi limpa. Limpa agora.
                log_q(("AVISO: Referência da janela do assistente estava 'zumbi'. Limpando e recriando.", "orange"))
                self._janela_assistente = None
                self._widget_assistente = None
        
        # 2. Se chegou aqui, cria uma nova janela.
        log_q("Criando nova janela para o Assistente de Configuração...")
        
        # Cria a QMdiSubWindow (o "contêiner").
        self._janela_assistente = QMdiSubWindow(self)
        self._janela_assistente.setWindowTitle("Assistente de Configuração")
        self._janela_assistente.setMinimumSize(850, 650)
        self._janela_assistente.setAttribute(Qt.WA_DeleteOnClose, True)

        # CRUCIAL - CONEXÃO 1: LIMPEZA
        # Conecta o sinal 'destroyed' da janela ao método que limpa as referências.
        # Assume que _janela_assistente_destruida está definido na sua classe.
        self._janela_assistente.destroyed.connect(self._janela_assistente_destruida)


        # Cria o nosso widget de conteúdo.
        # A classe WidgetAssistente deve estar definida antes desta classe.
        self._widget_assistente = WidgetAssistente(parent=self)
        
        
        # === CONEXÕES ESSENCIAIS DO WIDGET PARA A JANELA PRINCIPAL ===

        # CRUCIAL - CONEXÃO 2: ATIVAÇÃO
        # Conecta o sinal 'solicitacaoAtivacao' emitido pelo widget
        # ao método nesta classe que INICIA A THREAD.
        # Assume que _lidar_com_solicitacao_ativacao_thread está definido na sua classe.
        self._widget_assistente.solicitacaoAtivacao.connect(self._lidar_com_solicitacao_ativacao_thread)
        
        # CRUCIAL - CONEXÃO 3: FINALIZAÇÃO E FECHAMENTO
        # Conecta o sinal 'assistenteConcluido' emitido pelo widget (quando o botão 'Finalizar' é clicado)
        # ao método nesta classe que vai FECHAR A JANELA.
        # Assume que _fechar_janela_assistente está definido na sua classe.
        self._widget_assistente.assistenteConcluido.connect(self._fechar_janela_assistente)

        # ================================================================

        # Define o widget como conteúdo da subjanela e adiciona à área MDI.
        self._janela_assistente.setWidget(self._widget_assistente)
        self.mdi_area.addSubWindow(self._janela_assistente)
        
        # Exibe a janela para o usuário.
        self._janela_assistente.show()

        log_q(("Janela do Assistente de Configuração criada e exibida com sucesso.", "green"))

    def _lidar_com_solicitacao_ativacao_thread(self, nova_chave: str):
        # A implementação deste método, que cria e inicia a ThreadAtivarLicenca,
        # permanece a mesma que você já tem funcionando. Ela deve apenas
        # certificar-se de conectar o sinal `resultado` da thread ao slot `finalizar_ativacao`.
        log_q = log_queue.put
        try:
            instance_id_maquina = self.numero_serie if hasattr(self, 'numero_serie') and self.numero_serie and isinstance(self.numero_serie, str) and self.numero_serie.strip() not in ["SN_DESCONHECIDO", "SN_ERRO_INIT", "SN_INDISPONIVEL"] else get_system_info()

            if not instance_id_maquina or instance_id_maquina.strip() in ["SN_DESCONHECIDO", "SN_ERRO_INIT", "SN_INDISPONIVEL"]:
                raise ValueError("Não foi possível obter um Instance ID válido para a máquina.")

            log_q(f"Usando Instance ID (Numero de série) da máquina para ativação: {instance_id_maquina}")
            log_q("Iniciando thread para chamada 'ativar_licenca'...")

            self.thread_licenca = ThreadAtivarLicenca(nova_chave, instance_id_maquina)
            self.thread_licenca.resultado.connect(self.finalizar_ativacao)
            self.thread_licenca.start()

        except Exception as e:
            log_q((f"❌ ERRO CRÍTICO ao iniciar a Thread de ativação: {type(e).__name__} - {e}", "red"))
            QMessageBox.critical(self, "Erro ao iniciar ativação", str(e))



    def _janela_assistente_destruida(self, obj=None):
        # Abre a janela lateral de ativos e arquivos
        self.dock_tree.setVisible(True)
        if hasattr(self, '_janela_assistente') and self._janela_assistente == obj:
            self.log_queue.put(("Janela do Assistente destruída. Limpando referências...", "blue"))
            self._janela_assistente = None
            self._widget_assistente = None


    def _fechar_janela_assistente(self):
        """Slot chamado pelo WidgetAssistente para fechar a sua própria janela MDI."""
        if hasattr(self, '_janela_assistente') and self._janela_assistente:
            log_queue.put(("Recebido sinal para fechar assistente. Fechando janela MDI...", "blue"))
            try:
                self._janela_assistente.close()

                
            except RuntimeError:
                log_queue.put(("AVISO: Tentativa de fechar janela do assistente que já estava destruída.", "orange"))
                self._janela_assistente = None
                self._widget_assistente = None





# ----------------- Sistema de Licenças -------------------
    def _lidar_com_solicitacao_ativacao(self, nova_chave: str):

        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para seguir com ativação de licença.")
            return    
        self.start_progressbar()    #   inicializa o progressbar na interface

        log_q = log_queue.put
        log_q((f"Iniciando fluxo de ativação _lidar_com_solicitacao_ativacao com chave: {nova_chave[:8]}...", "blue"))

        if not hasattr(self, '_widget_licenca') or self._widget_licenca is None or not isinstance(self._widget_licenca, WidgetConfiguracaoLicenca):
            log_q(("AVISO: Referência para _widget_licenca inválida ou perdida no início de _lidar_com_solicitacao_ativacao. Abortando, não posso atualizar UI.", "orange"))
            return

        try:
            self._widget_licenca.definir_estado_botao_ativacao(False)
        except Exception as e:
            log_q((f"AVISO: Falha ao desabilitar botão de ativação no widget via método: {type(e).__name__} - {e}", "red"))

        try:
            instance_id_maquina = self.numero_serie if hasattr(self, 'numero_serie') and self.numero_serie and isinstance(self.numero_serie, str) and self.numero_serie.strip() not in ["SN_DESCONHECIDO", "SN_ERRO_INIT", "SN_INDISPONIVEL"] else get_system_info()

            if not instance_id_maquina or instance_id_maquina.strip() in ["SN_DESCONHECIDO", "SN_ERRO_INIT", "SN_INDISPONIVEL"]:
                raise ValueError("Não foi possível obter um Instance ID válido para a máquina.")

            log_q(f"Usando Instance ID (Numero de série) da máquina para ativação: {instance_id_maquina}")
            log_q("Iniciando thread para chamada 'ativar_licenca'...")

            self.thread_licenca = ThreadAtivarLicenca(nova_chave, instance_id_maquina)
            self.thread_licenca.resultado.connect(self.finalizar_ativacao)
            self.thread_licenca.start()

        except Exception as e:
            log_q((f"❌ ERRO CRÍTICO ao iniciar a Thread de ativação: {type(e).__name__} - {e}", "red"))
            QMessageBox.critical(self, "Erro ao iniciar ativação", str(e))
            if hasattr(self, '_widget_licenca'):
                self._widget_licenca.definir_estado_botao_ativacao(True)

    def finalizar_ativacao(self, resposta_servidor_raw):
        log_q = log_queue.put
        final_process_data = {}
        activation_exception_occurred = False

        try:
            instance_id_maquina = self.numero_serie if hasattr(self, 'numero_serie') and self.numero_serie else get_system_info()

            log_q("Descriptografando resposta da requisição >> 'montar_dados_licenca_ativacao'...")
            dados_processados_para_salvar_exibir = montar_dados_licenca_ativacao(
                resposta_servidor_raw, instance_id_maquina, self.thread_licenca.chave
            )

            log_q(f"Dados formatados: {dados_processados_para_salvar_exibir.get('sucesso')}")

            global CAMINHO_ARQUIVO_ATIVACAO
            salvar_json_licenca_ativacao(dados_processados_para_salvar_exibir, CAMINHO_ARQUIVO_ATIVACAO)

            final_process_data = dados_processados_para_salvar_exibir.copy()

        except Exception as e:
            activation_exception_occurred = True
            msg = f"❌ ERRO durante finalização da ativação: {type(e).__name__} - {e}"
            log_q((msg, "red"))
            QMessageBox.critical(self, "Erro na Ativação", msg)

            final_process_data = {
                "modo": "ativacao",
                "status": "ERRO_FINALIZACAO",
                "sucesso": False,
                "instance_id": instance_id_maquina if 'instance_id_maquina' in locals() else "N/A",
                "token": None,
                "license_key": self.thread_licenca.chave_digitada,
                "expires_at": None,
                "ativacoes": None,
                "limite_ativacoes": None,
                "mensagem": msg,
                "notificacao_servico": "FALHA_NO_PROCESSO"
            }

        finally:
            if hasattr(self, '_widget_licenca') and self._widget_licenca:
                try:
                    self._widget_licenca.exibir_dados_licenca(final_process_data)
                    if final_process_data.get("sucesso") is True and not activation_exception_occurred:
                        self._widget_licenca.limpar_input_chave()
                        #log_q("Campo da nova chave limpo (resultado final indica sucesso).")
                    else:
                        log_q("Campo da nova chave NÃO limpo (resultado final NÃO indica sucesso).")
                except Exception as e:
                    log_q((f"ERRO ao atualizar a UI: {type(e).__name__} - {e}", "red"))

                try:
                    self._widget_licenca.definir_estado_botao_ativacao(True)
                    log_q("Reabilitado sistema de licenciamento.")
                except Exception as e:
                    log_q((f"AVISO ao reabilitar licenciamento: {type(e).__name__} - {e}", "orange"))

            status_final_log = final_process_data.get('status', 'N/A')
            sucesso_final_log = final_process_data.get('sucesso', False)
            result = final_process_data.get('mensagem', 'N/A')

            if not activation_exception_occurred and sucesso_final_log is True:
                log_q((f"[API] --- PROCESSO DE ATIVAÇÃO CONCLUÍDO COM SUCESSO [STATUS]: {status_final_log} ---", "green"))
                # Verifica se o widget do assistente ainda está aberto antes de chamar seu método
                if hasattr(self, '_widget_assistente') and self._widget_assistente:
                    # CHAMA o método público do widget para que ELE atualize a si mesmo
                    self._widget_assistente.ativacao_concluida(True, result)
            elif activation_exception_occurred:
                log_q((f"[API] --- PROCESSO DE ATIVAÇÃO TERMINOU COM EXCEÇÃO [STATUS]: {status_final_log} ---", "red"))
            else:
                log_q((f"[API] --- PROCESSO DE ATIVAÇÃO FALHOU LOGICAMENTE [STATUS]: {status_final_log} ---", "orange"))
                # Verifica se o widget do assistente ainda está aberto antes de chamar seu método
                if hasattr(self, '_widget_assistente') and self._widget_assistente:
                    # CHAMA o método público do widget para que ELE atualize a si mesmo
                    self._widget_assistente.ativacao_concluida(False, result)


            if final_process_data.get("sucesso") is True and not activation_exception_occurred:
                if hasattr(self, 'notify_license_update') and callable(self.notify_license_update):
                    try:
                        self.notify_license_update()
                        log_q("[API] --- Processo de ativação interno iniciado com sucesso ✅... ")
                    except Exception as e:
                        log_q((f"[API] --- AVISO ao chamar notify_license_update: Processo de ativação de licença interno {type(e).__name__} - {e}", "orange"))




   

    def inicializar_arquivo_licenca_interno(self):
        formato_data = "%d-%m-%Y %H:%M:%S"
        agora_str = datetime.now().strftime(formato_data)
        numero_serie = self.numero_serie

        # Se o arquivo já existe, preserva valores
        if os.path.exists(LICENSE_FILE):
            try:
                with open(LICENSE_FILE, 'rb') as f:
                    conteudo = f.read()
                dados = json.loads(descriptografar_dados(conteudo).decode('utf-8'))

                # Apenas inicializa os campos 
                dados["numero_serie"] = numero_serie
                dados["dias"] = 0
                dados["ultima_atualização_dias"] = agora_str
                dados["ultima_verificacao_real"] = agora_str
                dados["ultimo_registro_validado"] = agora_str
                dados["licenca"] = True
                dados["motivo"] = "Ativação ..."
                log_queue.put(("[Licença] processo de licença [inicializar_arquivo_licenca_interno] atualizado e concluido...", "blue"))

            except Exception as e:
                print(f"[ERRO] Falha ao ler/atualizar arquivo existente: {e}")
                log_queue.put((f"[Licença] [ERRO] Falha ao ler/atualizar arquivo existente:[inicializar_arquivo_licenca_interno]  {e} ", "red"))
                dados = {
                    "numero_serie": numero_serie,
                    "dias": 0,
                    "ultima_atualização_dias": agora_str,
                    "ultima_verificacao_real": agora_str,
                    "ultimo_registro_validado": agora_str,
                    "licenca": True,
                    "motivo": "Ativação ... (fallback)"
                }

        else:
            # Arquivo ainda não existe, cria do zero
            dados = {
                "numero_serie": numero_serie,
                "dias": 0,
                "ultima_atualização_dias": agora_str,
                "ultima_verificacao_real": agora_str,
                "ultimo_registro_validado": agora_str,
                "licenca": True,
                "motivo": "Ativação ... "
            }
        log_queue.put((f"[Licença] [INFO] criando novo arquivo de licença >> Authentication [inicializar_arquivo_licenca_interno]", "orange"))
        # Salva o arquivo (recriptografado)
        conteudo_final = criptografar_dados(json.dumps(dados, indent=4).encode('utf-8'))
        with open(LICENSE_FILE, 'wb') as f:
            f.write(conteudo_final)

    def notify_license_update(self):
        try:
            recriar_arquivo_validacao_vazio()
        except Exception as e:
            log_queue.put(("[Erro] No processo de criação do arquivo adicional de licença: [recriar_arquivo_validacao_vazio] >> {e}", "red"))
        try:
            threading.Thread(target=self.inicializar_arquivo_licenca_interno, daemon=True).start()
        except Exception as e:
            log_queue.put(("[Erro] No processo de licença: [inicializar_arquivo_licenca_interno] >> {e}", "red")) 
        try:
            threading.Thread(target=monitorar_dias_e_serial, daemon=True).start()
        except Exception as e:
            log_queue.put(("[Erro] No processo de licença: [monitorar_dias_e_serial] >> {e}", "red"))
        try:
            threading.Thread(target=monitorar_licenca, daemon=True).start()
        except Exception as e:
            log_queue.put(("[Erro] No processo de licença: [threading.Thread(target=monitorar_licenca, daemon=True).start()] >> {e}", "red"))

    def abrir_config_licenca(self):
        """
        Gerencia a abertura ou ativação da subjanela MDI para configuração de licença.
        Carrega os dados da licença local (Authentication_ativacao.cfg) e exibe no widget.
        Lida com arquivo não encontrado ou vazio/inválido na leitura.
        """
        # Acessa a fila de log (deve estar inicializada em __init__)
        log_q = log_queue.put

        try:
            if (hasattr(self, '_janela_licenca') and self._janela_licenca is not None and
                hasattr(self, '_widget_licenca') and self._widget_licenca is not None and
                self._janela_licenca.widget() is self._widget_licenca):
                self.mdi_area.setActiveSubWindow(self._janela_licenca)
                return
        except RuntimeError:
            # O objeto já foi destruído, limpe as referências e prossiga para criar uma nova janela normalmente
            self._janela_licenca = None
            self._widget_licenca = None

        # 2. Se a janela não está aberta ou não é válida, carrega os dados ATUAIS da licença do arquivo local.
        # Este método auxiliar _carregar_dados_arquivo_licenca foi projetado para ser ROBUSTO.
        # Chama o método auxiliar _carregar_dados_arquivo_licenca (que DEVE ESTAR DEFINIDO NA AplicacaoSupervisoria).
        dados_licenca_do_arquivo = self._carregar_dados_arquivo_licenca() # <<< Chama o método auxiliar desta CLASSE.


        # 3. Cria a nova subjanela MDI (o contêiner).
        # Cria um novo QMdiSubWindow, filho da janela principal (self).
        self._janela_licenca = QMdiSubWindow(self) # Passa self como parent.
        self._janela_licenca.setWindowTitle("Configuração de Licença") # Título da janela MDI
        # Configura para auto-destruição e conecta o slot de limpeza de referências.
        self._janela_licenca.setAttribute(Qt.WA_DeleteOnClose, True)
        self._janela_licenca.destroyed.connect(self._janela_licenca_destruida) # <<< Conecta ao método _janela_licenca_destruida (abaixo ou definido em outro lugar na classe).


        # 4. Cria a instância do nosso widget personalizado de conteúdo.
        # Passamos os dados lidos do arquivo (mesmo que seja o dict de status de erro)
        # E a referência para a janela principal 'self' como pai.
        # Assume WidgetConfiguracaoLicenca é uma classe definida e importada antes da AplicacaoSupervisoria.
        self._widget_licenca = WidgetConfiguracaoLicenca(dados_licenca_do_arquivo, parent=self) # <<< Cria o widget customizado.


        # 5. Conecta o sinal 'solicitacaoAtivacao' emitido pelo widget ao método
        # nesta classe (_lidar_com_solicitacao_ativacao) que fará a lógica de ativação REAL.
        # Assume _lidar_com_solicitacao_ativacao é um método definido nesta classe.
        self._widget_licenca.solicitacaoAtivacao.connect(self._lidar_com_solicitacao_ativacao) # <<< Conecta ao slot _lidar_com_solicitacao_ativacao (abaixo ou definido).


        # 6. Define o widget customizado como o conteúdo visual da subjanela MDI.
        self._janela_licenca.setWidget(self._widget_licenca)


        # 7. Adiciona a subjanela MDI à área MDI principal da aplicação.
        self.mdi_area.addSubWindow(self._janela_licenca) # <<< Adiciona ao MDI Area.


        # 8. Exibe a subjanela para o usuário.
        # Use show() para permitir tamanho inicial ou showMaximized().
        self._janela_licenca.show() # Mostra com tamanho inicial padrão.


        log_q(("Janela de Configuração de Licença.", "green"))

    def _carregar_dados_arquivo_licenca(self) -> dict:
        """
        Tenta ler, descriptografar e processar o arquivo local de ativação
        (Authentication_ativacao.cfg). Este arquivo é usado para armazenar
        o resultado da ÚLTIMA tentativa de ativação de licença com o servidor.

        Retorna um dicionário contendo os dados da licença lidos e processados em caso de sucesso.
        Em caso de falha (arquivo não encontrado, vazio, ilegível, corrompido, etc.),
        retorna um dicionário PREDETERMINADO que informa claramente a natureza da falha,
        mas sem levantar exceção.
        Este dicionário retornado é sempre em um formato que
        WidgetConfiguracaoLicenca.exibir_dados_licenca sabe como exibir (mesmo que apenas status/mensagem de erro).
        É chamado por self.abrir_config_licenca e por self._lidar_com_solicitacao_ativacao (se precisar recarregar o display após uma ação).

        Depende da função GLOBAL ler_json_licenca.
        """
        # Acessa a fila de log (deve estar inicializada em self.log_queue em __init__)
        log_q = self.log_queue if hasattr(self, 'log_queue') else print # Use self.log_queue

        caminho_arquivo_local = self._caminho_arquivo_ativacao # Usa a constante global para o caminho.


        log_q(f"Carregando dados do arquivo de licença local: {caminho_arquivo_local}")

        try:
            # =================================================================
            # USA A FUNÇÃO GLOBAL 'ler_json_licenca'
            # Esta função (que você já deve ter copiado) faz o trabalho de
            # checar se o arquivo existe, abrir, ler binário, tentar descriptografar,
            # decodificar UTF-8, tentar parsear JSON, e validar se é um dicionário.
            # Ela NÃO DEVE LEVANTAR EXCEÇÃO para problemas comuns (não encontrado, vazio,
            # ilegível, corrompido, JSON inválido) e sim RETORNAR None ou {}.
            # Exceções são para falhas de I/O muito baixas (permissão, disco),
            # mas tentamos pegá-las dentro dela também.
            # =================================================================
            # Chama a função GLOBAL ler_json_licenca, passando o caminho do arquivo.
            dados_licenca_lidos = ler_json_licenca(caminho_arquivo_local) # <<< CHAMA A FUNÇÃO GLOBAL!


            # =================================================================
            # === Análise do Resultado da função Global ler_json_licenca ===
            # (Trata os possíveis retornos: None, {}, ou dict)
            # =================================================================

            # 1. Resultado é None: 'ler_json_licenca' não conseguiu nem encontrar/abrir o arquivo ou teve um erro muito grave na leitura binária.
            if dados_licenca_lidos is None:
                # ler_json_licenca já logou que o arquivo não foi encontrado/falhou na leitura base.
                msg_log = "Arquivo de licença local NÃO encontrado ou falha grave na leitura binária (indicado por ler_json_licenca)."
                log_q((msg_log, "orange")) # Log para a fila da GUI.
                # Retorna um dicionário padronizado que WidgetConfiguracaoLicenca.exibir_dados_licenca sabe como interpretar
                # para mostrar na UI: "INATIVO - Arquivo Local Não Encontrado".
                return {"modo": "ativacao", "status": "INATIVO",
                        "mensagem": "Arquivo local de ativação não encontrado. Ative a licença.",
                        "sucesso": False, # Indicar claramente como false
                        "license_key": "N/A", "token": "N/A",
                        "expires_at": "N/A", "ativacoes": "N/A", "limite_ativacoes": "N/A",
                        # Opcional: Adicionar timestamp de quando a leitura falhou:
                        # "ultima_verificacao_local": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                       } # Retorna um dicionário formatado.


            # 2. Resultado é um Dicionário Vazio ({}) ou similar avaliando como False: 'ler_json_licenca' encontrou o arquivo
            # mas o conteúdo estava vazio, a criptografia/Base64 estava errada, ou não era um JSON válido,
            # ou o JSON não parseou para um dicionário populado.
            elif not dados_licenca_lidos: # Este `not dados_licenca_lidos` verifica se é um dicionário vazio {} (ou [] ou None, mas None já foi pego)
                 msg_log = "Arquivo de licença local encontrado, mas o conteúdo não pôde ser lido/processado em um dicionário válido pela função global."
                 log_q((msg_log, "red")) # Log na fila da GUI com cor de erro.
                 # Avisar o usuário diretamente na UI via QMessageBox (complementa o log).
                 QMessageBox.warning(self, "Erro de Arquivo Local", "O arquivo de licença local está vazio, corrompido ou inválido. Por favor, reative a licença.")
                 # Retorna um dicionário de status formatado para a UI, indicando falha no conteúdo/processamento.
                 return {"modo": "ativacao", "status": "ERRO",
                         "mensagem": "Falha ao ler/processar arquivo local. Conteúdo inválido/vazio/corrompido.",
                         "sucesso": False, # Indicar claramente como false
                         "license_key": "ERRO", "token": "ERRO",
                         "expires_at": "N/A", "ativacoes": "N/A", "limite_ativacoes": "N/A"} # Retorna um dicionário formatado.


            # 3. Resultado é um Dicionário Populado (type é dict e avalia como True): A função ler_json_licenca conseguiu ler,
            # descriptografar, decodificar UTF-8 e parsear JSON para um dicionário. Assumimos sucesso na leitura local.
            elif isinstance(dados_licenca_lidos, dict):
                 log_q("Dados de licença lidos com sucesso do arquivo local e parseados como dicionário válido.")


                 return dados_licenca_lidos # Retorna o dicionário lido da função global (SEM MODIFICAÇÃO DE STATUS/SUCESSO POR CHECK OFFLINE NESTE EXEMPLO).


            # Este else NÃO deveria ser alcançado se a lógica anterior foi correta.
            # Se 'dados_licenca_lidos' não for None, {} ou dict, há um problema na 'ler_json_licenca'.
            else:
                 msg_log = f"Função global ler_json_licenca retornou um tipo INESPERADO: {type(dados_licenca_lidos).__name__}"
                 log_q((msg_log, "red"))
                 # Mensagem para o usuário sobre um erro na função de leitura.
                 QMessageBox.critical(self, "Erro Interno de Leitura", f"Falha na função de leitura de licença local: retorno de tipo inesperado.\nDetalhe: {type(dados_licenca_lidos).__name__}")
                 # Retorna um dicionário de status de erro consistente, mesmo para um retorno inesperado.
                 return {"modo": "ativacao", "status": "ERRO_INTERNO",
                         "mensagem": f"Falha na função de leitura de licença: Retorno inesperado {type(dados_licenca_lidos).__name__}",
                         "sucesso": False, # Indica claramente false
                         "license_key": "ERRO", "token": "ERRO",
                         "expires_at": "N/A", "ativacoes": "N/A", "limite_ativacoes": "N/A"} # Retorna um dicionário formatado.


        # Conforme projetamos ler_json_licenca, ela tenta pegar a maioria dos erros e retornar None/{}, então este catch aqui é um ÚLTIMO RECURSO.
        except Exception as e:
            # Se chegamos aqui, uma exceção subiu da chamada `ler_json_licenca(...)` (ou algo antes do try/except interno dessa global).
            msg_erro_inesperado = f"❌ ERRO INESPERADO (subiu de ler_json_licenca ou chamada) durante o carregamento de dados da licença local: {type(e).__name__} - {e}"
            log_q((msg_erro_inesperado, "red"))
            # Exibe uma QMessageBox para o usuário para erros de alto nível que impedem a leitura.
            QMessageBox.critical(self, "Erro Crítico de Arquivo", f"Ocorreu um erro crítico ao tentar carregar os dados da licença local:\nDetalhe: {e}")
            # Retorna um dicionário de status de erro consistente, informando que não foi possível carregar NADA devido ao erro.
            return {"modo": "ativacao", "status": "ERRO_CRÍTICO_INESPERADO",
                    "mensagem": f"Falha crítica inesperada ao carregar arquivo local. Detalhe: {e}",
                    "sucesso": False, "license_key": "ERRO", "token": "ERRO",
                    "expires_at": "N/A", "ativacoes": "N/A", "limite_ativacoes": "N/A"}

    def _janela_licenca_destruida(self, obj=None):
        """
        Slot chamado quando a subjanela MDI de configuração de licença é fechada/destruída.
        Limpa as referências internas (_janela_licenca, _widget_licenca) para evitar
        referências a objetos C++ deletados e permitir que uma nova janela seja criada.
        Conectado ao sinal destroyed da QMdiSubWindow da licença em abrir_config_licenca.
        """
        # Acessa a fila de log (deve estar inicializada em self.log_queue em __init__)
        log_q = self.log_queue if hasattr(self, 'log_queue') else print # Use self.log_queue

        # O objeto 'obj' que é passado é o objeto (neste caso, a QMdiSubWindow) que está sendo destruído.
        # Verificamos se as nossas referências correspondem ao objeto que está sendo destruído
        # antes de limpar os atributos internos.
        if hasattr(self, '_janela_licenca') and self._janela_licenca is not None and self._janela_licenca == obj:
             log_q("Subjanela de Configuração de Licença detectada como destruída.")
             # Limpa as referências internas da AplicacaoSupervisoria.
             # Definir como None permite que open_config_licenca crie uma nova janela da próxima vez.
             self._janela_licenca = None
             self._widget_licenca = None # Limpa a referência para o widget de conteúdo também.
             log_q("Referências da janela de licença (janela MDI e widget) limpas na AplicacaoSupervisoria.")
# ----------------------------------------------------------------------


    # --- Janela de logs ---
    def _update_logs_area(self, log_message, color="black"):
        """Updates the logs_area QTextEdit with a message and color."""
        # This method is called ONLY from processar_logs
        if self.logs_area is not None:
            try:
                cursor = self.logs_area.textCursor()
                cursor.movePosition(QTextCursor.End)

                # Use QTextCharFormat for colored text
                char_format = QTextCharFormat()
                # Look up the color from the map, default to black
                # self._color_map precisa estar definido no seu __init__
                qcolor = QColor(self._color_map.get(color.lower(), self._color_map["black"]))
                char_format.setForeground(qcolor)

                cursor.insertText(log_message, char_format)
                cursor.insertHtml("<br>") # Use HTML break for newline

                self.logs_area.setTextCursor(cursor)
                self.logs_area.ensureCursorVisible()
            except Exception as e:
                # Fallback if updating logs_area fails for some reason
                print(f"FATAL ERROR updating logs_area: {e}")
                # Avoid putting errors back into the queue in the log processing function itself

    def processar_logs(self):
        """Verifica e processa a fila de logs para adicionar à história e à interface."""
    
        while not log_queue.empty():
            try:
                item = log_queue.get_nowait()

                # Process item: get message and color
                if isinstance(item, tuple) and len(item) == 2:
                    log_message, color = str(item[0]), str(item[1]).lower()
                else:
                    log_message = str(item)
                    color = "black" # Default color

                # Add to history (self.log_history precisa ser inicializado no __init__)
                self.log_history.append((log_message, color))
                # Trim history if it exceeds max size (self.MAX_LOG_HISTORY_SIZE precisa ser definido no __init__)
                if len(self.log_history) > self.MAX_LOG_HISTORY_SIZE:
                    self.log_history.pop(0)

                # Update the visible logs area if it exists and is valid
                # (self.logs_window e self.logs_area precisam ser inicializados no __init__ e gerenciados por open_logs_window/logs_window_destroyed)
                if self.logs_window and self.logs_window.widget() is self.logs_area:
                    self._update_logs_area(log_message, color) # Chama o novo método interno

            except queue.Empty:
                # Should not happen with get_nowait() inside while loop, but good practice
                pass
            except Exception as e:
                # Handle errors during log processing itself
                print(f"❌ Erro crítico durante processamento de logs para GUI: {e}")
                # Avoid recursively putting this error back into the queue if it causes issues

    def monitorar_log_rotativo(self):
        """
        Monitora o arquivo de log principal do serviço em tempo real,
        apenas lendo novas linhas adicionadas. Assume que rotação,
        criação e existência do arquivo são gerenciadas externamente.
        """
        # Initial connection message
        # (Usando a tupla (mensagem, cor) como conversamos)
        log_queue.put(("InLogic Service>> Iniciando...", "blue"))

        # File handle and position tracking
        posicao = 0
        arquivo = None

        # Main loop to continuously read
        while True:
            try:
                # Open the file if it's not currently open.
                # This block is mainly for the initial start of the thread.
                # If the external process creates the file after the GUI starts,
                # this will eventually find and open it.
                if arquivo is None:
                    if os.path.exists(caminho_log):
                        # Open for reading, specify encoding and error handling
                        # 'r' mode is sufficient if file exists and you just read
                        arquivo = open(caminho_log, "r", encoding="utf-8", errors='ignore')
                        # Seek to the end to only read *new* lines added AFTER this point
                        arquivo.seek(0, os.SEEK_END)
                        posicao = arquivo.tell()
                        # (Usando a tupla (mensagem, cor))
                        log_queue.put((f"InLogic Service>> ✅ Conectado.", "blue"))
                    else:
                        # File doesn't exist yet. Assume the external process will create it.
                        # Wait and try again. Avoid putting this message repeatedly.
                        # print(f"InLogic Service>> Arquivo de log '{caminho_log}' não encontrado. Aguardando...") # Keep console print if needed
                        time.sleep(5) # Wait longer if file is not even created yet
                        continue # Go to the next iteration to try opening again

                # Try to read a new line from the file
                # If no new line is available, readline() typically returns an empty string ('').
                linha = arquivo.readline()

                if linha:
                    # If a line was read (not empty string), process it
                    linha = linha.strip()
                    # Put the message with the specified color into the queue
                    # (Usando a tupla (mensagem, cor))
                    log_queue.put((f"InLogic Service>> {linha}", "blue"))
                    # Update the position after reading the line
                    posicao = arquivo.tell()
                else:
                    # No new line was read (reached end of file, or file is empty).
                    # Wait a short period before trying to read again to avoid busy loop.
                    # IMPORTANT: We are NOT checking file size or existence here,
                    # we rely on the external function for that management.
                    time.sleep(0.5) # Wait a bit


            except FileNotFoundError:
                 # If the file disappears *while* the 'arquivo' object is open
                 # (unlikely with 'r' mode, but possible), this catches it.
                 # Log the event and set arquivo to None to trigger re-opening logic
                 # in the next loop iteration.
                 # (Usando a tupla (mensagem, cor))
                 log_queue.put((f"InLogic Service>> Arquivo de log '{caminho_log}' não encontrado inesperadamente durante a leitura. Tentando reabrir.", "orange"))
                 if arquivo:
                     try: arquivo.close() # Close the file handle safely
                     except: pass # Ignore errors during close
                 arquivo = None # Signal to the next loop iteration to try opening the file again
                 time.sleep(2) # Wait a bit before trying to reopen

            except Exception as e:
                # Catch any other unexpected errors during file operations (e.g., permission issues)
                # (Usando a tupla (mensagem, cor))
                log_queue.put((f"InLogic Service>> Erro inesperado ao ler arquivo de log: {e}. Tentando continuar.", "red"))
                # Wait a bit after an error before trying again
                time.sleep(1)

    def logs_window_destroyed(self, obj=None):
        """Slot connected to the destroyed signal of the logs QMdiSubWindow."""
        log_queue.put(("Janela de Logs fechada", "blue")) # Usando tupla
        # Reset the references so a new window is created next time
        self.logs_window = None
        self.logs_area = None

    def open_logs_window(self):
        """Opens or activates the logs window."""
        # Check if a valid logs window already exists
        # self.logs_window e self.logs_area precisam ser inicializados no __init__
        if self.logs_window is not None and self.logs_window.widget() is self.logs_area:
             # Window exists, just activate it
             self.mdi_area.setActiveSubWindow(self.logs_window)
             log_queue.put(("Janela de Logs já aberta. Ativando janela existente.", "blue")) # Usando tupla
        else:
            # Window doesn't exist or was closed/deleted, create a new one
            log_queue.put(("Criando nova Janela de Logs...", "blue")) # Usando tupla

            self.logs_window = QMdiSubWindow()
            self.logs_window.setWindowTitle("Logs do Sistema")
            # This ensures the window is deleted when the user clicks the close button ('X')
            self.logs_window.setAttribute(Qt.WA_DeleteOnClose, True) # CORREÇÃO PRINCIPAL AQUI
            # Connect the destroyed signal to our slot to clean up references
            self.logs_window.destroyed.connect(self.logs_window_destroyed) # CONECTA AO NOVO MÉTODO


            self.logs_area = QTextEdit()
            self.logs_area.setReadOnly(True)
            self.logs_area.setPlaceholderText("Logs do sistema aparecerão aqui...\n")
            self.logs_area.setStyleSheet("QTextEdit { padding: 5px; }") # Add some padding for aesthetics


            # Populate the new QTextEdit with history (usando self.log_history inicializado no __init__)
            self._update_logs_area("--- Histórico de Logs ---", "blue") # Usa o novo método interno para popular
            for msg, color in self.log_history: # Itera sobre a lista de histórico
                self._update_logs_area(msg, color) # Usa o novo método interno
            self._update_logs_area("--- Logs em Tempo Real ---", "blue") # Usa o novo método interno


            self.logs_window.setWidget(self.logs_area)
            self.mdi_area.addSubWindow(self.logs_window)

            self.logs_window.showMaximized() # Ou show(), dependendo do comportamento desejado
    # ----------------------


    # --- Janela de edição de ativos ---
    def open_properties_window(self):
        """
        Abre uma subjanela MDI com editor de código moderno para editar o JSON de configuração.
        Possui números de linha, destaque de sintaxe e Ctrl+S para salvar.
        """
        import pprint  # Garante que pprint está disponível

        # Se já existe editor aberto, ativa ele
        if hasattr(self, '_properties_area_editor') and self._properties_area_editor is not None:
            for sub_window in self.mdi_area.subWindowList():
                if sub_window.widget() is self._properties_area_editor:
                    self.mdi_area.setActiveSubWindow(sub_window)
                    log_queue.put("Editor de Configuração já aberto. Ativando janela existente.")
                    return

        # Cria a subjanela
        properties_window = QMdiSubWindow()
        properties_window.setWindowTitle("Editor de ativos")
        properties_window.setAttribute(Qt.WA_DeleteOnClose, True)
        properties_window.destroyed.connect(self._properties_window_destroyed)

        # Cria o editor moderno com números de linha
        self._properties_area_editor = EditorCodigo()
        self._properties_area_editor.setObjectName("configEditor")
        self._properties_area_editor.setReadOnly(False)
        self._properties_area_editor.setPlaceholderText("Carregando configuração JSON...")
        self._properties_area_editor.setFont(QFont("Consolas", 10))
        self._properties_area_editor.setTabStopDistance(
            4 * QFontMetrics(self._properties_area_editor.font()).horizontalAdvance(' ')
        )

        # Instala o event filter para Ctrl+S
        self._properties_area_editor.installEventFilter(self)

        # --- Tenta carregar, exibir o JSON formatado E CONFIGURAR O DESTACADOR ---
        try:
            config_json_string = json.dumps(self.config, indent=4, ensure_ascii=False)
            self._properties_area_editor.setPlainText(config_json_string)

            # Associa o highlighter de sintaxe JSON (cores funcionam)
            self._properties_highlighter = HighlighterJson(self._properties_area_editor.document())

        except Exception as e:
            log_queue.put((f"❌ Erro ao preparar editor de configuração (carregar JSON/configurar destacador): {e}", "red"))
            error_text = f"❌ Erro ao exibir configuração como JSON para edição: {e}\n\nExibindo formato original (Não Editável):"
            try:
                fallback_pprint_string = pprint.pformat(self.config)
                self._properties_area_editor.setPlainText(error_text + "\n\n" + fallback_pprint_string)
            except Exception as pprint_e:
                self._properties_area_editor.setPlainText(f"{error_text}\n\nErro adicional ao exibir pprint fallback: {pprint_e}")
            self._properties_area_editor.setReadOnly(True)

        # Adiciona o editor ao widget principal da subjanela.
        properties_window.setWidget(self._properties_area_editor)
        self.mdi_area.addSubWindow(properties_window)
        properties_window.showMaximized()
        log_queue.put("Abrindo Editor de Configuração...", "blue")

    def _properties_window_destroyed(self, obj=None):
        """Slot para limpar referências quando a janela de propriedades for fechada."""
        log_queue.put("Editor de Configuração fechado.")
        # Limpa as referências quando a janela é fechada
        self._properties_area_editor = None
        self._properties_highlighter = None # Limpa também a referência do highlighter

    def eventFilter(self, source: QObject, event: QEvent) -> bool:
        """
        Filtra eventos para capturar Ctrl+S no editor de configuração.
        """
        # Verifica se o evento é de tecla (KeyPress)
        if event.type() == QEvent.KeyPress:
            key_event = event # Type hint (opcional)

            # Verifica se a fonte do evento é o nosso editor de propriedades ATIVO
            # E se o editor existe e não é None (para evitar erros após ser fechado)
            if hasattr(self, '_properties_area_editor') and self._properties_area_editor is not None and source is self._properties_area_editor:

                 # Verifica se é Ctrl + S
                 if key_event.key() == Qt.Key_S and key_event.modifiers() == Qt.ControlModifier:
                     log_queue.put("Atalho Ctrl+S detectado no editor de configuração. Tentando salvar...")
                     # Chama o método para salvar
                     self._salvar_configuracao_editor()
                     return True  # Indica que o evento foi tratado e não deve ser processado adiante

        # Para outros eventos ou outros widgets, permite o processamento normal
        return super().eventFilter(source, event)

    def _salvar_configuracao_editor(self):
        """
        Obtém o texto do editor de configuração, tenta parsear como JSON,
        atualiza self.config e salva no arquivo (criptografado).
        """
        # Verifica status de login primeiro
        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para salvar configurações.")
            log_queue.put(("Falha ao salvar configuração no editor: Não logado.", "orange"))
            return

        # Verifica se a referência do editor é válida
        if not hasattr(self, '_properties_area_editor') or self._properties_area_editor is None:
            log_queue.put(("Erro: Editor de configuração não está ativo ou referência perdida durante a tentativa de salvar.", "red"))
            # QMessageBox.critical(self, "Erro ao Salvar", "Editor de configuração não está ativo ou referência perdida.") # Mensagem já logada
            return

        # Obtém o texto atual do editor
        editor_text = self._properties_area_editor.toPlainText()

        try:
            # Tenta parsear o texto como JSON
            # Isso validará se o conteúdo editado é JSON sintaticamente correto
            nova_config = json.loads(editor_text)

            # Validação básica da estrutura esperada (opcional, mas recomendado)
            # Verifica se é um dicionário e se tem a chave 'grupos' como lista
            if not isinstance(nova_config, dict) or "grupos" not in nova_config or not isinstance(nova_config["grupos"], list):
                QMessageBox.warning(self, "Erro de Estrutura", "O conteúdo editado não parece ter a estrutura correta esperada (deve ser um dicionário com a chave 'grupos' sendo uma lista).")
                log_queue.put(("Erro ao salvar: Estrutura JSON inválida ou inesperada após edição.", "orange"))
                return # Não salva se a estrutura for inválida

            # Tudo parece bem, atualiza a configuração em memória
            self.config = nova_config
            log_queue.put("Configuração em memória atualizada a partir do editor.")

            # Salva a configuração no arquivo (criptografado)
            # A função salvar_configuracao já trata a criptografia e logging.
            salvar_configuracao(self.config)

            # Notifica sucesso
            if hasattr(self, 'tray_icon') and self.tray_icon:
                 # Usa a bandeja do sistema para mensagem discreta de sucesso
                 self.tray_icon.showMessage("InLogic Studio", "Configuração salva!", QSystemTrayIcon.Information, 2000)
            else:
                 # Ou um QMessageBox se a bandeja não estiver disponível ou preferir
                 QMessageBox.information(self, "Sucesso ao Salvar", "Configuração salva com sucesso!")

            # Opcional: Recarregar a árvore de ativos para refletir as mudanças salvas
            self.config = carregar_configuracao()
            self.carregar_ativos()


        except json.JSONDecodeError as e:
            # Captura erros específicos de JSON (texto não é JSON válido)
            QMessageBox.critical(self, "Erro de Sintaxe", f"Erro ao parsear codigo:\n{e}\n\nPor favor, corrija a sintaxe no editor.")
            log_queue.put((f"Erro ao salvar: Erro de sintaxe no editor: {e}", "red"))

        except Exception as e:
            # Captura quaisquer outros erros inesperados durante o salvamento
            QMessageBox.critical(self, "Erro Inesperado ao Salvar", f"Ocorreu um erro inesperado ao salvar:\n{e}")
            log_queue.put((f"Erro inesperado ao salvar configuração do editor: {e}", "red"))
    # -----------------------------------




 
# --- Métodos de Autenticação (Adaptados para a nova lógica de login) ---
    def show_login_dialog(self):
        """Exibe o diálogo de login."""
        if self.login_status:
            QMessageBox.information(self, "Informação", "Você já está logado.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Login")
        layout = QFormLayout()

        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Senha:", password_input)

        button_box = QHBoxLayout()
        login_button = QPushButton("Login")
        cancel_button = QPushButton("Cancelar")
        button_box.addWidget(login_button)
        button_box.addWidget(cancel_button)
        layout.addRow(button_box)

        login_button.clicked.connect(lambda: self.attempt_login(password_input.text(), dialog))
        cancel_button.clicked.connect(dialog.reject)

        dialog.setLayout(layout)
        dialog.exec_()

    def attempt_login(self, entered_password, dialog):
        """Tenta logar com a senha fornecida."""
        global senha_autenticacao_ativa

        # Garante que a senha digitada e a senha requerida são strings e remove espaços
        entered_password = entered_password.strip()
        senha_requerida = str(senha_autenticacao_ativa).strip()


        if entered_password == senha_requerida:
            self.login_status = True
            self.update_login_ui()
            QMessageBox.information(self, "Sucesso", "Login bem-sucedido!")
            dialog.accept()
        else:
            QMessageBox.warning(self, "Erro de Login", "Senha incorreta.")

    def logout(self):
        """Realiza o logout do sistema."""
        if self.login_status:
            self.login_status = False
            self.update_login_ui()
            QMessageBox.information(self, "Sucesso", "Logout realizado.")
            
        else:
            QMessageBox.information(self, "Informação", "Você não está logado.")

    def show_change_password_dialog(self):
        """Exibe o diálogo para alterar a senha."""
        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para alterar a senha.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Alterar Senha")
        layout = QFormLayout()

        new_password_input = QLineEdit()
        new_password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Nova Senha:", new_password_input)

        confirm_password_input = QLineEdit()
        confirm_password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Confirmar Nova Senha:", confirm_password_input)

        button_box = QHBoxLayout()
        change_button = QPushButton("Alterar")
        cancel_button = QPushButton("Cancelar")
        button_box.addWidget(change_button)
        button_box.addWidget(cancel_button)
        layout.addRow(button_box)

        change_button.clicked.connect(lambda: self.change_password(
            new_password_input.text(),
            confirm_password_input.text(),
            dialog
        ))
        cancel_button.clicked.connect(dialog.reject)

        dialog.setLayout(layout)
        dialog.exec_()

    def change_password(self, new_password, confirm_password, dialog):
        """Altera a senha se as condições forem atendidas."""
        global senha_autenticacao_ativa

        new_password = new_password.strip()
        confirm_password = confirm_password.strip()

        log_queue.put("Tentando alterar senha.")

        if not new_password:
            QMessageBox.warning(self, "Erro", "A nova senha não pode ser vazia.")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Erro", "A nova senha e a confirmação não correspondem.")
            log_queue.put("Falha ao alterar senha: Nova senha e confirmação não correspondem.")
            return

        # Salvar a nova senha no arquivo
        success = salvar_senha_autenticacao(new_password)
        if success:
            QMessageBox.information(self, "Sucesso", "Senha alterada com sucesso.")
            dialog.accept()
        else:
            QMessageBox.warning(self, "Erro", "Não foi possível salvar a nova senha.")

    def reset_password_to_default(self):
        """Reseta a senha para o valor da variável senha_correta_padrao."""
        global senha_autenticacao_ativa

        confirmacao = QMessageBox.question(
            self,
            "Confirmar Reset",
            "Deseja realmente resetar a senha para o valor padrão?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirmacao == QMessageBox.Yes:
            # Remover a senha do arquivo
            success = resetar_senha_autenticacao()

            if success:
                QMessageBox.information(self, "Sucesso", "Senha resetada para o valor padrão.")
                self.update_login_ui()
            else:
                QMessageBox.warning(self, "Erro", "Não foi possível resetar a senha.")

    def update_login_ui(self):
        """Atualiza elementos da UI com base no status de login."""
        if self.login_status:
            self.login_status_label.setText("Conectado")
            self.login_status_label.setStyleSheet(f"color: #2ecc71; margin-left: 12px;")
            self.action_login.setEnabled(False)
            self.action_logout.setEnabled(True)
            self.action_change_password.setEnabled(True)
            self.action_reset_password.setEnabled(True)
            log_queue.put(("Login usuario: Conectado.", "green"))

        else:
            self.login_status_label.setText("Desconectado")
            self.login_status_label.setStyleSheet(f"color: #FF0000; margin-left: 12px;")
            self.action_login.setEnabled(True)
            self.action_logout.setEnabled(False)
            self.action_change_password.setEnabled(False)
            self.action_reset_password.setEnabled(False)
            log_queue.put(("Login usuario: Desconectado.", "Red"))
# ----------------------------------------------------------------------


# --- Metodos de edição dos ativos da arvore de ativos do sistema ---
    def exibir_menu_contexto(self, position):
        """Exibe o menu de contexto para os itens da árvore de ativos."""
        item = self.tree_ativos.itemAt(position)
        # O menu de contexto só aparece se houver um item E o usuário estiver logado
        # NOTA: Se quiser que o menu de contexto apareça SEMPRE mas as ações de edição/adicionar/excluir
        # estejam desabilitadas/ocultas quando não logado, remova 'and self.login_status' daqui
        # e adicione action.setEnabled(self.login_status) ou action.setVisible(self.login_status)
        # para cada ação individual dentro da lógica abaixo.
        if item and self.login_status:
            menu = QMenu()
            key_data = item.data(0, Qt.UserRole)

            if key_data is not None and len(key_data) >= 2:
                key, grupo = key_data[:2]

                actions_to_add = []

                # Ação Editar
                editable_keys = ["ip", "intervalo_temporizador", "grupo", "server", "diretorio", "database", "tabela", "username", "password", "gatilho", "memorias_gravacao"]
                parent_keys = ["memorias_gravacao", "login", "ACESSO_MQTT", "notificacao_parent", "storage_parent", "calculos_parent"]

                if (key in editable_keys and key not in parent_keys) or key.startswith("mqtt_") or key.startswith("notificacao_") or key == "calculo" or (key == "mem_list" and len(key_data) == 3):
                     if key != "login":
                         edit_action = QAction("Editar", self)
                         edit_action.triggered.connect(lambda checked=False, i=item: self.editar_item(i))
                         actions_to_add.append(edit_action)


                # Ação Adicionar Novo (filho)
                if key == "memorias_gravacao":
                    add_mem_action = QAction("Adicionar Nova Memória", self)
                    add_mem_action.triggered.connect(lambda checked=False, i=item: self.adicionar_item(i))
                    actions_to_add.append(add_mem_action)

                elif key == "calculos_parent" and len(key_data) == 2:
                    add_calc_action = QAction("Adicionar Novo Cálculo", self)
                    add_calc_action.triggered.connect(lambda checked=False, i=item: self.adicionar_calculo(i))
                    actions_to_add.append(add_calc_action)
                elif key == "grupo" and len(key_data) == 2:
                     add_calc_action_from_group = QAction("Adicionar Novo Cálculo (neste grupo)", self)
                     add_calc_action_from_group.triggered.connect(lambda checked=False, i=item: self.adicionar_calculo(i))
                     actions_to_add.append(add_calc_action_from_group)

                     # Adicionar ação para DUPLICAR GRUPO
                     duplicate_group_action = QAction("Duplicar Grupo", self)
                     duplicate_group_action.triggered.connect(lambda checked=False, i=item, g=grupo: self.duplicar_grupo(i, g))
                     actions_to_add.append(duplicate_group_action)

                # Adicionar Local de Gravação (clicando no pai "EVENTOS")
                elif key == "storage_parent" and len(key_data) == 2:
                    add_storage_menu = menu.addMenu("Adicionar Local de Gravação")
                    opcoes_gravacao = ["mqtt", "sql", "excel", "notificacao"]
                    locais_disponiveis = [
                         opcao for opcao in opcoes_gravacao
                         if not grupo.get("local_gravacao", {}).get(opcao, False)
                     ]

                    if not locais_disponiveis:
                        info_action = QAction("Todos os locais já habilitados.", self)
                        info_action.setEnabled(False)
                        add_storage_menu.addAction(info_action)
                    else:
                        for opcao in locais_disponiveis:
                            action = QAction(opcao.upper(), self)
                            action.triggered.connect(lambda checked=False, g=grupo, o=opcao: self.adicionar_local_gravacao(g, o))
                            add_storage_menu.addAction(action)
                    if add_storage_menu.actions():
                         actions_to_add.append(add_storage_menu)

                elif key == "grupo" and len(key_data) == 2:
                     add_group_action = QAction("Duplicar Grupo", self)
                     add_group_action.triggered.connect(lambda checked=False, i=item: self.adicionar_item(i))
                     actions_to_add.append(add_group_action)


                # Ação Excluir
                if key == "grupo":
                    delete_group_action = QAction("Excluir Grupo", self)
                    delete_group_action.triggered.connect(lambda checked=False, i=item: self.excluir_item(i))
                    actions_to_add.append(delete_group_action)

                elif key == "mem_list" and len(key_data) == 3:
                    delete_mem_action = QAction("Excluir Memória", self)
                    delete_mem_action.triggered.connect(lambda checked=False, i=item: self.excluir_item(i))
                    actions_to_add.append(delete_mem_action)

                elif key == "calculo" and len(key_data) == 3:
                    delete_calc_action = QAction("Excluir Cálculo", self)
                    delete_calc_action.triggered.connect(lambda checked=False, i=item: self.excluir_item(i))
                    actions_to_add.append(delete_calc_action)

                elif key == "storage_method" and len(key_data) == 3:
                    metodo = key_data[2]
                    disable_storage_action = QAction(f"Desabilitar {metodo.upper()}", self)
                    disable_storage_action.triggered.connect(lambda checked=False, g=grupo, m=metodo: self.excluir_local_gravacao(g, m))
                    actions_to_add.append(disable_storage_action)


                for action in actions_to_add:
                     if not isinstance(action, QMenu):
                         menu.addAction(action)

                if menu.actions() or (hasattr(menu, 'menus') and menu.menus()):
                    menu.exec_(self.tree_ativos.viewport().mapToGlobal(position))

    # --- Método para Duplicar um Grupo Completo ---#     
    def duplicar_grupo(self, item_arvore: QTreeWidgetItem, grupo_original_dict: dict):
        """
        Duplica um dicionário de grupo de ativo completo, obtém um novo nome via diálogo,
        adiciona à configuração global, salva o arquivo de configuração (criptografado),
        e recarrega a árvore de ativos na GUI para refletir a mudança.

        Args:
            item_arvore: O item QTreeWidgetItem que foi clicado para acionar esta ação.
                         (Passado para contexto, pode não ser usado na lógica interna de duplicação)
            grupo_original_dict: O dicionário representando o grupo de ativo original
                                 a ser duplicado.
        """
 

        # 1. Verificar status de login
        if not self.login_status:
            # Usa QMessageBox aqui, pois esta ação é manual via UI
            QMessageBox.warning(self, "Acesso Negado", "Faça login para duplicar ativos.")
            # Registra a tentativa falha no log
            return # Sai da função

        # Obtém o nome do grupo original para mensagens de log/confirmação
        grupo_nome_original = grupo_original_dict.get('grupo', 'Nome Desconhecido')


        # 2. Confirmar a duplicação com o usuário
        # Use self para referenciar a janela principal como pai do QMessageBox,
        # garantindo que ele aparece corretamente.
        confirmacao = QMessageBox.question(
            self, # Pai do QMessageBox
            "Duplicar Ativo (Grupo)",
            f"Deseja duplicar o ativo completo '{grupo_nome_original}'?\n"
            "Será criada uma cópia com um novo nome. Esta ação não pode ser desfeita.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No # Define o botão 'No' como padrão para evitar cliques acidentais
        )

        # Se o usuário clicou em 'Não', cancela a operação
        if confirmacao == QMessageBox.No:
            return

        # 3. Criar uma cópia profunda do dicionário do grupo original
        try:
            novo_grupo_dict = copy.deepcopy(grupo_original_dict)
        except Exception as e:
            # Captura e loga qualquer erro que ocorra durante a cópia profunda
            # Exibe uma mensagem de erro clara para o usuário
            QMessageBox.critical(self, "Erro na Duplicação", f"Não foi possível criar uma cópia do grupo para duplicação.\nDetalhe do erro: {e}")
            return # Sai da função se a cópia falhar


        # 4. Obter um nome para o novo grupo duplicado via diálogo
        novo_nome_sugerido = f"{grupo_nome_original}_COPIA"

        # Usa self como pai do diálogo de input
        novo_nome, ok_name_dialog = QInputDialog.getText(
            self, # Pai do QInputDialog
            "Nome do Novo Ativo (Grupo)",
            "Digite o nome para o novo ativo/grupo duplicado:",
            QLineEdit.Normal,
            novo_nome_sugerido # Valor inicial sugerido no campo de texto
        )

        # 5. Validar o nome obtido do diálogo
        # Verifica se o usuário clicou OK no diálogo (ok_name_dialog)
        # E se o texto digitado não é vazio após remover espaços em branco (novo_nome.strip())
        if not ok_name_dialog or not novo_nome.strip():
            # Não exibe uma QMessageBox para o usuário, pois ele optou por não fornecer um nome ou cancelar.
            return # Sai da função se o nome for vazio ou diálogo cancelado

        novo_nome = novo_nome.strip() # Remove espaços em branco no início/fim

        # 6. Verificar se já existe um grupo com o mesmo nome na configuração principal (em memória)
        try:
            # Garante que self.config é um dicionário e tem a chave 'grupos' como lista
            if not isinstance(self.config, dict):
                QMessageBox.critical(self, "Erro Interno", "Estrutura de configuração inválida.")
                return # Sai se a estrutura da config estiver fundamentalmente errada

            if not isinstance(self.config.get("grupos"), list):
                # Se 'grupos' não existe ou não é uma lista, loga um aviso
                self.config["grupos"] = [] # Cria ou sobrescreve com uma lista vazia

            # Verifica duplicidade apenas se a lista 'grupos' existir e for uma lista
            if isinstance(self.config["grupos"], list):
                 # Cria uma lista de nomes de grupos existentes (ignorando entradas não-dicionários ou sem nome)
                 existing_names = [g.get("grupo") for g in self.config["grupos"] if isinstance(g, dict) and g.get("grupo") is not None]
                 # Compara o novo nome (já limpo de espaços) com os nomes existentes
                 if novo_nome in existing_names:
                    # Exibe uma mensagem de aviso clara para o usuário
                    QMessageBox.warning(self, "Nome Duplicado", f"Já existe um ativo/grupo com o nome '{novo_nome}'. Por favor, escolha outro nome.")
                    return # Sai da função se o nome já existir

        except Exception as e:
             # Captura outros erros inesperados durante a validação de nome (menos comum)
             QMessageBox.critical(self, "Erro Interno", f"Ocorreu um erro interno ao validar o nome do novo grupo:\n{e}")
             return # É mais seguro parar em caso de erro inesperado na validação


        # 7. Atribuir o novo nome ao dicionário do grupo duplicado (na cópia)
        # Verifica se a cópia profunda resultou em um dicionário
        if isinstance(novo_grupo_dict, dict):
            novo_grupo_dict["grupo"] = novo_nome
        else:
             # Este caso indica que a cópia profunda não retornou um dicionário, o que é inesperado se a cópia original era um dict.
            QMessageBox.critical(self, "Erro Interno", "Falha interna ao processar a duplicação do grupo após copiar.")
            return # Sai da função


        # 8. Adicionar o novo dicionário de grupo (renomeado) à lista de grupos na configuração principal (em memória)
        # Garante novamente que self.config e self.config['grupos'] têm a estrutura esperada antes de adicionar
        if not isinstance(self.config, dict) or not isinstance(self.config.get("grupos"), list):
            # Isto não deveria acontecer se as validações anteriores passaram, mas como fallback robusto...
            QMessageBox.critical(self, "Erro Interno", "Estrutura de configuração interna inválida ao tentar adicionar novo grupo.")
            return # Sai em caso de erro de estrutura persistente

        try:
            # Adiciona o dicionário do novo grupo à lista 'grupos'
            self.config["grupos"].append(novo_grupo_dict)
        except Exception as e:
            # Captura outros erros inesperados durante a adição à lista (menos comum, ex: lista corrompida)
            QMessageBox.critical(self, "Erro Interno", f"Não foi possível adicionar o novo grupo à configuração interna:\n{e}")
            # É seguro sair, pois a configuração em memória está potencialmente inconsistente.
            return

        # 9. Salvar a configuração atualizada do arquivo (criptografado)
        # Chama sua função existente salvar_configuracao(self.config).
        # Presume-se que esta função lida com a criptografia e escreve no arquivo CONFIG_PATH1.
        # Sua função salvar_configuracao deve incluir seus próprios try/excepts e logging para falhas de escrita.
        try:

            salvar_configuracao(self.config)


        except Exception as e:
            # Este 'except' pega exceções levantadas POR self.salvar_configuracao (se ela não tratar a exceção)
            # Log da falha no salvamento já pode estar na queue se salvar_configuracao loga antes de levantar exceção.
            # Adicionar log aqui de qualquer forma como redundância/diagnóstico.
            QMessageBox.critical(self, "Erro ao Salvar", f"Falha ao salvar a configuração:\n{e}\nA árvore pode não estar sincronizada.")


        self.config = carregar_configuracao()
        self.carregar_ativos()



    def editar_item(self, item):
        """Edita propriedades de um item na árvore de ativos."""
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para editar itens.")
             return

        key_data = item.data(0, Qt.UserRole)
        if key_data is None or len(key_data) < 2:
             print(f"Erro: Dados insuficientes no item para edição: {key_data}")
             log_queue.put(f"Erro: Dados insuficientes no item para edição: {key_data}")
             return

        key, grupo = key_data[:2]

        # === Edição de IP ===
        if key == "ip":
            dialog = QDialog(self)
            dialog.setWindowTitle("Editar Ativo")
            layout = QVBoxLayout()

            ip_label = QLabel("Address:")
            ip_input = QLineEdit(grupo.get("plc_ip", ""))
            layout.addWidget(ip_label)
            layout.addWidget(ip_input)

            tipo_clp_label = QLabel("Tipo de Ativo:")
            tipo_clp_combo = QComboBox()
            tipos_validos = ["Delta", "Controllogix", "Mqtt"]
            tipo_clp_combo.addItems(tipos_validos)
            current_tipo = grupo.get("tipo_clp", "delta")
            try:
                 tipo_clp_combo.setCurrentText(current_tipo.title())
                 if tipo_clp_combo.currentText().lower() != current_tipo.lower():
                      index = [t.lower() for t in tipos_validos].index(current_tipo.lower())
                      tipo_clp_combo.setCurrentIndex(index)
            except ValueError:
                tipo_clp_combo.setCurrentIndex(0)
                log_queue.put(f"Aviso: Tipo de CLP '{current_tipo}' não encontrado nas opções padrão ao editar IP. Usando o primeiro item.")


            layout.addWidget(tipo_clp_label)
            layout.addWidget(tipo_clp_combo)

            button_box = QHBoxLayout()
            save_button = QPushButton("Salvar")
            cancel_button = QPushButton("Cancelar")
            button_box.addWidget(save_button)
            button_box.addWidget(cancel_button)
            layout.addLayout(button_box)

            def salvar():
                novo_ip = ip_input.text().strip()
                novo_tipo_clp = tipo_clp_combo.currentText().lower()

                if not novo_ip:
                    QMessageBox.warning(self, "Erro", "O campo Address não pode estar vazio.")
                    return

                grupo["plc_ip"] = novo_ip
                grupo["tipo_clp"] = novo_tipo_clp

                salvar_configuracao(self.config)
                if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Atualização concluída!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos()
                if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                dialog.accept()

            save_button.clicked.connect(salvar)
            cancel_button.clicked.connect(dialog.reject)

            dialog.setLayout(layout)
            dialog.exec_()

        # === Edição de Intervalo Temporizador ===
        elif key == "intervalo_temporizador":
            try:
                locale_original = locale.getlocale(locale.LC_NUMERIC)
                locale.setlocale(locale.LC_NUMERIC, 'C')
            except locale.Error:
                print("Aviso: Não foi possível definir o locale 'C'. Formato decimal pode variar.")
                log_queue.put("Aviso: Não foi possível definir o locale 'C'. Formato decimal pode variar.")
                locale_original = None

            initial_value = float(grupo.get("intervalo_temporizador", 0)) if isinstance(grupo.get("intervalo_temporizador"), (int, float)) else 0.0

            novo_valor, ok = QInputDialog.getDouble(
                self,
                "Editar",
                f"Novo valor para Intervalo Temporizador (em segundos):",
                value=initial_value,
                min=0.0,
                decimals=3
            )

            if locale_original:
                 try:
                    locale.setlocale(locale.LC_NUMERIC, locale_original)
                 except locale.Error:
                    print("Aviso: Não foi possível restaurar o locale original.")
                    log_queue.put("Aviso: Não foi possível restaurar o locale original.")


            if ok and novo_valor >= 0:
                grupo["intervalo_temporizador"] = float(novo_valor)

                salvar_configuracao(self.config)
                if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Atualização concluída!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos()
                if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()


        # === Edição de Cálculo Individual ===
        elif key == "calculo":
            if len(key_data) == 3 and key_data[2] in grupo.get("calculos", {}):
                calculo_nome = key_data[2]
                calculo_dados_orig = grupo["calculos"][calculo_nome]

                if isinstance(calculo_dados_orig, list) and len(calculo_dados_orig) > 2:
                    formula_atual = calculo_dados_orig[2]
                    memoria_atual = calculo_dados_orig[0] if len(calculo_dados_orig) > 0 else ""
                elif isinstance(calculo_dados_orig, dict):
                    formula_atual = calculo_dados_orig.get("formula", "")
                    memoria_atual = calculo_dados_orig.get("memoria", "")
                else:
                    formula_atual = ""
                    memoria_atual = ""
                    print(f"Aviso: Estrutura de cálculo inesperada para '{calculo_nome}': {calculo_dados_orig}")
                    log_queue.put(f"Aviso: Estrutura de cálculo inesperada para '{calculo_nome}': {calculo_dados_orig}")


                if 'JanelaCalculos' in globals():
                    dialog = JanelaCalculos(
                        grupo.get("mem_list", []),
                        ["+", "-", "*", "/"],
                        self,
                        nome=calculo_nome,
                        formula=formula_atual,
                        memoria_selecionada=memoria_atual
                    )

                    if dialog.exec_() == QDialog.Accepted:
                        dados = dialog.get_dados()
                        novo_nome = dados.get("nome", "").strip()
                        nova_formula = dados.get("formula", "").strip()
                        nova_memoria = dados.get("memoria", "").strip()

                        if novo_nome and nova_formula and nova_memoria:
                            if novo_nome != calculo_nome:
                                grupo["calculos"][novo_nome] = {"formula": nova_formula, "memoria": nova_memoria}
                                del grupo["calculos"][calculo_nome]
                            else:
                                grupo["calculos"][novo_nome] = {"formula": nova_formula, "memoria": nova_memoria}


                            salvar_configuracao(self.config)
                            if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Cálculo atualizado!", QSystemTrayIcon.Information, 2000)
                            self.carregar_ativos()
                            if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                        else:
                            QMessageBox.warning(self, "Erro", "Nome, fórmula e memória do cálculo não podem ser vazios.")
                else:
                    QMessageBox.critical(self, "Erro", "A classe JanelaCalculos não está definida ou importada.")
                    print("Erro: JanelaCalculos não definida para editar cálculo.")


        # === Edição de campos simples sob MQTT ===
        elif key.startswith("mqtt_"):
            mqtt_config = grupo.get("ACESSO_MQTT", {})
            field_map = {
                "mqtt_broker_address": "broker_address",
                "mqtt_port": "port",
                "mqtt_client_id": "client_id",
                "mqtt_username": "username",
                "mqtt_password": "password",
                "mqtt_keep_alive": "keep_alive",
                "mqtt_qos": "qos"
            }
            field = field_map.get(key)
            if not field: return

            current_value = mqtt_config.get(field, "")
            display_text = "*******" if field == "password" and current_value else str(current_value)
            input_mode = QLineEdit.Password if field == "password" else QLineEdit.Normal

            new_value, ok = QInputDialog.getText(
                self,
                "Editar",
                f"Novo valor para {field.replace('_', ' ').title()}:",
                input_mode,
                str(current_value)
            )

            if ok:
                mqtt_config[field] = new_value
                salvar_configuracao(self.config)
                if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Atualização concluída!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos()
                if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()


        # === Edição de campos simples sob Notificação ===
        elif key.startswith("notificacao_"):
            notif_config = grupo.get("notificacao", {})
            campo = key.split("_", 1)[1]
            current_value = notif_config.get(campo, "")

            new_value, ok = QInputDialog.getText(
                self,
                "Editar",
                f"Novo valor para {campo.title()}:",
                QLineEdit.Normal,
                str(current_value)
            )
            if ok:
                notif_config[campo] = new_value
                salvar_configuracao(self.config)
                if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Atualização concluída!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos()
                if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()


        # === Edição de outros campos simples (grupo, server, diretorio, database, tabela, username, password, gatilho, memorias_gravacao) ===
        elif key in ["grupo", "server", "diretorio", "database", "tabela", "username", "password", "gatilho", "memorias_gravacao"]:
             current_value = grupo.get(key) if key in ["grupo", "diretorio", "tabela_sql", "gatilho", "memorias_gravacao"] else grupo.get("db_config", {}).get(key)

             input_mode = QLineEdit.Password if key == "password" else QLineEdit.Normal
             display_text = "*******" if key == "password" and current_value else str(current_value if current_value is not None else '')

             novo_valor, ok = QInputDialog.getText(
                 self,
                 "Editar",
                 f"Novo valor para {key.replace('_',' ').title()}:",
                 input_mode,
                 str(current_value if current_value is not None else '')
             )

             if ok:
                 if key in ["grupo", "diretorio", "tabela_sql"]:
                      grupo[key] = novo_valor
                 elif key in ["gatilho", "memorias_gravacao"]:
                      if isinstance(novo_valor, str) and novo_valor.isdigit():
                           grupo[key] = int(novo_valor)
                      else:
                           grupo[key] = novo_valor
                 elif key in ["server", "database", "username", "password"]:
                     if "db_config" not in grupo: grupo["db_config"] = {}
                     grupo["db_config"][key] = novo_valor

                 salvar_configuracao(self.config)
                 if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Atualização concluída!", QSystemTrayIcon.Information, 2000)
                 self.carregar_ativos()
                 if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()

        # === Edição de memória individual na lista mem_list ===
        elif key == "mem_list" and len(key_data) == 3:
            old_mem_value = key_data[2]
            try:
                old_mem_value_str = str(old_mem_value)
            except Exception:
                 old_mem_value_str = str(old_mem_value)


            novo_valor_str, ok = QInputDialog.getText(
                self,
                "Editar Memória",
                f"Novo valor para a memória '{old_mem_value_str}':",
                QLineEdit.Normal,
                old_mem_value_str
            )
            if ok:
                try:
                    if isinstance(old_mem_value, int):
                         try:
                             new_mem_value = int(novo_valor_str)
                         except ValueError:
                             new_mem_value = novo_valor_str
                    else:
                         new_mem_value = novo_valor_str

                    if "mem_list" in grupo and isinstance(grupo["mem_list"], list):
                         index = grupo["mem_list"].index(old_mem_value)
                         grupo["mem_list"][index] = new_mem_value

                         salvar_configuracao(self.config)
                         if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Memória atualizada!", QSystemTrayIcon.Information, 2000)
                         self.carregar_ativos()
                         if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                    else:
                        raise ValueError("Lista de memórias não encontrada ou inválida no grupo.")

                except ValueError as ve:
                    QMessageBox.warning(self, "Erro", f"Valor antigo da memória '{old_mem_value_str}' não encontrado na lista ou erro de formato: {ve}")
                    print(f"Erro ValueError ao atualizar memória: {ve}")
                except Exception as e:
                    QMessageBox.warning(self, "Erro", f"Erro inesperado ao atualizar memória: {e}")
                    print(f"Erro inesperado ao atualizar memória: {e}")


        else:
             print(f"Ação 'Editar' não implementada para o item com chave: {key}")

    def adicionar_item(self, item):
        """Adiciona um novo item (Memória ou Grupo duplicado) conforme a lógica da versão antiga."""
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para adicionar itens.")
             return

        key_data = item.data(0, Qt.UserRole)
        if key_data is None or len(key_data) < 2:
            print(f"Erro: Dados insuficientes no item para adição: {key_data}")
            log_queue.put(f"Erro: Dados insuficientes no item para adição: {key_data}")
            return

        key, grupo = key_data[:2]

        # Adicionar Nova Memória (clicando no item "MEMORIA DE GRAVAÇÃO")
        if key == "memorias_gravacao":
            novo_valor_str, ok = QInputDialog.getText(self, "Adicionar Memória", "Valor da nova memória (Número ou String):")
            if ok and novo_valor_str:
                try:
                    if novo_valor_str.isdigit():
                        novo_valor = int(novo_valor_str)
                    else:
                        novo_valor = novo_valor_str

                    if "mem_list" not in grupo or not isinstance(grupo["mem_list"], list):
                         grupo["mem_list"] = []
                         log_queue.put(f"Aviso: 'mem_list' não era uma lista no grupo '{grupo.get('grupo', 'Desconhecido')}'. Criada uma nova lista.")

                    grupo["mem_list"].append(novo_valor)
                    salvar_configuracao(self.config)
                    if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Memória adicionada!", QSystemTrayIcon.Information, 2000)
                    self.carregar_ativos()
                    # Reiniciar CLPs?
                    # if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                except Exception as e:
                    QMessageBox.warning(self, "Erro", f"Erro ao adicionar memória: {e}")
                    print(f"Erro ao adicionar memória: {e}")


        # Adicionar Novo Grupo (Duplicando o grupo clicado)
        elif key == "grupo":
             confirmacao = QMessageBox.question(
                 self,
                 "Duplicar Grupo",
                 f"Deseja duplicar o grupo '{grupo.get('grupo', 'Nome Desconhecido')}'?",
                 QMessageBox.Yes | QMessageBox.No
             )
             if confirmacao == QMessageBox.Yes:
                 import copy
                 novo_grupo = copy.deepcopy(grupo)
                 novo_nome_sugerido = f"{grupo.get('grupo', 'Grupo')}_COPIA"
                 novo_nome, ok = QInputDialog.getText(self, "Nome do Novo Grupo", "Digite o nome para o novo grupo:", QLineEdit.Normal, novo_nome_sugerido)

                 if ok and novo_nome:
                     if isinstance(self.config.get("grupos"), list):
                         existing_names = [g.get("grupo") for g in self.config["grupos"] if isinstance(g, dict)]
                         if novo_nome in existing_names:
                              QMessageBox.warning(self, "Erro", f"Já existe um grupo com o nome '{novo_nome}'.")
                              return

                     novo_grupo["grupo"] = novo_nome

                     if not isinstance(self.config.get("grupos"), list):
                          self.config["grupos"] = []

                     self.config["grupos"].append(novo_grupo)
                     salvar_configuracao(self.config)
                     if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", f"Grupo '{novo_nome}' duplicado adicionado!", QSystemTrayIcon.Information, 2000)
                     self.carregar_ativos()


        else:
             print(f"Ação 'Adicionar Novo' não implementada para o item com chave: {key}")

    def adicionar_local_gravacao(self, grupo, metodo):
        """Habilita um local de gravação (seta a flag para True) no grupo e cria bloco de config padrão se necessário."""
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para adicionar locais de gravação.")
             return

        if "local_gravacao" not in grupo or not isinstance(grupo["local_gravacao"], dict):
            grupo["local_gravacao"] = {}
            log_queue.put(f"Aviso: 'local_gravacao' não era um dicionário no grupo '{grupo.get('grupo', 'Desconhecido')}'. Criado um novo dicionário.")

        if grupo["local_gravacao"].get(metodo, False):
             QMessageBox.information(self, "Informação", f"O método '{metodo.upper()}' já está habilitado para este grupo.")
             return

        grupo["local_gravacao"][metodo] = True

        if metodo == "notificacao" and "notificacao" not in grupo:
            grupo["notificacao"] = {
                "topico": hasattr(self, 'numero_serie') and self.numero_serie or "SN_DESCONHECIDO_PADRAO",
                "titulo": "Título padrão",
                "mensagem": "Mensagem padrão"
            }
            log_queue.put(f"Criado bloco de config padrão para notificação no grupo '{grupo.get('grupo', 'Desconhecido')}'.")
        elif metodo == "mqtt" and "ACESSO_MQTT" not in grupo:
             grupo["ACESSO_MQTT"] = {
                "broker_address": "mqtt.exemplo.com",
                "port": 1883,
                "client_id": f"cliente_{hasattr(self, 'numero_serie') and self.numero_serie or 'PADRAO'}",
                "username": "",
                "password": "",
                "keep_alive": 60,
                "qos": 1
            }
             log_queue.put(f"Criado bloco de config padrão para MQTT no grupo '{grupo.get('grupo', 'Desconhecido')}'.")

        salvar_configuracao(self.config)
        if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", f"Método '{metodo.upper()}' habilitado!", QSystemTrayIcon.Information, 2000)
        self.carregar_ativos()
        if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()

    def excluir_local_gravacao(self, grupo, local):
        """Desabilita um método de gravação (seta a flag para False) no grupo."""
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para desabilitar locais de gravação.")
             return

        if "local_gravacao" in grupo and isinstance(grupo["local_gravacao"], dict) and local in grupo["local_gravacao"]:
            confirmacao = QMessageBox.question(
                self,
                "Desabilitar Local de Gravação",
                f"Deseja realmente desabilitar o método '{local.upper()}' para este grupo?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirmacao == QMessageBox.Yes:
                grupo["local_gravacao"][local] = False

                salvar_configuracao(self.config)
                if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", f"Método '{local.upper()}' desabilitado!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos()
                if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
        else:
            QMessageBox.warning(self, "Aviso", f"O local '{local.upper()}' já estava desabilitado ou não existe neste grupo.")

    def adicionar_calculo(self, item_arvore):
        """
        Abre um diálogo (JanelaCalculos) para criar um novo cálculo
        e o adiciona ao grupo selecionado na árvore de ativos.
        """
        # 1. Verifica o status de login
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para adicionar cálculos.")
             # Registra a tentativa falha no log
             log_queue.put(("Tentativa de adicionar cálculo falhou: Não logado.", "orange"))
             return # Sai da função

        # 2. Obtém os dados do item da árvore clicado
        dados_item = item_arvore.data(0, Qt.UserRole)
        # Verifica se os dados do item são válidos
        if dados_item is None or not isinstance(dados_item, tuple) or len(dados_item) < 2:
            # Registra o erro no log
            log_queue.put((f"Erro: Dados insuficientes/inválidos no item da árvore para adicionar cálculo: {dados_item}", "red"))
            QMessageBox.warning(self, "Erro", "Não foi possível obter os dados do item da árvore.")
            return # Sai da função

        # 3. Encontra o dicionário do grupo correto
        chave_item = dados_item[0]
        grupo = dados_item[1] # O dicionário do grupo está na segunda posição

        # Verifica se o item clicado permite adicionar um cálculo (se é o grupo ou o pai dos cálculos)
        if chave_item == "calculos_parent":
            # Ok, clicou no item "SISTEMA DE CALCULOS"
            pass
        elif chave_item == "grupo":
             # Ok, clicou diretamente no item "GRUPO" (permissão alternativa)
             pass
        else:
            # Item clicado não é o local correto para adicionar cálculo
            mensagem_aviso = f"Ação 'Adicionar Cálculo' inválida para item com chave: {chave_item}. Clique em um Grupo ou no item 'SISTEMA DE CALCULOS'."
            # Registra o aviso no log
            log_queue.put((mensagem_aviso, "orange"))
            QMessageBox.warning(self, "Aviso", "Clique em um Grupo ou no item 'SISTEMA DE CALCULOS' para adicionar um cálculo.")
            return # Sai da função

        # Obtém o nome do grupo para mensagens de log/erro
        nome_grupo = grupo.get("grupo", "Desconhecido")
        log_queue.put((f"Adicionando cálculo no grupo '{nome_grupo}'.", "blue")) # Registra a ação no log

        # 4. Verifica se o grupo possui uma lista de memórias de gravação
        # (Necessário para selecionar a memória de saída do cálculo)
        lista_memorias = grupo.get("mem_list", [])
        if not lista_memorias or not isinstance(lista_memorias, list):
            # Registra o erro no log
            log_queue.put((f"Falha ao adicionar cálculo: Grupo '{nome_grupo}' sem memórias de gravação vinculadas (lista vazia ou inválida).", "orange"))
            QMessageBox.warning(self, "Erro", "Este ativo não possui Memórias de Gravação vinculadas para usar como saída de cálculo.")
            return # Sai da função

        # 5. Abre o diálogo JanelaCalculos
        # Verifica se a classe JanelaCalculos está definida (se foi importada ou definida no código)
        if 'JanelaCalculos' in globals():
            # Instancia o diálogo, passando a lista de memórias, operadores (mock) e o item pai
            # Passamos a self como parent para que o diálogo apareça centralizado em relação à janela principal
            # (A lista de operadores "["+", "-", "*", "/"]" pode ser removida se JanelaCalculos não a usar)
            dialogo = JanelaCalculos(lista_memorias, ["+", "-", "*", "/"], self)

            # Executa o diálogo modal (bloqueia a janela principal)
            if dialogo.exec_() == QDialog.Accepted:
                # 6. Se o usuário clicou em "Salvar", obtém os dados do diálogo
                dados_calculo = dialogo.get_dados() # Obtém o dicionário {'nome': ..., 'formula': ..., 'memoria': ...}

                # Extrai e limpa os dados obtidos
                nome_novo = dados_calculo.get("nome", "").strip()
                formula_nova = dados_calculo.get("formula", "").strip()
                memoria_saida_selecionada = dados_calculo.get("memoria", "").strip()

                # 7. Valida os dados obtidos do diálogo
                if not nome_novo or not formula_nova or not memoria_saida_selecionada:
                    # Registra o erro no log
                    log_queue.put(("Falha ao adicionar cálculo: Campos obrigatórios vazios no diálogo.", "orange"))
                    QMessageBox.warning(self, "Erro", "Nome, fórmula e memória de saída do cálculo não podem ser vazios.")
                    return # Sai da função após o aviso

                # 8. Verifica se o nome do novo cálculo já existe no grupo
                # Garante que o dicionário 'calculos' existe no grupo
                if "calculos" not in grupo or not isinstance(grupo["calculos"], dict):
                    grupo["calculos"] = {} # Inicializa se estiver faltando ou inválido
                    log_queue.put((f"Aviso: 'calculos' não era um dicionário válido no grupo '{nome_grupo}'. Criado um novo dicionário.", "orange"))

                # Verifica duplicidade
                if nome_novo in grupo["calculos"]:
                     # Registra o erro no log
                     log_queue.put((f"Falha ao adicionar cálculo: Nome '{nome_novo}' já existe no grupo '{nome_grupo}'.", "orange"))
                     QMessageBox.warning(self, "Erro", f"Já existe um cálculo com o nome '{nome_novo}'.")
                     return # Sai da função

                # 9. Verifica se a memória de saída selecionada é válida (existe na lista de memórias do grupo)
                # Compara a memória selecionada (string) com as memórias na lista (convertidas para string)
                if memoria_saida_selecionada not in [str(m) for m in lista_memorias]:
                     # Registra o erro no log
                     log_queue.put((f"Falha ao adicionar cálculo: Memória de saída '{memoria_saida_selecionada}' selecionada é inválida para o grupo '{nome_grupo}'. Não está na lista de memórias vinculadas.", "orange"))
                     QMessageBox.warning(self, "Erro", f"A memória de saída '{memoria_saida_selecionada}' selecionada não está na lista de Memórias de Gravação do grupo.")
                     return # Sai da função

                # 10. Adiciona o novo cálculo ao dicionário 'calculos' do grupo
                grupo["calculos"][nome_novo] = {
                    "formula": formula_nova,
                    "memoria": memoria_saida_selecionada # Armazena a memória selecionada
                }
                log_queue.put((f"Cálculo '{nome_novo}' com fórmula '{formula_nova}' e memória de saída '{memoria_saida_selecionada}' adicionado ao grupo '{nome_grupo}'.", "blue"))

                # 11. Salva a configuração, atualiza a árvore e notifica o serviço
                salvar_configuracao(self.config) # Salva a configuração atualizada
                # Mostra uma mensagem na bandeja do sistema (se disponível)
                if hasattr(self, 'tray_icon') and self.tray_icon:
                    self.tray_icon.showMessage("InLogic Studio", "Cálculo adicionado!", QSystemTrayIcon.Information, 2000)
                self.carregar_ativos() # Recarrega a árvore de ativos para mostrar o novo cálculo
                # Notifica o serviço ou as threads de leitura para recarregar a configuração
                if hasattr(self, 'reiniciar_clps'):
                     self.reiniciar_clps()
                     log_queue.put(("Notificando serviço para recarregar configuração...", "blue"))

                # Registra o sucesso no log
                log_queue.put((f"Cálculo '{nome_novo}' adicionado com sucesso ao grupo '{nome_grupo}'.", "green"))

            # else: Se o diálogo foi rejeitado (cancelado), nada acontece

        else:
            # Registra erro crítico se a classe JanelaCalculos não estiver disponível
            log_queue.put(("CRÍTICO: A classe JanelaCalculos não está definida ou importada. Não foi possível adicionar cálculo.", "red"))
            QMessageBox.critical(self, "Erro", "A classe JanelaCalculos não está definida ou importada. Verifique os imports.")

    def excluir_item(self, item):
        """Exclui um item (Grupo, Memória, Cálculo) conforme a lógica da versão antiga."""
        if not self.login_status:
             QMessageBox.warning(self, "Acesso Negado", "Faça login para excluir itens.")
             return

        key_data = item.data(0, Qt.UserRole)
        if key_data is None or len(key_data) < 2:
            print(f"Erro: Dados insuficientes no item para exclusão: {key_data}")
            log_queue.put(f"Erro: Dados insuficientes no item para exclusão: {key_data}")
            return

        key, grupo = key_data[:2]

        # === Excluir Grupo inteiro ===
        if key == "grupo":
            grupo_nome = grupo.get('grupo', 'Nome Desconhecido')
            confirmacao = QMessageBox.question(
                self,
                "Excluir Grupo",
                f"Deseja realmente excluir o grupo '{grupo_nome}'? Esta ação é irreversível.",
                QMessageBox.Yes | QMessageBox.No
            )
            if confirmacao == QMessageBox.Yes:
                try:
                    grupo_para_remover = None
                    if isinstance(self.config.get("grupos"), list):
                         for i, g in enumerate(self.config["grupos"]):
                             if isinstance(g, dict) and g.get("grupo") == grupo_nome and g is grupo:
                                 grupo_para_remover = g
                                 break

                    if grupo_para_remover:
                         self.config["grupos"].remove(grupo_para_remover)
                         salvar_configuracao(self.config)
                         if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", f"Grupo '{grupo_nome}' excluído!", QSystemTrayIcon.Information, 2000)
                         self.carregar_ativos()
                         if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                    else:
                         print(f"Erro: Grupo '{grupo_nome}' não encontrado na lista principal de configuração ao tentar remover.")
                         log_queue.put(f"Erro: Grupo '{grupo_nome}' não encontrado na lista principal de configuração ao tentar remover.")
                         QMessageBox.warning(self, "Erro", "Não foi possível encontrar o grupo para excluir na configuração principal.")

                except Exception as e:
                     print(f"Erro ao excluir grupo: {e}")
                     log_queue.put(f"Erro ao excluir grupo: {e}")
                     QMessageBox.warning(self, "Erro", f"Erro inesperado ao excluir grupo: {e}")


        # === Excluir Memória específica da lista mem_list ===
        elif key == "mem_list" and len(key_data) == 3:
            mem_value_to_remove = key_data[2]
            confirmacao = QMessageBox.question(
                 self,
                 "Excluir Memória",
                 f"Deseja realmente excluir a memória '{mem_value_to_remove}'?",
                 QMessageBox.Yes | QMessageBox.No
             )
            if confirmacao == QMessageBox.Yes:
                if "mem_list" in grupo and isinstance(grupo["mem_list"], list):
                    try:
                        # Remove a primeira ocorrência do valor na lista
                        grupo["mem_list"].remove(mem_value_to_remove)
                        salvar_configuracao(self.config)
                        if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Memória excluída!", QSystemTrayIcon.Information, 2000)
                        self.carregar_ativos()
                        # Reiniciar CLPs?
                        # if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                    except ValueError:
                        print(f"Erro: Memória '{mem_value_to_remove}' não encontrada na lista do grupo '{grupo.get('grupo', 'Desconhecido')}' ao tentar remover.")
                        log_queue.put(f"Erro: Memória '{mem_value_to_remove}' não encontrada na lista do grupo '{grupo.get('grupo', 'Desconhecido')}' ao tentar remover.")
                        QMessageBox.warning(self, "Erro", "Não foi possível encontrar a memória para excluir.")
                    except Exception as e:
                         print(f"Erro ao excluir memória: {e}")
                         log_queue.put(f"Erro ao excluir memória: {e}")
                         QMessageBox.warning(self, "Erro", f"Erro inesperado ao excluir memória: {e}")

                else:
                    print(f"Aviso: 'mem_list' não encontrado ou não é lista no grupo '{grupo.get('grupo', 'Desconhecido')}'.")
                    log_queue.put(f"Aviso: 'mem_list' não encontrado ou não é lista no grupo '{grupo.get('grupo', 'Desconhecido')}'.")
                    QMessageBox.warning(self, "Aviso", "A lista de memórias para este grupo não é válida.")


        # === Excluir Cálculo específico ===
        elif key == "calculo" and len(key_data) == 3:
            calculo_nome = key_data[2]

            confirmacao = QMessageBox.question(
                self,
                "Excluir Cálculo",
                f"Deseja realmente excluir o cálculo '{calculo_nome}'?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirmacao == QMessageBox.Yes:
                if "calculos" in grupo and isinstance(grupo["calculos"], dict) and calculo_nome in grupo["calculos"]:
                    del grupo["calculos"][calculo_nome]

                    salvar_configuracao(self.config)
                    if hasattr(self, 'tray_icon') and self.tray_icon: self.tray_icon.showMessage("Supervisório", "Cálculo excluído!", QSystemTrayIcon.Information, 2000)
                    self.carregar_ativos()
                    if hasattr(self, 'reiniciar_clps'): self.reiniciar_clps()
                else:
                     print(f"Erro: Cálculo '{calculo_nome}' não encontrado no dicionário 'calculos' do grupo '{grupo.get('grupo', 'Desconhecido')}' ao tentar remover.")
                     log_queue.put(f"Erro: Cálculo '{calculo_nome}' não encontrado no dicionário 'calculos' do grupo '{grupo.get('grupo', 'Desconhecido')}' ao tentar remover.")
                     QMessageBox.warning(self, "Erro", "Não foi possível encontrar o cálculo para excluir.")


        else:
             print(f"Ação 'Excluir' não implementada para o item com chave: {key}")
    # ------------------------------------------------------------------------

    # Função responsavel pela exibição do progressbar de carregamento na interface
    def start_progressbar(self):
        """Método para iniciar a Progressbar."""
        self.progress_window = Progressbar(tempo=5000)  # Tempo em milissegundos
        self.progress_window.center_on_screen()
        self.progress_window.show()
        self.progress_window.start_task()


    # Funçoes de donload e upload utilizando importação do modulo auxiliar 
    def realizar_download(self):
        """
        Realiza o download (criptografia e salvamento da pasta).
        """
        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para seguir com download.")
            return
        log_queue.put((f"Iniciando download de backup...", "blue"))
        self.verificar = self.backup_manager.processar_pasta(PATH)
        self.start_progressbar()    #   inicializa o progressbar na interface

    def realizar_upload_completo(self):
        """
        Realiza o upload completo de uma pasta criptografada.
        """
        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para seguir com upload.")
            return        
        self.backup_manager.upload_arquivos_ou_pasta()
        self.start_progressbar()    #   inicializa o progressbar na interface
        log_queue.put((f"Iniciando upload de backup...", "blue"))
        self.config = carregar_configuracao()
        self.carregar_ativos()
    # ---------------------------------------------------------------------

    # Add novo ativo no sistema
    def add_ativo (self):
        verificar_ou_criar_configuracao()
        self.config = carregar_configuracao()
        self.carregar_ativos()

    # Enviar comando nemd pipes para reiniciar o serviço windons e atualizar novas configuraçoes no sistema
    def enviar_comandos(self):
        """
        Enviar comando via named pipes para reiniciar serviço windons e recarregar novas configuraçoes
        """
        if not self.login_status:
            QMessageBox.warning(self, "Acesso Negado", "Faça login para recarregar configuraçoes")
            return 
        try:
            self.start_progressbar()    #   inicializa o progressbar na interface
            # comando = input("\n📥 Digite o comando (iniciar_clps / parar_clps / reload_config / status):\n> ")
            comando = "iniciar_clps"
            handle = win32file.CreateFile(
                self.PIPE_CMD,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            win32file.WriteFile(handle, comando.encode("utf-8"))
            result, data = win32file.ReadFile(handle, 4096)
        # decodifica bytes e remove espaços
            message = data.decode('utf-8').strip()
            # envia única string formatada
            QTimer.singleShot(5100, lambda: self.mostrar_alerta_depois(mensagem=message))

            
            
            win32file.CloseHandle(handle)

        except pywintypes.error as e:
            log_queue.put(f"InLogic Service>> [ERRO] Pipe de comando indisponível: {e}")

            time.sleep(2)
        except Exception as e:
            log_queue.put(f"InLogic Service>> [EXCEÇÃO] {e}")
            time.sleep(2)

    def mostrar_alerta_depois(self, mensagem):
        log_queue.put((f"InLogic Service>> {mensagem}", "blue"))
        QMessageBox.warning(self, "InLogic Service", "Atualização concluida...")
    # ---------------------------------------------------------------------


    # Iniciar Serviço do windons e verificar 
    def inicia_service(self):
        """ Verificar existencia, criar serviço do windons"""

        # Chama a função principal para gerenciar o serviço DO WINDONS
        verificar_servico_criar_start(
            self.service_name,
            self.bin_path,
            self.display_name
        )

    # Verificar Status do Serviço do windons
    def status_service(self):
        """ Verificar status do serviço do windons"""

        # Verifica o status final após a tentativa de iniciar
        final_status = get_service_status(self.service_name, log_queue) # Passa a queue
        log_queue.put(f"SISTEMA  |  [START] Status final após tentativa de início: {final_status}")
        if final_status == "RUNNING":
            self.status_variavel_critica = True  # ou True, conforme o padrão desejado
            QMessageBox.warning(self, "InLogic Service", f"Status: {final_status}")
            
        else:
            self.status_variavel_critica = False  # ou True, conforme o padrão desejado
            QMessageBox.warning(self, "InLogic Service", f"Status: {final_status}")
    
    # Verificar Status do Serviço do windons
    def triger_status_service(self):
        """Verifica status da licença e do serviço do Windows, atualizando indicador e tooltip."""
        status_licenca = False
        status_servico = False
        tooltip_msgs = []

        # --- Verificação da Licença ---
        try:
            with open(LICENSE_FILE, 'rb') as arquivo:
                conteudo_criptografado = arquivo.read()

            conteudo_descriptografado = descriptografar_dados(conteudo_criptografado)
            dados_json = json.loads(conteudo_descriptografado.decode('utf-8'))

            licenca = dados_json.get("licenca", False)
            if isinstance(licenca, str):
                licenca = licenca.strip().lower() == "true"

            if licenca is True:
                status_licenca = True
                tooltip_msgs.append("Licença: ✅ Ativa")
            else:
                tooltip_msgs.append("Licença: ❌ Inválida")
                try:
                    threading.Thread(target=monitorar_licenca, daemon=True).start()
                except Exception as e:
                    log_queue.put(("[Erro] No processo de licença: [threading.Thread(target=monitorar_licenca, daemon=True).start()] >> {e}", "red"))


                

        except Exception as e:
            log_queue.put((f"[ERRO] Falha ao verificar licença: {type(e).__name__} - {e}", "red"))
            log_queue.put((traceback.format_exc(), "gray"))
            tooltip_msgs.append("Licença: ❌ Erro na leitura")

        # --- Verificação do Serviço ---
        try:
            final_status = get_service_status(self.service_name, log_queue)
            if final_status == "RUNNING":
                status_servico = True
                tooltip_msgs.append("Serviço: ✅ Ativo")
            else:
                tooltip_msgs.append("Serviço: ❌ Inativo")

        except Exception as e:
            log_queue.put((f"[ERRO] Falha ao verificar serviço: {type(e).__name__} - {e}", "red"))
            log_queue.put((traceback.format_exc(), "gray"))
            tooltip_msgs.append("Serviço: ❌ Erro na verificação")

        # --- Atualização da UI ---
        status_geral = status_licenca and status_servico
        self.status_variavel_critica = status_geral

        if status_geral:
            cor = "green"
        else:
            cor = "red"

        # Atualizar estilo da bolinha (caso use estilos)
        self.label_indicador_status.setStyleSheet(f"background-color: {cor}; border-radius: 7px;")
        self.label_indicador_status.setToolTip("\n".join(tooltip_msgs))

        # ------------------------------   
# --------------------------------------


# --- Ponto de entrada e inicialização da aplicação ---
if __name__ == "__main__":

    log_queue.put(f"Iniciando aplicação {nome_software} V{versao}...")

    # Chama a função para baixar os recursos do Google Drive
    iniciar_download_recursos()

    # Crie a aplicação PyQt
    app = QApplication(sys.argv)

    # Define o ícone do aplicativo na barra de tarefas
    try:
        if os.path.exists(ICON_PATH) and not QIcon(ICON_PATH).isNull():
             app.setWindowIcon(QIcon(ICON_PATH))
        else:
             print(f"Aviso: Ícone da aplicação {ICON_PATH} não encontrado ou inválido. Usando padrão do sistema.")
             log_queue.put(f"Aviso: Ícone da aplicação {ICON_PATH} não encontrado ou inválido. Usando padrão do sistema.")
    except Exception as e:
        print(f"Aviso: Não foi possível definir o ícone do aplicativo na barra de tarefas: {e}")
        log_queue.put(f"Aviso: Falha ao definir ícone da aplicação: {e}")

    # Ler a senha de autenticação (do arquivo ou usar padrão) ANTES de criar a janela principal
    ler_senha_autenticacao()
    numero_serie = get_system_info()

    if ctypes.windll.shell32.IsUserAnAdmin():
        window = SupervisoryApp()
        window.show()
        sys.exit(app.exec_())
    else:
        adm = checar_e_elevacao_admin()
        if False:
            window = SupervisoryApp()
            window.show()
            sys.exit(app.exec_())
# -----------------------------------------------------



 A seguir codigo que roda como serviço do windons 100% 

 import os
import sys
import time
import logging
import traceback
import pythoncom
from queue import Queue, Empty
from logging.handlers import RotatingFileHandler
from threading import Thread, Lock
import threading
from pyModbusTCP.client import ModbusClient  # Substituído por pyModbusTCP
from multiprocessing import Process, Manager , freeze_support, Event, RawArray, Value, Queue
from pycomm3 import LogixDriver
import paho.mqtt.client as mqtt_client
import paho.mqtt.client as mqtt
import win32file
import openpyxl
import pyodbc
import json
import servicemanager
import uuid
from datetime import datetime
import win32api
win32api.SetConsoleCtrlHandler(lambda x: True, True)

# Api do google envio de notificação
from google.oauth2 import service_account
import google.auth.transport.requests
import requests
import tempfile


import hashlib
import sys
import os
import win32event
import win32api
import winerror
import psutil
import ctypes

# Imports do service
import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import sys
import traceback


# Import da validação de licença
import threading
import time
import os
import json
import wmi
import pythoncom
from datetime import datetime, timedelta
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from collections import deque  # Adicione no topo do arquivo
log_buffer = deque(maxlen=100)  # Buffer circular de logs

from concurrent.futures import ThreadPoolExecutor, as_completed


pipe_handle = None  # 🔗 Variável global para o Named Pipe

# === Configuração Avançada do Logger ===
LOG_DIR = r"C:\In Logic\Logs Inlogic"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "log_service.log")
MAX_LOG_SIZE = 200 * 1024 * 1024  # 200MB
BACKUP_COUNT = 5  # Quantidade máxima de arquivos antigos mantidos
MAX_LOG_QUEUE_SIZE = 1000  # Limite da fila para evitar consumo excessivo de RAM

# Fila global para logs
log_queue = Queue()

# Lista global para manter os CLPs ativos
clps_ativos = []


# Configuração global do logger
logger = logging.getLogger("LogService")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT, encoding="utf-8")
formatter = logging.Formatter(
    '%(asctime)s |  %(levelname)-8s |  %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S'
)
handler.setFormatter(formatter)
logger.addHandler(handler)


status_conexao = False
running = True
servico_global = None


# Caminho e chave
CONFIG_PATH = r"C:\In Logic\Setup ativos"
BASE_IMAGES = r"C:\In Logic\Imagens"
CONFIG_PATH1 = os.path.join(CONFIG_PATH, "Setup.cfg")
CHAVE_SECRETA = b"inlogic18366058".ljust(32, b'0')  # Garante 32 bytes
LICENSE_FILE = os.path.join(CONFIG_PATH, "Authentication.cfg")  # Arquivo de licença

# Arquivo json de configuração de autenticação google
service_account_info = {
Variavel ocultada
}

# Variável global para controle do status da licença
licenca_ativa = threading.Event()

# Função desabilitada devido codigo estar rodando como um serviço nativo windons
def evitar_execucao_duplicada(nome_base=None):
    """
    Evita execução duplicada do script ou .exe.
    - Usa mutex nomeado via Windows API
    - Valida também via psutil se outro processo com mesmo path já está rodando
    """

    # 📌 Descobre o caminho do executável ou script atual
    if nome_base is None:
        caminho_executavel = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    else:
        caminho_executavel = nome_base

    caminho_normalizado = os.path.realpath(caminho_executavel).lower()

    # 🔒 Mutex exclusivo baseado no hash do caminho
    hash_nome = hashlib.sha256(caminho_normalizado.encode()).hexdigest()
    nome_mutex = f"inlogic_mutex_{hash_nome}"
    mutex = win32event.CreateMutex(None, False, nome_mutex)

    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        #ctypes.windll.user32.MessageBoxW(0, "O sistema já está em execução (mutex detectado).", "In Logic", 0x10)
        sys.exit(1)

    # 🧠 Validação extra via psutil
    meu_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'exe', 'cmdline']):
        try:
            if proc.info['pid'] == meu_pid:
                continue

            exe_proc = proc.info['exe'] or ""
            cmdline_proc = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            exe_proc_normalizado = os.path.realpath(exe_proc).lower() if exe_proc else ""

            if caminho_normalizado == exe_proc_normalizado:
                mensagem = (
                    f"⚠ Já existe uma instância do sistema em execução!\n\n"
                    f"🔁 PID Atual: {meu_pid}\n"
                    f"🆔 PID Duplicado: {proc.info['pid']}\n"
                    f"📄 Executável: {exe_proc}\n"
                    f"📜 Cmdline: {cmdline_proc}\n"
                    f"📁 Comparado com: {caminho_executavel}"
                )

                print("\n🔍 Instância duplicada detectada!")
                print(mensagem)

                ctypes.windll.user32.MessageBoxW(0, mensagem, "In Logic - Instância Duplicada", 0x10)
                sys.exit(1)

        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            continue

    return mutex

# === Classes Principais ===

class ConexaoSQLPersistente:
    def __init__(self, db_config):
        self.db_config = db_config
        self.conn = None
        self.cursor = None
        self.lock = threading.Lock()  # 🔒 Protege acesso simultâneo
        self.erro_colunas = False
        self.erro_fechar = False
        self.erro_execultar = False
        self.erro_execultar1 = False
        self.erro_conectar = False

        self.reconectar()

    def reconectar(self):
        """Tenta (re)estabelecer a conexão com o SQL Server"""
        try:
            self.fechar()  # Fecha conexão anterior, se houver

            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={self.db_config['server']};"
                f"DATABASE={self.db_config['database']};"
                f"UID={self.db_config['username']};"
                f"PWD={self.db_config['password']};"
            )
            self.conn = pyodbc.connect(conn_str, timeout=5)
            self.cursor = self.conn.cursor()
            log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   Conexão SQL estabelecida com sucesso...")
            self.erro_conectar = False

        except Exception as ex:
            if not self.erro_conectar:
                log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   [ERRO] Falha ao conectar ao SQL Server: {ex}")
                self.erro_conectar = True
            self.conn = None
            self.cursor = None

    def executar(self, sql, valores=None):
        """
        Executa comandos SQL com reconexão automática em caso de falha.
        """
        with self.lock:
            try:
                if not self.conn or not self.cursor:
                    self.reconectar()

                self.cursor.execute(sql, valores or [])
                self.conn.commit()
                self.erro_execultar = False
                self.erro_execultar1 = False
            except pyodbc.OperationalError as op_err:
                if not self.erro_execultar:
                    log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   [ERRO] Operacional (desconectado?): {op_err}")
                    self.erro_execultar = True
                self.reconectar()
                raise op_err

            except Exception as ex:
                if not self.erro_execultar1:
                    log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   [ERRO] Falha ao executar comando SQL: {ex}")
                    self.erro_execultar1 = True
                raise ex

    def obter_colunas(self, tabela_sql):
        """
        Retorna os nomes das colunas da tabela SQL fornecida.
        """
        with self.lock:
            try:
                if not self.conn or not self.cursor:
                    self.reconectar()

                self.cursor.execute(f"SELECT * FROM {tabela_sql} WHERE 1=0")
                self.erro_colunas = False
                return [col[0] for col in self.cursor.description]

            except Exception as ex:
                if not self.erro_colunas:
                    log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   [ERRO] Falha ao obter colunas da tabela '{tabela_sql}': {ex}")
                    self.erro_colunas = True
                return []

    def fechar(self):
        """Fecha conexão e cursor"""
        try:
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            if self.conn:
                self.conn.close()
                self.conn = None

            self.erro_fechar = False

        except Exception as ex:
            if not self.erro_fechar:
                log_queue.put(f"SISTEMA  |  {self.db_config['database']}  |   [ERRO] Falha ao fechar conexão: {ex}")
                self.erro_fechar = True


# ===============================
# Processo filho: leitura Modbus
# ===============================
class CLPModbusProcesso(Process):
    """
    Processo concorrente responsável por:
      - Ler todas as memórias do CLP (registradores Modbus)
      - Ler o bit/coil do gatilho
      - Atualizar a memória compartilhada (RawArray e Value)
      - Atualizar status e tempo de ciclo
    """
    def __init__(
        self,
        plc_ip,
        mem_list,
        gatilho_addr,
        shared_mem_raw,
        gatilho_valor_raw,
        loop_time_raw,
        status_raw,
        stop_flag,
        log_queue
    ):
       
        super().__init__()
        self.daemon = True  # Processo filho morre junto com o pai
        self.plc_ip = plc_ip
        self.mem_list = mem_list
        self.gatilho_addr = gatilho_addr  # endereço do coil do gatilho
        self.shared_mem_raw = shared_mem_raw  # RawArray para registradores
        self.gatilho_valor_raw = gatilho_valor_raw  # Value(bool) para gatilho
        self.loop_time_raw = loop_time_raw  # Value(double) para tempo de ciclo
        self.status_raw = status_raw  # Value(char*) para status do processo
        self.stop_flag = stop_flag
        self.log_queue = log_queue  # Fila global de logs do codigo pai principal
        self.connected = None # Flag de status de conexão do CLP
        self.client = None # FLag para armazenar o cliente de conexão modbus 

    def run(self):
        import time
        from pyModbusTCP.client import ModbusClient

        self.client = None                   # Cliente ModbusTCP
        self.connected = False               # Flag para status de conexão
        self.previous_trigger_state = False  # Estado anterior do gatilho (para detectar borda)
        last_logged_status = None            # Controle para logar conexão/desconexão apenas em transição

        # Loga início do processo
        self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Processo iniciado ✅")

        while not self.stop_flag.value:
            try:
                # 1. Tenta conectar se necessário (apenas se não está conectado)
                if not self.connected or self.client is None:
                    self.client = ModbusClient(
                        host=self.plc_ip, auto_open=True, auto_close=True, timeout=2
                    )
                    self.connected = self.client.open()  # Tenta abrir conexão TCP

                    if self.connected:
                        self.status_raw.value = b'connected'
                        # Loga conexão apenas se status mudou
                        if last_logged_status != "connected":
                            self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] ✅ CLP conectado com sucesso.")
                            last_logged_status = "connected"
                        # Inicializa o estado anterior do gatilho
                        gatilho_valor = self.client.read_coils(self.gatilho_addr, 1)
                        self.previous_trigger_state = gatilho_valor[0] if gatilho_valor is not None else False
                    else:
                        self.status_raw.value = b'disconnected'
                        # Loga desconexão apenas se status mudou
                        if last_logged_status != "disconnected":
                            self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] ❌ Tentando reconectar em 2s...")
                            last_logged_status = "disconnected"
                        time.sleep(2)  # Aguarda antes de tentar reconectar
                        continue       # Reinicia o loop (não tenta ler nada sem conexão)

                # 2. Leitura cíclica dos dados do CLP
                ciclo_inicio = time.perf_counter()  # Marca início do ciclo de leitura

                # Lê o valor do gatilho (coil)
                gatilho_valor = self.client.read_coils(self.gatilho_addr, 1)
                if gatilho_valor is not None:
                    current_trigger_state = gatilho_valor[0]
                else:
                    raise Exception("Falha ao ler o gatilho (coil)")

                # Atualiza a memória compartilhada com valor do gatilho
                self.gatilho_valor_raw.value = current_trigger_state

                # Lê todos os registradores (holding registers) definidos em mem_list
                memories_data = {}
                for reg in self.mem_list:
                    valor_word = self.client.read_holding_registers(reg, 1)
                    if valor_word is not None:
                        memories_data[reg] = valor_word[0]
                    else:
                        raise Exception(f"Falha na leitura do registrador {reg}")

                # Atualiza o RawArray compartilhado com os valores lidos
                for idx, reg in enumerate(self.mem_list):
                    self.shared_mem_raw[idx] = memories_data.get(reg, 0)

                ciclo_fim = time.perf_counter()  # Marca fim do ciclo de leitura
                ciclo_duracao = ciclo_fim - ciclo_inicio
                self.loop_time_raw.value = ciclo_duracao  # Atualiza tempo de ciclo

                # Loga borda de subida do gatilho (apenas para diagnóstico, não polui log)
                if current_trigger_state and not self.previous_trigger_state:
                    pass
                # Atualiza estado anterior do gatilho para próxima iteração
                self.previous_trigger_state = current_trigger_state

                time.sleep(0.01)  # Pequeno delay para aliviar CPU

            except Exception as e:
                # Se ocorrer exceção, loga desconexão apenas se status mudou
                self.status_raw.value = b'disconnected'
                if last_logged_status != "disconnected":
                    self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Erro de comunicação: {e} | Tentando reconectar...")
                    last_logged_status = "disconnected"
                self.connected = False
                # Fecha o cliente Modbus, se necessário
                if self.client:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                time.sleep(2)  # Aguarda antes de tentar reconectar

        # Ao sair do loop (stop_flag ativado), fecha conexão e loga finalização
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Processo finalizado.")

# Classe principal: inicializa estrutura e lógica CLP
# ===================================================
class CLPModbus:
    """
    Classe principal de integração com CLP Delta via Modbus TCP.
    Organiza toda a comunicação, memória compartilhada e eventos.
    """
    def __init__(
        self,
        plc_ip,
        notificacao_config=None,
        mem_list=None,
        gatilho=1000,
        triger=None,
        db_config=None,
        calculos=None,
        mqtt_config_acesso=None,
        local_gravacao=None,
        manager=None
    ):
        # --- Variáveis originais e opcionais ---
        self.notificacao_config = notificacao_config or {}
        self.plc_ip = plc_ip
        self.mem_list = mem_list if mem_list is not None else []
        self.gatilho = gatilho                      # Endereço do gatilho (coil Modbus)
        self.triger = float(triger) if isinstance(triger, (int, float)) and triger else 0   # Trigger automático (tempo, em segundos)
        self.db_config = db_config
        self.calculos = calculos if calculos is not None else {}
        self.configuracao_mqtt = mqtt_config_acesso
        self.local_gravacao = local_gravacao if local_gravacao is not None else {}
        self.manager = manager
        self.mem_size = len(self.mem_list)

        # --- Memória compartilhada robusta para dados e controle ---
        # Array para registradores int16
        self.shared_mem_raw = RawArray('h', self.mem_size)
        # Valor booleano do gatilho (coil)
        self.gatilho_valor_raw = Value(ctypes.c_bool, False)
        # Tempo de loop/ciclo (monitoramento)
        self.loop_time_raw = Value(ctypes.c_double, 0.0)
        # Status do processo (monitoramento)
        self.status_raw = Value(ctypes.c_char_p, b'disconnected')


        # Flag para parar processo
        self.stop_flag = Value('b', False)  # 'b' = boolean

        # Fila para eventos de gravação/etc.
        self.fila = Queue()
        self.fila_excel = Queue()    # Fila para falhas de Excel
        self.fila_sql = Queue()      # Fila para falhas de SQL
        self.fila_mqtt = Queue()     # Fila para falhas de MQTT

        # Estado anterior do gatilho (para detectar a borda de subida)
        self.gatilho_valor_anterior = False
        # Para trigger automático de gravação
        self._last_trigger_time = time.perf_counter()

        # --- Variáveis globais e SQL (mantém compatibilidade) ---
        global licenca_ativa
        self.licenca_ativa = licenca_ativa

        # Banco de dados: inicialização (mantém compatibilidade)
        self.sql_conexao = None

        # Verifica se db_config foi passado e se é um dicionário
        if isinstance(self.db_config, dict):
            # Define as chaves obrigatórias para conexão SQL
            required_keys = {'server', 'database', 'username', 'password'}
            
            # Lista de valores considerados genéricos (placeholders não preenchidos)
            invalid_values = {
                "GENÉRICO_MODIFICAVEL",
                "GENÉRICO_V001_MODIFICAVEL",
                "SEU_NOME_MODIFICAVEL",
                "SUA_SENHA"
            }
            
            # Verifica se todas as chaves obrigatórias estão presentes no dicionário
            if required_keys.issubset(self.db_config):
                # Verifica se ALGUM dos campos obrigatórios está com valor padrão/genérico
                if any(not str(self.db_config[k]).strip() or str(self.db_config[k]).strip() in invalid_values for k in required_keys):
                    # Se existir valor genérico, loga que a configuração não está válida e ignora a conexão
                    log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")
                else:
                    try:
                        # Tenta criar a conexão persistente com o banco de dados usando os dados fornecidos
                        self.sql_conexao = ConexaoSQLPersistente(self.db_config)
                    except Exception as e:
                        # Em caso de erro na conexão, loga o erro para diagnóstico
                        log_queue.put(f"{self.plc_ip}  |  [ERRO SQL] {e}")
            else:
                # Se faltar qualquer chave obrigatória, loga que os dados estão incompletos e desabilita SQL
                log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")



        # --- Instacia Processo filho para leitura do CLP ---
        try:
            self.process = CLPModbusProcesso(
                plc_ip=self.plc_ip,
                mem_list=self.mem_list,
                gatilho_addr=self.gatilho,
                shared_mem_raw=self.shared_mem_raw,
                gatilho_valor_raw=self.gatilho_valor_raw,
                loop_time_raw=self.loop_time_raw,
                status_raw=self.status_raw,
                stop_flag=self.stop_flag,
                log_queue=log_queue    # <-- aqui você passa a fila global
            )
            self.process.start()
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            log_queue.put(f"{self.plc_ip}  |  ❌ Falha ao iniciar processo: {e}\n{tb}")


        self.running = True  # <-- Adicione esta linha

        # Tempos para análise de desempenho (nomes antigos)
        self.inicio_tempo = 0
        self.fim_tempo = 0
        self.tempo_total = 0

    def ler_memorias(self):
        proximo_disparo_timer = time.perf_counter() + self.triger if self.triger and self.triger > 0 else None

        while self.running:
            # --- Borda de subida do gatilho físico ---
            valor_atual = self.gatilho_valor_raw.value
            if valor_atual and not self.gatilho_valor_anterior:
                self.tempo_total = self.loop_time_raw.value
                self._registrar_evento(motivo="gatilho")
            self.gatilho_valor_anterior = valor_atual

            # --- Temporizador: gravação automática ---
            if self.triger and isinstance(self.triger, (int, float)) and self.triger > 0:
                agora = time.perf_counter()
                if agora >= proximo_disparo_timer:
                    self.tempo_total = self.loop_time_raw.value
                    self._registrar_evento(motivo="tempo")
                    # Garante que o próximo disparo será exatamente múltiplo do trigger, sem drift
                    proximo_disparo_timer += self.triger
                    # Se houve atraso e o tempo já passou de vários triggers, corrige:
                    if agora > proximo_disparo_timer:
                        # Ajusta para o próximo múltiplo
                        proximo_disparo_timer = agora + self.triger

            time.sleep(0.01)  # Alivia CPU

    def conectar (self):
        while self.running:
            break

    def _registrar_evento(self, motivo="manual"):
        """
        Monta o dicionário de dados e coloca na fila para gravação/SQL/MQTT/etc.
        """
        dados = {reg: self.shared_mem_raw[i] for i, reg in enumerate(self.mem_list)}
        item = {
            "clp_ip": self.plc_ip,
            "gatilho": self.gatilho,
            "dados_memorias": dados,
        }
        if licenca_ativa.is_set():
            self.fila.put(item)
        else:
            log_queue.put(f"{self.plc_ip}  |  Gravação interrompida: licença inativa.")

    def obter_dados(self):
        """
        Retorna snapshot atual das memórias compartilhadas.
        """
        return {reg: self.shared_mem_raw[i] for i, reg in enumerate(self.mem_list)}

    def obter_status(self):
        """
        Retorna status atual do processo filho/Modbus.
        """
        return self.status_raw.value.decode('utf-8')

    def parar(self):
        """
        Para o processo filho e limpa recursos.
        """
        try:
            self.stop_flag.value = True
            if hasattr(self, 'process') and self.process.is_alive():
                self.process.join(timeout=10)
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(timeout=2)
            log_queue.put(f"{self.plc_ip}  | CLPModbus parado com sucesso.")
            self.running = False  # Finaliza Thread principal CLP
        except Exception as e:
            log_queue.put(f"{self.plc_ip}  |  ❌ Erro na finalização do CLP: {e}")



# Processo filho: leitura cíclica do ControlLogix
class CLPControlLogixProcesso(Process):
    """
    Processo concorrente responsável por:
      - Ler todas as tags do CLP ControlLogix
      - Ler o bit/tag do gatilho
      - Atualizar a memória compartilhada (RawArray e Value)
      - Atualizar status e tempo de ciclo
    """
    def __init__(
        self,
        plc_ip,
        mem_list,
        gatilho_tag,
        shared_mem_raw,
        gatilho_valor_raw,
        loop_time_raw,
        status_raw,
        stop_flag,
        log_queue
    ):
        super().__init__()
        self.daemon = True  # Processo filho morre junto com o pai
        self.plc_ip = plc_ip
        self.mem_list = mem_list
        self.gatilho_tag = gatilho_tag
        self.shared_mem_raw = shared_mem_raw
        self.gatilho_valor_raw = gatilho_valor_raw
        self.loop_time_raw = loop_time_raw
        self.status_raw = status_raw
        self.stop_flag = stop_flag
        self.log_queue = log_queue


    def run(self):
        from pycomm3 import LogixDriver
        self.client = None
        self.connected = False
        last_logged_status = None

        self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Processo iniciado ✅")

        while not self.stop_flag.value:
            try:
                if not self.connected or self.client is None:
                    self.client = LogixDriver(self.plc_ip)
                    self.client.open()
                    self.connected = True
                    self.status_raw.value = b'connected'
                    if last_logged_status != "connected":
                        self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] ✅ ControlLogix conectado.")
                        last_logged_status = "connected"
                    gatilho_valor = self.client.read(self.gatilho_tag)
                    self.previous_trigger_state = gatilho_valor.value if gatilho_valor is not None and hasattr(gatilho_valor, 'value') else False

                ciclo_inicio = time.perf_counter()

                # Lê o valor do gatilho (tag)
                gatilho_valor = self.client.read(self.gatilho_tag)
                if gatilho_valor is not None:
                    current_trigger_state = gatilho_valor.value if hasattr(gatilho_valor, 'value') else gatilho_valor
                else:
                    raise Exception("Falha ao ler o gatilho (tag)")
                self.gatilho_valor_raw.value = bool(current_trigger_state)

                # Lê todas as tags definidas em mem_list
                for idx, tag in enumerate(self.mem_list):
                    valor_lido = self.client.read(tag)
                    valor = valor_lido.value if hasattr(valor_lido, 'value') else valor_lido

                    # -- Tratamento igual ao antigo:
                    v = 0
                    if valor is None:
                        v = 0
                    elif isinstance(valor, (int, float)):
                        v = valor
                    elif isinstance(valor, bool):
                        v = int(valor)
                    elif isinstance(valor, str):
                        try:
                            # tenta converter string para float
                            if "." in valor or "e" in valor.lower():
                                v = float(valor)
                            else:
                                v = int(valor)
                        except Exception:
                            v = 0
                    else:
                        v = 0

                    self.shared_mem_raw[idx] = v

                ciclo_fim = time.perf_counter()
                self.loop_time_raw.value = ciclo_fim - ciclo_inicio
                self.status_raw.value = b'connected'
                time.sleep(0.01)
            except Exception as e:
                self.status_raw.value = b'disconnected'
                if last_logged_status != "disconnected":
                    self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Erro: {e} | Tentando reconectar...")
                    last_logged_status = "disconnected"
                self.connected = False
                if self.client:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                time.sleep(2)

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.log_queue.put(f"[{self.plc_ip}] [PROCESSO] Processo finalizado.")



class CLPControlLogix:
    """
    Classe principal de integração com CLP Allen Bradley ControlLogix via Ethernet/IP.
    Estrutura e lógica compatíveis com CLPModbus: filas, SQL seguro, logs, triggers, temporizador, shutdown seguro.
    """
    def __init__(
        self,
        plc_ip,
        notificacao_config=None,
        mem_list=None,
        gatilho=None,
        triger=None,
        db_config=None,
        calculos=None,
        mqtt_config_acesso=None,
        local_gravacao=None,
        manager=None
    ):
        # --- Variáveis de configuração ---
        self.notificacao_config = notificacao_config or {}
        self.plc_ip = plc_ip
        self.mem_list = mem_list if mem_list is not None else []
        self.gatilho = gatilho
        self.triger = float(triger) if isinstance(triger, (int, float)) and triger else 0
        self.db_config = db_config
        self.calculos = calculos if calculos is not None else {}
        self.configuracao_mqtt = mqtt_config_acesso
        self.local_gravacao = local_gravacao if local_gravacao is not None else {}
        self.manager = manager
        self.mem_size = len(self.mem_list)

        # --- Memória compartilhada para dados e controle ---
        self.shared_mem_raw = RawArray('d', self.mem_size)  # Memória para os valores das tags
        self.gatilho_valor_raw = Value(ctypes.c_bool, False)  # Valor do gatilho
        self.loop_time_raw = Value(ctypes.c_double, 0.0)     # Tempo de ciclo
        self.status_raw = Value(ctypes.c_char_p, b'disconnected')  # Status do processo
        self.stop_flag = Value('b', False)  # Flag de parada

        # --- Filas para eventos, erros e logs ---
        self.fila = Queue()
        self.fila_excel = Queue()
        self.fila_sql = Queue()
        self.fila_mqtt = Queue()

        # --- Controle de trigger e temporizador ---
        self.gatilho_valor_anterior = False
        self._last_trigger_time = time.perf_counter()

        # --- Variáveis globais e SQL seguro ---
        global licenca_ativa
        self.licenca_ativa = licenca_ativa
        self.sql_conexao = None

        # --- Checagem avançada do db_config ---
        if isinstance(self.db_config, dict):
            required_keys = {'server', 'database', 'username', 'password'}
            invalid_values = {
                "GENÉRICO_MODIFICAVEL",
                "GENÉRICO_V001_MODIFICAVEL",
                "SEU_NOME_MODIFICAVEL",
                "SUA_SENHA"
            }
            if required_keys.issubset(self.db_config):
                if any(not str(self.db_config[k]).strip() or str(self.db_config[k]).strip() in invalid_values for k in required_keys):
                    log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")
                else:
                    try:
                        self.sql_conexao = ConexaoSQLPersistente(self.db_config)
                    except Exception as e:
                        log_queue.put(f"{self.plc_ip}  |  [ERRO SQL] {e}")
            else:
                log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")

        self.running = True
        self.inicio_tempo = 0
        self.fim_tempo = 0
        self.tempo_total = 0

        # --- Instancia Processo filho para leitura do CLP ---
        try:
            self.process = CLPControlLogixProcesso(
                plc_ip=self.plc_ip,
                mem_list=self.mem_list,
                gatilho_tag=self.gatilho,
                shared_mem_raw=self.shared_mem_raw,
                gatilho_valor_raw=self.gatilho_valor_raw,
                loop_time_raw=self.loop_time_raw,
                status_raw=self.status_raw,
                stop_flag=self.stop_flag,
                log_queue=log_queue
            )
            self.process.start()
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            log_queue.put(f"{self.plc_ip}  |  ❌ Falha ao iniciar processo: {e}\n{tb}")


    def conectar (self):
        while self.running:
            break

    def ler_memorias(self):
        """
        Thread principal: monitora borda de gatilho e temporizador, dispara eventos padronizados (padrão Modbus).
        """
        proximo_disparo_timer = time.perf_counter() + self.triger if self.triger and self.triger > 0 else None

        while self.running:
            # --- Borda de subida do gatilho físico ---
            valor_atual = self.gatilho_valor_raw.value
            if valor_atual and not self.gatilho_valor_anterior:
                self.tempo_total = self.loop_time_raw.value
                self._registrar_evento(motivo="gatilho")
            self.gatilho_valor_anterior = valor_atual

            # --- Temporizador: gravação automática ---
            if self.triger and isinstance(self.triger, (int, float)) and self.triger > 0:
                agora = time.perf_counter()
                if agora >= proximo_disparo_timer:
                    self.tempo_total = self.loop_time_raw.value
                    self._registrar_evento(motivo="tempo")
                    proximo_disparo_timer += self.triger
                    if agora > proximo_disparo_timer:
                        proximo_disparo_timer = agora + self.triger

            time.sleep(0.01)  # Alivia CPU

    def _registrar_evento(self, motivo="manual"):
        """
        Monta o dicionário de dados e coloca na fila para gravação/SQL/MQTT/etc.
        Padrão igual ao Modbus!
        """
        dados = {reg: self.shared_mem_raw[i] for i, reg in enumerate(self.mem_list)}
        item = {
            "clp_ip": self.plc_ip,
            "gatilho": self.gatilho,
            "dados_memorias": dados
        }
        if licenca_ativa.is_set():
            self.fila.put(item)
        else:
            log_queue.put(f"{self.plc_ip}  |  Gravação interrompida: licença inativa.")

    def obter_dados(self):
        """
        Retorna snapshot atual das memórias compartilhadas.
        """
        return {reg: self.shared_mem_raw[i] for i, reg in enumerate(self.mem_list)}

    def obter_status(self):
        """
        Retorna status atual do processo filho/CLP.
        """
        return self.status_raw.value.decode('utf-8')

    def parar(self):
        """
        Para o processo filho e limpa recursos.
        """
        try:
            self.stop_flag.value = True
            if hasattr(self, 'process') and self.process.is_alive():
                self.process.join(timeout=10)
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(timeout=2)
            log_queue.put(f"{self.plc_ip}  | CLP ControlLogix parado com sucesso.")
            self.running = False
        except Exception as e:
            log_queue.put(f"{self.plc_ip}  |  ❌ Erro na finalização do CLP: {e}")



    
"""

class CLPControlLogix:
    def __init__(self, plc_ip, notificacao_config=None, mem_list=None, gatilho=None, triger=None, db_config=None, calculos=None, mqtt_config_acesso=None, local_gravacao=None):
        
        self.notificacao_config = notificacao_config or {}
        self.plc_ip = plc_ip
        self.mem_list = mem_list if mem_list else []
        self.gatilho = gatilho
        self.triger = float(triger) if isinstance(triger, (int, float)) and triger > 0 else 0
        self.local_gravacao = local_gravacao if local_gravacao else {}
        self.calculos = calculos if calculos else {}
        self.configuracao_mqtt = mqtt_config_acesso if mqtt_config_acesso else {}

        # Variavel de licença global
        global licenca_ativa
        self.licenca_ativa = licenca_ativa

        # ✅ Verificação avançada do db_config
        if isinstance(db_config, dict):
            required_keys = {'server', 'database', 'username', 'password'}
            if required_keys.issubset(db_config):
                self.db_config = db_config
                self.sql_conexao = ConexaoSQLPersistente(self.db_config)
            else:
                log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")
                self.db_config = None
                self.sql_conexao = None
        else:
            self.db_config = None
            self.sql_conexao = None


        # Filas individuais para este CLP
        self.fila = Queue()  # Fila principal para leitura de dados
        self.fila_excel = Queue()  # Fila de falhas para Excel
        self.fila_sql = Queue()  # Fila de falhas para SQL
        self.fila_mqtt = Queue()  # Fila de falhas para mqtt

        # controle de print de logs evitar multiplos
        self.falha_excel = False
        self.falha_sql = False

        self.lock = Lock()
        self.connected = False
        self.running = True
        self.previous_trigger_state = False
        self.client = None


    def conectar(self):
        try:
            self.client = LogixDriver(self.plc_ip)
            self.client.open()
            self.connected = True
            log_queue.put((f"{self.plc_ip}  |  CLP ControlLogix conectado...", "green"))
        except Exception as e:
            log_queue.put((f"{self.plc_ip}  |  Falha ao conectar ao CLP ControlLogix - {str(e)}", "red"))
            self.connected = False

    def ler_memorias(self):
        initial_state_set = False  # Variável para indicar se o estado inicial foi definido

        while self.running:
            try:
                # Conectar ao CLP, se ainda não estiver conectado
                if not self.connected:
                    self.client = LogixDriver(self.plc_ip)  # Inicializa o cliente
                    self.client.open()  # Abre a sessão explicitamente
                    self.connected = True
                    log_queue.put((f"{self.plc_ip}  |  Conectado ao CLP ControlLogix no IP: {self.plc_ip}", "green"))
                
                # Verificar se a conexão está ativa (usando uma leitura de teste)
                try:
                    # Testa a conexão lendo uma tag simples (pode ser substituída por outra tag padrão)
                    self.client.read(self.gatilho)
                except Exception as e:
                    log_queue.put((f"{self.plc_ip}  |  Falha ao verificar conexão com o CLP: {str(e)}", "red"))
                    raise ValueError("{self.plc_ip}  |  A conexão com o CLP parece estar inativa.")
                
                # Monitorar a tag de gatilho
                gatilho_valor = self.client.read(self.gatilho)
                if gatilho_valor is not None:
                    current_trigger_state = gatilho_valor.value if hasattr(gatilho_valor, 'value') else gatilho_valor
                    
                    # Define o estado inicial do gatilho, se ainda não foi definido
                    if not initial_state_set:
                        self.previous_trigger_state = current_trigger_state
                        initial_state_set = True
                        #log_queue.put(f"Estado inicial do gatilho {self.gatilho} configurado como {self.previous_trigger_state}")
                    
                    # Detectar borda de subida (gatilho ativado)
                    if current_trigger_state and not self.previous_trigger_state:
                        self.inicio_tempo = time.perf_counter() # Inicia o calculo de tempo gasto
      
                        # Leitura das memórias especificadas em `mem_list`
                        with self.lock:
                            dados_ciclo = {}  # Dicionário para armazenar os valores do ciclo de gravação
                            for tag in self.mem_list:
                                try:
                                    valor = self.client.read(tag)  # Lê o valor da tag
                                    valor = valor.value if hasattr(valor, 'value') else valor  # Extrai o valor real
                                    dados_ciclo[tag] = valor  # Adiciona o valor lido ao dicionário
                                except Exception as e:
                                    log_queue.put((f"{self.plc_ip}  |  Erro ao ler tag {tag}: {str(e)}", "red"))
                                    dados_ciclo[tag] = None  # Caso não consiga ler, adiciona None
                            # Insere os valores do ciclo completo na fila como um único item (dicionário)
                            item = {
                                "clp_ip": self.plc_ip,
                                "gatilho": self.gatilho,
                                "dados_memorias": dados_ciclo
                            }

                            # Verifica se a licença esta ativa antes de iniciar a gravação
                            if licenca_ativa.is_set():
                                # Coloca o item na fila com as informações de IP, gatilho e dados das memórias
                                self.fila.put(item)
                            else:
                                log_queue.put(f"{self.plc_ip}  |  Gravação interrompida licença inativa!")

                            self.fim_tempo = time.perf_counter()
                            self.tempo_total = self.fim_tempo - self.inicio_tempo
                
                    # Atualiza o estado anterior do gatilho
                    self.previous_trigger_state = current_trigger_state

                # Aqui: Verifica diretamente se está ligado
                if gatilho_valor is not None:
                    # ===> AQUI ELE VERIFICA SE TEM ALGUM TEMPORIZADOR CONFIGURADO
                    if hasattr(self, "triger") and isinstance(self.triger, (int, float)) and self.triger > 0:
                        if not hasattr(self, "_last_trigger_time"):
                            self._last_trigger_time = time.perf_counter()  # Use time.perf_counter() para precisão de alta resolução

                        # Verifica se o tempo decorrido atingiu o tempo do trigger
                        if time.perf_counter() - self._last_trigger_time >= self.triger:  # Verifica o intervalo de tempo em segundos
                            self.inicio_tempo = time.perf_counter() # Inicia o calculo de tempo gasto
                            if status_conexao:
                                log_queue.put(f"{self.plc_ip}  |  Iniciando gravação automatica CLP Contollogix IP:{self.plc_ip}")
                    

                            # Leitura das memórias especificadas em `mem_list`
                            with self.lock:
                                dados_ciclo = {}  # Dicionário para armazenar os valores do ciclo de gravação
                                for tag in self.mem_list:
                                    try:
                                        valor = self.client.read(tag)  # Lê o valor da tag
                                        valor = valor.value if hasattr(valor, 'value') else valor  # Extrai o valor real
                                        dados_ciclo[tag] = valor  # Adiciona o valor lido ao dicionário
                                    except Exception as e:
                                        log_queue.put((f"{self.plc_ip}  |  Erro ao ler tag {tag}: {str(e)}", "red"))
                                        dados_ciclo[tag] = None  # Caso não consiga ler, adiciona None
                                # Insere os valores do ciclo completo na fila como um único item (dicionário)
                                item = {
                                    "clp_ip": self.plc_ip,
                                    "gatilho": self.gatilho,
                                    "dados_memorias": dados_ciclo
                                }

                                # Verifica se a licença esta ativa antes de iniciar a gravação
                                if licenca_ativa.is_set():
                                    # Coloca o item na fila com as informações de IP, gatilho e dados das memórias
                                    self.fila.put(item)
                                else:
                                    log_queue.put(f"{self.plc_ip}  |  Gravação interrompida licença inativa!")

                                self.fim_tempo = time.perf_counter()
                                self.tempo_total = self.fim_tempo - self.inicio_tempo

                        # Atualiza o tempo do último trigger
                        self._last_trigger_time = time.perf_counter()


            
            except Exception as ex:
                if status_conexao:
                    log_queue.put((f"{self.plc_ip}  |  Erro de Conexão - CLP ControlLogix IP:{self.plc_ip} - {ex}", "red"))
                self.connected = False  # Marca como desconectado



    def parar(self):
        self.running = False
        log_queue.put(f"{self.plc_ip}  |  Parando CLP Controllogix...")
        if self.client:
            self.client.close()

"""



class CLPMQTT:
    def __init__(self, broker_address, notificacao_config=None, mem_list=None, gatilho=None, triger=None, db_config=None, calculos=None, mqtt_config_acesso=None, local_gravacao=None):
        """
        Inicializa a classe com as configurações do broker MQTT e parâmetros de memória e gatilho.
        """
        self.notificacao_config = notificacao_config or {}
        self.broker_address = broker_address  # Endereço do broker MQTT
        self.plc_ip = broker_address  # Endereço do broker MQTT
        self.mem_list = mem_list if mem_list is not None else []  # Lista de tópicos de memória
        self.gatilho = gatilho  # Tópico do gatilho
        self.calculos = calculos if calculos is not None else {}
        self.local_gravacao = local_gravacao if local_gravacao is not None else {}
        self.configuracao_mqtt = mqtt_config_acesso
        self.triger = float(triger) if isinstance(triger, (int, float)) and triger > 0 else 0 

        # Variavel de licença global
        global licenca_ativa
        self.licenca_ativa = licenca_ativa

        # ✅ Verificação avançada do db_config
        if isinstance(db_config, dict):
            required_keys = {'server', 'database', 'username', 'password'}
            if required_keys.issubset(db_config):
                self.db_config = db_config
                self.sql_conexao = ConexaoSQLPersistente(self.db_config)
            else:
                log_queue.put(f"{self.plc_ip}  |  [INFO] Dados de acesso SQL incompletos. SQL desabilitado.")
                self.db_config = None
                self.sql_conexao = None
        else:
            self.db_config = None
            self.sql_conexao = None



        # Estado inicial do gatilho
        self.estado_gatilho_anterior = 1  # Estado anterior do gatilho (0 = desativado, 1 = ativado)
        self.lock = Lock()  # Trava para evitar condições de corrida

        # Filas para processamento de dados
        self.fila = Queue()  # Fila principal para leitura de dados
        self.fila_sql = Queue()  # Fila de falhas para SQL
        self.fila_excel = Queue()  # Fila de falhas para Excel
        self.fila_mqtt = Queue()  # Fila de falhas para mqtt

        # controle de print de logs evitar multiplos
        self.falha_excel = False
        self.falha_sql = False

        # Dicionário para armazenar os valores das memórias
        self.memories = {}  # Armazena os valores atualizados dos tópicos de memória
        self.running = True  # Controla o loop principal

        # Cliente MQTT
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.erro_conectar = False

    def conectar(self):
        """
        Conecta ao broker MQTT e inicia o loop do cliente.
        """
        try:
            self.client.connect(self.broker_address, 1883, 60)  # Conecta ao broker na porta 1883
            self.client.loop_start()  # Inicia o loop para processar mensagens
            log_queue.put((f"{self.broker_address}  |  Conectado ao broker MQTT", "green"))  # Log de sucesso
            self.erro_conectar = False
        except Exception as e:
            if not self.erro_conectar:
                log_queue.put((f"{self.broker_address}  |  Erro ao conectar ao broker MQTT: {e}", "red"))
                self.erro_conectar = True

    def on_connect(self, client, userdata, flags, rc):
        """
        Callback quando a conexão é estabelecida.
        """
        if rc == 0:
            log_queue.put((f"{self.broker_address}  |  Conexão MQTT bem-sucedida.", "green"))
            self.inscrever_topicos()  # Inscreve-se nos tópicos após a conexão
        else:
            log_queue.put((f"{self.broker_address}  |  Falha na conexão MQTT. Código: {rc}", "red"))

    def inscrever_topicos(self):
        """
        Inscreve-se nos tópicos de memória e gatilho.
        """
        try:
            # Inscreve-se no tópico do gatilho
            if self.gatilho:
                self.client.subscribe(self.gatilho)
                log_queue.put((f"{self.broker_address}  |  Inscrito no tópico de gatilho >>>> {self.gatilho}", "blue"))
                # Reseta o gatilho enviando 0 para o tópico
                self.enviar_valor_gatilho(0)

            # Inscreve-se nos tópicos de memória
            for topico in self.mem_list:
                self.client.subscribe(topico)
                log_queue.put((f"{self.broker_address}  |  Inscrito no tópico de memória: {topico}", "blue"))
        except Exception as e:
            log_queue.put((f"{self.broker_address}  |  Erro ao inscrever nos tópicos: {e}", "red"))

    def on_message(self, client, userdata, msg):
        """
        Callback para processar mensagens recebidas.
        """
        try:
            topic = msg.topic
            payload = msg.payload.decode('utf-8')  # Converte o payload para string

            # Verifica se a mensagem é do tópico de gatilho
            if topic == self.gatilho:
                self.processar_gatilho(payload)
            elif topic in self.mem_list:
                self.processar_memoria(topic, payload)
                
        except Exception as e:
            log_queue.put((f"{self.broker_address}  |  Erro ao processar a mensagem: {e}", "red"))

    def processar_memoria(self, topico, valor):
        """
        Processa os dados das memórias recebidas.
        """
        try:
            """
            Função para identificar o tipo do valor e convertê-lo para gravação correta.
            Retorna:
                - NULL se vazio
                - INT se número inteiro
                - FLOAT se número decimal
                - STRING se misturado ou texto puro
            """
            if isinstance(valor, str):  # Garante que está recebendo uma string
                valor = valor.strip()  # Remove espaços em branco
                
                # 1. Verifica se está vazio
                if valor == "":
                    valor = "NULL"

                # 2. Verifica se é Inteiro (números sem ponto ou vírgula)
                elif valor.isdigit():  
                    valor = int(valor)  # Converte para inteiro

                # 3. Verifica se é Float (com ponto ou vírgula)
                else:
                    try:
                        valor = float(valor.replace(",", "."))  # Converte para float (aceita ',' ou '.')
                    except ValueError:
                        valor = str(valor)  # Se não for nem int nem float, mantém como string


            with self.lock:
                self.memories[topico] = valor  # Atualiza o valor no dicionário de memórias
                print(f"{self.broker_address}  |  Memória atualizada: {topico} = {valor}")
        except Exception as e:
            log_queue.put((f"{self.broker_address}  |  Erro ao processar memória: {e}", "red"))

    def processar_gatilho(self, valor):
        """
        Processa o gatilho e inicia gravações se houver uma borda de subida.
        """
        try:
            valor = int(valor)  # Converte o valor do gatilho para inteiro
            if valor != 0 and self.estado_gatilho_anterior == 0:  # Detecta borda de subida
                self.inicio_tempo = time.perf_counter() # Inicia o calculo de tempo gasto
                if status_conexao:
                    pass
                    #log_queue.put((f"Iniciando gravação Mqtt Address:{self.broker_address} - Gatilho:{self.gatilho}...", "green"))

                # Lê todas as memórias da lista, mesmo que não tenham sido atualizadas
                dados_memorias = {}
                for topico in self.mem_list:
                    dados_memorias[topico] = self.memories.get(topico, 0)  # Usa 0 como valor padrão

                # Cria o pacote com os dados
                item = {
                    "Address": self.broker_address,
                    "gatilho": self.gatilho,
                    "dados_memorias": dados_memorias
                }

                # Verifica se a licença esta ativa antes de iniciar a gravação
                if licenca_ativa.is_set():
                    # Coloca o item na fila com as informações de IP, gatilho e dados das memórias
                    self.fila.put(item)
                else:
                    log_queue.put(f"{self.plc_ip}  |  Gravação interrompida licença inativa!")


                self.fim_tempo = time.perf_counter()
                self.tempo_total = self.fim_tempo - self.inicio_tempo

                # Reseta o gatilho enviando 0 para o tópico
                self.enviar_valor_gatilho(0)

            # Atualiza o estado anterior do gatilho
            self.estado_gatilho_anterior = valor

        except Exception as e:
            log_queue.put((f"{self.broker_address}  |  Erro ao processar gatilho: {e}", "red"))

    def enviar_valor_gatilho(self, valor):
        """
        Envia o valor para o tópico do gatilho para alterar seu estado.
        """
        try:
            self.client.publish(self.gatilho, valor)
        except Exception as e:
            log_queue.put((f"{self.broker_address}  |  Erro ao enviar valor para gatilho: {e}", "red"))

    def ler_memorias(self):
        """
        Loop contínuo para monitorar e atualizar os valores das memórias.
        """
        while self.running:
            try:
                with self.lock:
                    # Não faz nada aqui, pois as memórias já estão sendo atualizadas em tempo real pelo callback
                    pass

                # ===> AQUI ELE VERIFICA SE TEM ALGUM TEMPORIZADOR CONFIGURADO
                if hasattr(self, "triger") and isinstance(self.triger, (int, float)) and self.triger > 0:
                    if not hasattr(self, "_last_trigger_time"):
                        self._last_trigger_time = time.perf_counter()  # Usando time.perf_counter() para alta precisão

                    # Verifica se o tempo decorrido atingiu o tempo do trigger
                    if time.perf_counter() - self._last_trigger_time >= self.triger:
                        self.inicio_tempo = time.perf_counter() # Inicia o calculo de tempo gasto
                        self.disparar_fila_triger()  # 🔥🔥 Aqui ele dispara o pacote automático
                        self._last_trigger_time = time.perf_counter()  # Atualiza o tempo de disparo

            except Exception as e:
                log_queue.put((f"{self.broker_address}  |  Erro no loop de leitura: {e}", "red"))
            

    def disparar_fila_triger(self):
        """
        Dispara a gravação automática para a fila.
        """
        if self.client.is_connected():
            try:
                dados_memorias = {}
                for topico in self.mem_list:
                    with self.lock:
                        dados_memorias[topico] = self.memories.get(topico, 0)

                item = {
                    "Address": self.broker_address,
                    "gatilho": "TEMPO",
                    "dados_memorias": dados_memorias
                }

                # Verifica se a licença esta ativa antes de iniciar a gravação
                if licenca_ativa.is_set():
                    # Coloca o item na fila com as informações de IP, gatilho e dados das memórias
                    self.fila.put(item)
                else:
                    log_queue.put(f"{self.plc_ip}  |  Gravação interrompida licença inativa!")

                self.fim_tempo = time.perf_counter()
                self.tempo_total = self.fim_tempo - self.inicio_tempo

                print(f"{self.broker_address}  |  item na fila:{item}...")

            except Exception as e:
                log_queue.put((f"{self.broker_address}  |  Erro ao disparar fila automática Address:{self.broker_address} - {e}", "red"))

    def parar(self):
        """
        Encerra a conexão MQTT.
        """
        self.running = False
        self.client.loop_stop()
        self.client.disconnect()
        log_queue.put((f"{self.broker_address}  |  Conexão MQTT encerrada.", "red"))


class InLogicService(win32serviceutil.ServiceFramework):
    _svc_name_ = "InLogicService"
    _svc_display_name_ = "InLogic Service"
    _svc_description_ = "Serviço de comunicação da In Logic - Software"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        # Informa ao sistema que o serviço está parando
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        try:
            # Informa ao sistema que o serviço está iniciando
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING, waitHint=30000)

            servicemanager.LogInfoMsg("InLogicService | Iniciando...")

            # Marca o serviço como "rodando"
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            # Executa a lógica principal do serviço
            self.executar()

        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            erro = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            servicemanager.LogErrorMsg(f"InLogicService | Erro fatal:\n{erro}")
            raise

    def executar(self):
        try:
            # ⛔️ Evita duplicação no início || Desabilitado
            #evitar_execucao_duplicada()

            # ✅ Inicia a thread de background uma única vez
            Thread(target=run_background, name="ThreadLogs", daemon=True).start()

            logger.info("SISTEMA  |  Iniciando InLogic Service...")

            while self.running:
                time.sleep(5)  # mantém vivo, leve e sem sobrecarga

        except Exception as e:
            erro = "".join(traceback.format_exception(*sys.exc_info()))
            servicemanager.LogErrorMsg(f"InLogicService | Erro na execução:\n{erro}")
            self.SvcStop()




def gravar_dados_excel(caminho_excel, memories, mem_list):
    if not os.path.exists(caminho_excel):
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "Dados"
        sheet.append(["Timestamp"] + [f"D{mem}" for mem in mem_list])
        workbook.save(caminho_excel)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data_row = [timestamp] + [memories.get(mem, None) for mem in mem_list]

    try:
        workbook = openpyxl.load_workbook(caminho_excel)
        sheet = workbook.active
        sheet.append(data_row)
        workbook.save(caminho_excel)
        #log_queue.put(f"Dados gravados no Excel: {caminho_excel}")
    except Exception as ex:
        raise

def reprocessar_gravar_dados_excel(caminho_excel, memories, mem_list):
    if not os.path.exists(caminho_excel):
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "Dados"
        sheet.append(["Timestamp"] + [f"D{mem}" for mem in mem_list])
        workbook.save(caminho_excel)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data_row = [timestamp] + [memories.get(mem, None) for mem in mem_list]

    try:
        workbook = openpyxl.load_workbook(caminho_excel)
        sheet = workbook.active
        sheet.append(data_row)
        workbook.save(caminho_excel)
    except Exception as ex:
        raise

def gravar_dados_sql(memories, tabela_sql, mem_list, db_config=None, clp=None):
    """
    Grava dados no SQL com cache de colunas/INSERT, conexão persistente e benchmark.
    """
    origem = clp.plc_ip if clp else "SQL"
    try:
        timestamp_inicio = time.perf_counter()
        timestamp = datetime.now()
        valores = [timestamp] + [memories.get(mem, None) for mem in mem_list]

        if clp and clp.sql_conexao:
            # ✅ Cache das colunas da tabela
            if not hasattr(clp, "_colunas_sql"):
                clp._colunas_sql = clp.sql_conexao.obter_colunas(tabela_sql)

            # ✅ Completa valores com None se faltar
            valores += [None] * (len(clp._colunas_sql) - len(valores))

            # ✅ Cache do comando INSERT
            if not hasattr(clp, "_insert_sql_cache"):
                placeholders = ", ".join(["?"] * len(clp._colunas_sql))
                clp._insert_sql_cache = f"INSERT INTO {tabela_sql} VALUES ({placeholders})"

            clp.sql_conexao.executar(clp._insert_sql_cache, valores)

        elif db_config:
            # 🔁 Conexão temporária (fallback)
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={db_config['server']};"
                f"DATABASE={db_config['database']};"
                f"UID={db_config['username']};"
                f"PWD={db_config['password']};"
            )
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {tabela_sql} WHERE 1=0")
            colunas = [col[0] for col in cursor.description]
            valores += [None] * (len(colunas) - len(valores))
            sql = f"INSERT INTO {tabela_sql} VALUES ({', '.join(['?'] * len(colunas))})"
            cursor.execute(sql, valores)
            conn.commit()
            cursor.close()
            conn.close()
        else:
            log_queue.put(f"{origem}  |  [ERRO] Nenhuma conexão SQL disponível.")
            return

        # ⏱️ Benchmark
        tempo_total_ms = (time.perf_counter() - timestamp_inicio) * 1000
        #log_queue.put(f"{origem}  |  [SQL] Gravação concluída em {tempo_total_ms:.2f} ms")

    except Exception as ex:
        log_queue.put(f"{origem}  |  [ERRO] Falha ao gravar SQL: {ex}")
        raise

def reprocessar_gravar_dados_sql(*args, **kwargs):
    """
    Reprocessa gravação reaproveitando lógica principal de gravação SQL.
    """
    return gravar_dados_sql(*args, **kwargs)

def gravar_dados_mqtt(dados, configuracao_mqtt):
    """
    Função para publicar dados via MQTT sem o uso de threads.
    Executa a conexão, publicação e desconexão diretamente no fluxo principal.

    Parâmetros:
        dados (dict): Dicionário com os tópicos e valores a serem publicados.
        configuracao_mqtt (dict): Configuração MQTT contendo:
            - broker_address (str): Endereço do broker MQTT
            - porta (int): Porta do broker (padrão: 1883)
            - client_id (str): Identificação do cliente MQTT (única por conexão)
            - username (str): Nome de usuário (se necessário)
            - password (str): Senha (se necessário)
            - keep_alive (int): Tempo de keep-alive da conexão MQTT (padrão: 60s)
            - qos (int): Qualidade de Serviço (0, 1 ou 2)
        log_queue (queue.Queue): Fila para enviar logs para a interface gráfica.

    Lança:
        Exception: Se houver erro na publicação, será lançado para captura externa.
    """
    # Extrair configurações
    broker = configuracao_mqtt.get('broker_address', '')
    porta = configuracao_mqtt.get('porta', 1883)
    client_id = f"{configuracao_mqtt.get('client_id', 'client')}-{uuid.uuid4()}"
    username = configuracao_mqtt.get('username', '').strip()
    password = configuracao_mqtt.get('password', '').strip()
    keep_alive = configuracao_mqtt.get('keep_alive', 60)
    qos = configuracao_mqtt.get('qos', 1)

    if not broker:
        raise ValueError("Endereço do broker MQTT não informado.")

    try:
        # Criar cliente MQTT
        client = mqtt_client.Client(client_id=client_id, clean_session=True)

        # Configurar autenticação, se necessário
        if username and password:
            client.username_pw_set(username, password)

        # Callback para conexão
        def on_connect(c, u, f, rc):
            if rc == 0:
                if status_conexao:
                    log_queue.put((f"[MQTT {client_id}] ✅ Conectado ao broker {broker}:{porta}", "green"))
            else:
                log_queue.put((f"[MQTT {client_id}] ❌ Erro na conexão. Código: {rc}", "red"))

        client.on_connect = on_connect

        # Conectar ao broker
        if status_conexao:
            log_queue.put(f"[MQTT {client_id}] 🔄 Conectando ao broker {broker}:{porta}...")
        client.connect(broker, porta, keep_alive)
        client.loop_start()

        # Aguardar conexão
        timeout = 10
        while not client.is_connected() and timeout > 0:
            time.sleep(1)
            timeout -= 1

        if not client.is_connected():
            raise ConnectionError(f"[MQTT {client_id}] ❌ Falha ao conectar ao broker {broker}:{porta}")

        # Publicar mensagens nos tópicos
        for topico, valor in dados.items():
            topico_str = str(topico)
            valor_str = str(valor)
            if status_conexao:
                log_queue.put((f"[MQTT {client_id}] 📢 Publicando -> Tópico: {topico_str} | Valor: {valor_str}", "blue"))
            resultado = client.publish(topico_str, valor_str, qos=qos)

            # Aguardar confirmação de publicação
            resultado.wait_for_publish()
            if resultado.is_published():
                log_queue.put((f"ATIVO:{broker}|{topico_str} ✅ Dados gravados MQTT com sucesso...", "green"))
            else:
                log_queue.put((f"[MQTT {client_id}] ❌ Falha ao publicar no tópico: {topico_str}", "red"))

        # Encerrar conexão
        client.loop_stop()
        client.disconnect()
        if status_conexao:
            log_queue.put((f"[MQTT {client_id}] 🔌 Desconectado do broker.", "blue"))

    except Exception as e:
        log_queue.put((f"[MQTT {client_id}] 🔥 ERRO na publicação MQTT: {str(e)}", "red"))
        raise  # Relança a exceção para tratamento externo


def gerenciar_excel_e_sql(clp, diretorio, tabela_sql, db_config):
    log_queue.put(f"{clp.plc_ip}  |  SISTEMA  | Iniciando sistema avançado de gerenciamento de eventos...")
    global status_conexao

    LIMITE_FILA_FALHAS = 500

    if not clp.calculos:
        pass

    # Logs de inicialização
    if clp.local_gravacao.get("mqtt") is True:
        log_queue.put(f"{clp.plc_ip}  |  [EVENTOS] Gravação via MQTT ativa")
    if clp.local_gravacao.get("excel") is True:
        log_queue.put(f"{clp.plc_ip}  |  [EVENTOS] Gravação via EXCEL ativa")
    if clp.local_gravacao.get("sql") is True:
        log_queue.put(f"{clp.plc_ip}  |  [EVENTOS] Gravação via SQL ativa")
    if clp.local_gravacao.get("notificacao") is True:
        log_queue.put(f"{clp.plc_ip}  |  [EVENTOS] Envio de Notificação ativa")        
    if not clp.local_gravacao or all(valor in [None, False] for valor in clp.local_gravacao.values()):
        log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - [ERRO] Nenhum evento configurado", "red"))

    while clp.running:
        data_atual = datetime.now().strftime('%d%m%Y')
        caminho_excel = os.path.join(diretorio, f"DADOS_P3_{tabela_sql}_{data_atual}.xlsx")

        if not clp.fila.empty():
            tempo_inicial = time.perf_counter()
            item = clp.fila.get()


            dados = item["dados_memorias"]

            # Funções paralelas com tratamento individual
            def tarefa_mqtt():
                try:
                    gravar_dados_mqtt(dados, clp.configuracao_mqtt)
                    tempo_final = time.perf_counter() - tempo_inicial
                    tempo = clp.tempo_total + tempo_final
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  |  {clp.gatilho} | PROCESSAMENTO:{clp.tempo_total:.3f}s | MQTT:{tempo_final:.3f}s | T_total:{tempo:.3f}s  - MQTT gravado...", "green"))
                except Exception as ex:
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  | [ERRO] Falha MQTT: {ex}", "red"))

            def tarefa_excel():
                try:
                    gravar_dados_excel(caminho_excel, dados, clp.mem_list)
                    tempo_final = time.perf_counter() - tempo_inicial
                    tempo = clp.tempo_total + tempo_final
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  |  {clp.gatilho} | PROCESSAMENTO:{clp.tempo_total:.3f}s | EXCEL:{tempo_final:.3f}s | T_total:{tempo:.3f}s  - EXCEL gravado...", "green"))
                except Exception as ex:
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  | [ERRO] Falha Excel: {ex}", "red"))
                    clp.fila_excel.put(dados)

            def tarefa_sql():
                try:
                    gravar_dados_sql(dados, tabela_sql, clp.mem_list, db_config)
                    tempo_final = time.perf_counter() - tempo_inicial
                    tempo = clp.tempo_total + tempo_final
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  |  {clp.gatilho} | PROCESSAMENTO:{clp.tempo_total:.3f}s | SQL:{tempo_final:.3f}s | T_total:{tempo:.3f}s  - SQL gravado...", "green"))
                except Exception as ex:
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  | [ERRO] Falha SQL: {ex}", "red"))
                    clp.fila_sql.put(dados)

            def tarefa_notificacao():
                try:
                    c = clp.notificacao_config
                    status, resp = enviar_notificacao_fcm(
                        c["topico"],
                        c["titulo"],
                        c["mensagem"]
                    )
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  |  Notificação enviada com seucesso! - Status:{status}", "green"))
                except Exception as ex:
                    log_queue.put((f" [EVENTO] | {clp.plc_ip}  | [ERRO] Falha Notificação: {ex}", "red"))


            # Execução concorrente
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                if clp.local_gravacao.get("mqtt"): futures.append(executor.submit(tarefa_mqtt))
                if clp.local_gravacao.get("excel"): futures.append(executor.submit(tarefa_excel))
                if clp.local_gravacao.get("sql"): futures.append(executor.submit(tarefa_sql))
                if clp.local_gravacao.get("notificacao"): futures.append(executor.submit(tarefa_notificacao))
                for future in as_completed(futures):
                    future.result()

        # Reprocessa falhas do Excel
        if not clp.fila_excel.empty():
            dados_falha_excel = clp.fila_excel.queue[0]
            try:
                reprocessar_gravar_dados_excel(caminho_excel, dados_falha_excel, clp.mem_list)
                log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Reprocessamento Excel OK", "green"))
                clp.fila_excel.get()
                clp.falha_excel = False
            except Exception as ex:
                if not clp.falha_excel:
                    log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Falha reprocessamento Excel: {ex}", "red"))
                    clp.falha_excel = True

        # Reprocessa falhas do SQL
        if not clp.fila_sql.empty():
            dados_falha_sql = clp.fila_sql.queue[0]
            try:
                reprocessar_gravar_dados_sql(dados_falha_sql, tabela_sql, clp.mem_list, db_config)
                log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Reprocessamento SQL OK", "green"))
                clp.fila_sql.get()
                clp.falha_sql = False
            except Exception as ex:
                if not clp.falha_sql:
                    log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Falha reprocessamento SQL: {ex}", "red"))
                    clp.falha_sql = True

        # Limpeza fila de falha SQL
        if clp.fila_sql.qsize() > LIMITE_FILA_FALHAS:
            try:
                clp.fila_sql.get()
                log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  [Monitoramento] SQL > {LIMITE_FILA_FALHAS}, item removido", "red"))
                clp.falha_sql = False
            except Exception as ex:
                if not clp.falha_sql:
                    log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Erro ao limpar fila SQL: {ex}", "red"))
                    clp.falha_sql = True
        # Limpeza fila de falha Excel
        if clp.fila_excel.qsize() > LIMITE_FILA_FALHAS:
            try:
                clp.fila_excel.get()
                log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  [Monitoramento] EXCEL > {LIMITE_FILA_FALHAS}, item removido", "red"))
                clp.falha_excel = False
            except Exception as ex:
                if not clp.falha_excel:
                    log_queue.put((f"{clp.plc_ip}  |  [EVENTOS] - |  Erro ao limpar fila Excel: {ex}", "red"))
                    clp.falha_excel = True


def enviar_notificacao_fcm(topico, titulo, mensagem):
    global service_account_info
    message = {
        "message": {
            "topic": topico,
            "notification": {
                "title": titulo,
                "body": mensagem
            }
        }
    }

    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_json:
        json.dump(service_account_info, tmp_json)
        tmp_json.flush()

        credentials = service_account.Credentials.from_service_account_file(
            tmp_json.name,
            scopes=["https://www.googleapis.com/auth/firebase.messaging"]
        )
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)
        access_token = credentials.token

    os.unlink(tmp_json.name)

    PROJECT_ID = service_account_info["project_id"]
    url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; UTF-8",
    }
    response = requests.post(url, headers=headers, data=json.dumps(message))
    return response.status_code, response.text


def criptografar_json(dados_dict):
    dados_bytes = json.dumps(dados_dict).encode('utf-8')
    iv = get_random_bytes(16)
    cipher = AES.new(CHAVE_SECRETA, AES.MODE_CBC, iv)
    dados_encriptados = cipher.encrypt(pad(dados_bytes, AES.block_size))
    return b64encode(iv + dados_encriptados).decode('utf-8')

def descriptografar_json(conteudo_criptografado):
    dados = b64decode(conteudo_criptografado)
    iv = dados[:16]
    dados_encriptados = dados[16:]
    cipher = AES.new(CHAVE_SECRETA, AES.MODE_CBC, iv)
    dados_descriptografados = unpad(cipher.decrypt(dados_encriptados), AES.block_size)
    return json.loads(dados_descriptografados.decode('utf-8'))

def verificar_ou_criar_pasta_imagens():
    """
    Verifica se a pasta BASE_IMAGES existe.
    Caso não exista, ela será criada.
    """
    try:
        if not os.path.exists(BASE_IMAGES):
            os.makedirs(BASE_IMAGES)
            log_queue.put(f"  SISTEMA   |  Pasta IMG criada: {BASE_IMAGES}")
        else:
            log_queue.put(f"  SISTEMA   |  Pasta IMG já existe: {BASE_IMAGES}")
    except Exception as e:
        log_queue.put(f"  SISTEMA   |  [ERRO] Falha ao verificar/criar pasta: {e}")

def verificar_ou_criar_configuracao():
    """
    Verifica/cria a pasta e o arquivo conf_inlogic.cfg com dados criptografados.
    """
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(CONFIG_PATH)
        verificar_ou_criar_pasta_imagens()

    if not os.path.exists(CONFIG_PATH1):
        estrutura_generica = {
            "grupos": [
                {
                    "grupo": "GRUPO_GENÉRICO_MODIFICAVEL",
                    "plc_ip": "192.168.2.1",
                    "tipo_clp": "delta",
                    "diretorio": "C:\\CAMINHO\\GENERICO\\MODIFICAVEL",
                    "mem_list": [22031, 22028],
                    "gatilho": 1,
                    "intervalo_temporizador": 0,
                    "tabela_sql": "TABELA_GENÉRICA_MODIFICAVEL",
                    "db_config": {
                        "server": "GENÉRICO_MODIFICAVEL",
                        "database": "GENÉRICO_V001_MODIFICAVEL",
                        "username": "SEU_NOME_MODIFICAVEL",
                        "password": "SUA_SENHA"
                    },
                    "calculos": {},

                    "notificacao": {
                        "topico": "teste",
                        "titulo": "ATENÇÃO",
                        "mensagem": "Alerta do CLP!"
                    },

                    "ACESSO_MQTT": {
                        "broker_address": "mqtt.exemplo.com",
                        "port": 1883,
                        "client_id": "cliente1234",
                        "username": "usuario_teste",
                        "password": "senha_forte123",
                        "keep_alive": 60,
                        "qos": 1
                    }
                }
            ]
        }

        conteudo_criptografado = criptografar_json(estrutura_generica)
        with open(CONFIG_PATH1, "w") as f:
            f.write(conteudo_criptografado)

def carregar_configuracao():
    """
    Descriptografa e retorna o conteúdo da configuração .cfg
    """
    verificar_ou_criar_configuracao()
    if os.path.exists(CONFIG_PATH1):
        try:
            with open(CONFIG_PATH1, 'r') as f:
                conteudo = f.read()
            return descriptografar_json(conteudo)
        except Exception as e:
            log_queue.put(f"  SISTEMA   |  [ERRO] Ao descriptografar o config: {e}")

    

    return {"grupos": []}


def iniciar_clps():
    """Inicializa e reinicia CLPs se já existirem."""
    global clps_ativos

    # 🔁 Finaliza os CLPs ativos anteriores, se houver
    if clps_ativos:
        log_queue.put(("SISTEMA  |  ♻️ Finalizando Ativos anteriores...", "yellow"))
        for clp in clps_ativos:
            try:
                clp.parar()  # método parar() precisa existir em cada classe CLP
            except Exception as e:
                log_queue.put((f"ERRO  |  Falha ao parar Ativo {getattr(clp, 'plc_ip', 'sem IP')}: {e}", "red"))
        clps_ativos.clear()

    clps = []
    config = carregar_configuracao()
    log_queue.put(("SISTEMA  |  🔄 Iniciando Ativos no sistema...", "blue"))

    clp_count = 0  # Contador para CLPs ativos

    for grupo in config.get("grupos", []):
        tipo_clp = grupo.get("tipo_clp")
        log_queue.put((f"SISTEMA  |  Iniciando driver {tipo_clp}...", "blue"))

        if tipo_clp == "delta":
            clp = CLPModbus(
                grupo["plc_ip"], 
                mem_list=grupo["mem_list"], 
                gatilho=grupo.get("gatilho", 1000), 
                triger=grupo.get("intervalo_temporizador"),
                db_config=grupo.get("db_config"),
                calculos=grupo.get("calculos", {}),
                mqtt_config_acesso=grupo.get("ACESSO_MQTT", {}),
                local_gravacao=grupo.get("local_gravacao", {}),
                notificacao_config=grupo.get("notificacao", {}),
                manager=manager
            )

        elif tipo_clp == "controllogix":
            clp = CLPControlLogix(
                grupo["plc_ip"], 
                mem_list=grupo["mem_list"], 
                gatilho=grupo.get("gatilho", "inlogic"),
                triger=grupo.get("intervalo_temporizador"), 
                db_config=grupo.get("db_config"),
                calculos=grupo.get("calculos", {}),
                mqtt_config_acesso=grupo.get("ACESSO_MQTT", {}),
                local_gravacao=grupo.get("local_gravacao", {}),
                notificacao_config=grupo.get("notificacao", {})
            )

        elif tipo_clp == "mqtt":
            clp = CLPMQTT(
                broker_address=grupo["plc_ip"], 
                mem_list=grupo["mem_list"], 
                gatilho=grupo.get("gatilho", "inlogic"),
                triger=grupo.get("intervalo_temporizador"), 
                db_config=grupo.get("db_config"),
                calculos=grupo.get("calculos", {}),
                mqtt_config_acesso=grupo.get("ACESSO_MQTT", {}),
                local_gravacao=grupo.get("local_gravacao", {}),
                notificacao_config=grupo.get("notificacao", {})
            )

        else:
            log_queue.put((f"AVISO  |  Tipo de Ativo desconhecido: {tipo_clp}", "orange"))
            continue

        clps.append(clp)
        clp_count += 1

        # Threads de operação
        Thread(target=clp.conectar, name=f"CLP-{clp.plc_ip}-Conectar").start()
        Thread(target=clp.ler_memorias, name=f"CLP-{clp.plc_ip}-LerMemorias").start()
        Thread(target=gerenciar_excel_e_sql, args=(clp, grupo["diretorio"], grupo["tabela_sql"], grupo["db_config"])).start()

    log_queue.put((f"SISTEMA  |  ✅ Total de ativos iniciado no sistema >> {clp_count}", "green"))
    clps_ativos = clps  # Atualiza CLPs ativos
    return clps


def processar_logs():
    global pipe_handle  # 🔄 Acesso à variável global do pipe

    while True:
        try:
            item = log_queue.get(timeout=1)

            if isinstance(item, tuple):
                mensagem, cor = item
            else:
                mensagem = str(item)

            # 📄 Grava no logger rotativo
            logger.info(mensagem)
            handler.flush()

            # 🔁 Armazena no buffer circular (últimos logs)
            log_buffer.append(mensagem)

            # 📤 Envia via pipe, se válido
            if pipe_handle:
                try:
                    win32file.WriteFile(pipe_handle, f"{mensagem}\n".encode("utf-8"))
                except Exception as e:
                    logger.warning(f"⚠️ Falha ao enviar log via pipe: {e}")
                    pipe_handle = None  # 🔌 Reseta o pipe se der erro

        except Empty:
            continue
        except Exception as e:
            logger.error(f"❌ Erro crítico ao processar log: {e}")



def run_background():
    try:
        servicemanager.LogInfoMsg("INLOGIC | Entrando no run_background")
        Thread(target=processar_logs, name="ThreadLogs", daemon=True).start()
        threading.Thread(target=inicializar_clps_seguro, daemon=True).start()
        threading.Thread(target=pipe_server_loop, daemon=True).start()
        threading.Thread(target=thread_verificacao_licenca, daemon=True).start()


    except Exception as e:
        servicemanager.LogInfoMsg("INLOGIC | Erro na execução em background")
        logger.exception("Erro na execução em background")

def inicializar_clps_seguro():
    global clps
    try:
        logger.info(" INLOGIC  |  Iniciando driver")
        clps = iniciar_clps()
    except Exception as e:
        servicemanager.LogInfoMsg(" INLOGIC | Erro ao iniciar CLPs")
        logger.exception(" INLOGIC | Erro ao iniciar CLPs")

def pipe_server_loop():
    global running
    import win32pipe, win32file, pywintypes
    pipe_name = r'\\.\pipe\InlogicPipeCmd'

    while running:
        handle = None
        try:
            # Cria um novo Named Pipe
            handle = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 
                65536, 65536,
                0, None
            )

            logger.info("SISTEMA  |  Aguardando conexão do cliente no Named Pipe (Comandos)...")

            # Aguarda a conexão do cliente
            win32pipe.ConnectNamedPipe(handle, None)

            logger.info("SISTEMA  |  ✅ Cliente conectado ao Named Pipe (Comandos)")

            while running:
                try:
                    # Lê o comando do cliente
                    resp = win32file.ReadFile(handle, 64*1024)
                    comando = resp[1].decode().strip()

                    # Processa os comandos recebidos
                    if comando == "iniciar_clps":
                        log_queue.put(("SISTEMA  |  🔁 Reiniciando CLPs via Named Pipe (Comandos)", "orange"))
                        threading.Thread(target=inicializar_clps_seguro, daemon=True).start()

                    elif comando == "parar_clps":
                        log_queue.put(("SISTEMA  |  Parando todos os CLPs...", "orange"))
                        for clp in clps_ativos:
                            try:
                                clp.parar()
                            except Exception as e:
                                log_queue.put((f"SISTEMA  |  ERRO ao parar CLP {clp.plc_ip}: {e}", "red"))
                        clps_ativos.clear()


                    elif comando == "status":
                        status = "\n".join([
                            f"{clps_ativos.plc_ip} - {'🟢' if clps_ativos.running else '🔴'}"
                            for clps_ativos in clps
                        ])
                        win32file.WriteFile(handle, status.encode("utf-8"))

                    elif comando == "reload_config":
                        log_queue.put(("CONFIG  | 🔁 Configuração recarregada Testando ...", "blue"))

                    else:
                        log_queue.put((f"COMANDO  |  🚫 Comando inválido: {comando}", "red"))

                    win32file.WriteFile(handle, f"Comando executado: {comando}".encode())

                except Exception as e:
                    logger.error(f"❌ Erro ao processar o comando: {e}")
                    break

        except pywintypes.error as e:
            logger.error(f"SISTEMA  |  Erro no Named Pipe: {e}")
        
        except Exception as e:
            logger.error(f"SISTEMA  |  Erro inesperado no Named Pipe: {e}")

        finally:
            try:
                if handle and handle != win32file.INVALID_HANDLE_VALUE:
                    win32file.CloseHandle(handle)
                    logger.info("SISTEMA  |  🧹 Handle do Named Pipe fechado (Comandos)")
            except Exception as cleanup_exception:
                logger.error(f"SISTEMA  |  Erro ao fechar o Named Pipe(Comandos): {cleanup_exception}")

            # Se o pipe foi fechado ou ocorreu algum erro, aguarda e tenta criar um novo pipe
            if running:
                logger.info("SISTEMA  |  🔄 Tentando reconectar ao cliente (Comandos)... ")
                time.sleep(1)  # Aguardar antes de tentar uma nova conexão

def obter_serial_maquina():
    """Obtém informações únicas do sistema."""
    try:
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            serial = c.Win32_BaseBoard()[0].SerialNumber.strip()
            uuid = c.Win32_ComputerSystemProduct()[0].UUID.strip()
            #print(f"Serial do sistema: {serial}")
            #print(f"UUID do sistema: {uuid}")
            return {"serial": serial, "uuid": uuid}
        finally:
            pythoncom.CoUninitialize()
    except Exception as e:
        print(f"Erro ao obter informações do sistema: {e}")
        return {"serial": "unknown", "uuid": "unknown"}

def verificar_licenca():
    try:
        if not os.path.exists(LICENSE_FILE):
            print("❌ Arquivo de licença não encontrado.")
            log_queue.put(f"  SISTEMA   |  [ERRO] Arquivo de licença não encontrado.")
            licenca_ativa.clear()
            return False

        with open(LICENSE_FILE, "r") as file:
            dados_criptografados = file.read()

        dados_licenca = descriptografar_json(dados_criptografados)
        print(f"🔍 Dados da licença: {dados_licenca}")

        serial_atual = obter_serial_maquina().get("serial", "unknown")
        serial_arquivo = dados_licenca.get("serial", "")
        
        if serial_arquivo == serial_atual:
            print(f"✅ Licença de hardware compativel!")
            log_queue.put(f"  SISTEMA   |  Licença de hardware compativel!")

        if serial_arquivo != serial_atual:
            print(f"⚠️ Serial inválido! Salvo: {serial_arquivo}, Atual: {serial_atual}")
            log_queue.put(f"  SISTEMA   |  ⚠️ Serial inválido! Salvo: {serial_arquivo}, Atual: {serial_atual}")
            licenca_ativa.clear()
            return False

        status = dados_licenca.get("status", "inactive")
        ultima_verificacao = dados_licenca.get("last_checked", "1970-01-01")

        ultima_verificacao_data = datetime.strptime(ultima_verificacao, "%Y-%m-%d")
        dias_restantes = (ultima_verificacao_data + timedelta(days=365) - datetime.now()).days
        print(f"📅 Dias restantes para expiração da licença: {dias_restantes}")
        log_queue.put(f"  SISTEMA   |  📅 Dias restantes para expiração da licença: {dias_restantes}")

        if status != "active" or datetime.now() > ultima_verificacao_data + timedelta(days=365):
            dados_licenca["status"] = "inactive"
            dados_licenca["last_checked"] = datetime.now().strftime("%Y-%m-%d")

            dados_atualizados = criptografar_json(dados_licenca)
            with open(LICENSE_FILE, "w") as file:
                file.write(dados_atualizados)

            print("❌ Licença expirada ou inválida. Status atualizado para inactive.")
            log_queue.put(f"  SISTEMA   |  ❌ Licença expirada ou inválida. Status atualizado para inactive.")
            licenca_ativa.clear()
            return False

        print("✅ Licença válida e ativa.")
        log_queue.put(f"  SISTEMA   |  ✅ Licença válida e ativa!")
        licenca_ativa.set()
        return True

    except Exception as e:
        print(f"🚨 Erro ao verificar licença: {e}")
        log_queue.put(f"  SISTEMA   |  [ERRO] licença: {e}")
        licenca_ativa.clear()
        return False

def thread_verificacao_licenca():
    intervalo = 30 * 24 * 3600  # Intervalo inicial de 30 dias

    while True:
        print(f"🔄 Iniciando verificação da licença em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        log_queue.put(f"  SISTEMA   |  Iniciando verificação da licença em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        ativa = verificar_licenca()

        if ativa:
            intervalo = 30 * 24 * 3600  # Próxima verificação em 30 dias
        else:
            intervalo = 600  # Próxima verificação em 10 minutos

        proxima_verificacao = datetime.now() + timedelta(seconds=intervalo)
        print(f"⏰ Próxima verificação de licença agendada para {proxima_verificacao.strftime('%d/%m/%Y %H:%M:%S')}")
        log_queue.put(f"  SISTEMA   |  Próxima verificação de licença agendada para {proxima_verificacao.strftime('%d/%m/%Y %H:%M:%S')}")

        time.sleep(intervalo)







if __name__ == '__main__':

    freeze_support()  # Necessário no Windows para rodar processos

    from multiprocessing import Manager # Import lib forçar identificação empacotamento
    manager = Manager() # Cria um gerenciador de objetos compartilhados entre principal e processos 

    if True:
        if len(sys.argv) == 1:
            # Se nenhum argumento for passado, registra e inicia o serviço
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(InLogicService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            # Rodar como serviço
            win32serviceutil.HandleCommandLine(InLogicService)

    # Rodar local
    #iniciar_clps()



