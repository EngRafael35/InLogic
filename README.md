# InLogic Software

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Windows Service](https://img.shields.io/badge/Platform-Windows%20Service-blue.svg)
![GUI](https://img.shields.io/badge/Component-Desktop%20GUI-blue.svg)
![Protocols](https://img.shields.io/badge/Protocols-Modbus%20TCP%2C%20Ethernet%2FIP%2C%20MQTT-orange.svg)
![Databases](https://img.shields.io/badge/Database-SQL%20Server-lightgrey.svg)
![Files](https://img.shields.com/badge/File-Excel-green.svg)
![Cloud](https://img.shields.io/badge/Cloud-Firebase%20FCM-yellow.svg)
![License](https://img.shields.io/badge/License-Proprietary-red.svg) <!-- Ou a licença que você usa -->
![Status](https://img.shields.io/badge/Status-Development-orange.svg) <!-- Ou Alpha, Beta, Stable -->


## Visão Geral

O **InLogic Software** é uma solução robusta para automação industrial, focada na aquisição, processamento e gerenciamento de dados de chão de fábrica. O sistema é composto por dois componentes principais que trabalham em conjunto para oferecer monitoramento confiável e controle flexível:

1.  **InLogic Service:** Um serviço Windows leve e resiliente, rodando em segundo plano. Sua função primária é a comunicação direta com dispositivos industriais (CLPs e Brokers MQTT), coleta de dados em tempo real com base em eventos (gatilhos) ou tempo (temporizadores), e a distribuição desses dados para diversos destinos de armazenamento e notificação.
2.  **InLogic Studio:** Uma aplicação desktop com interface gráfica de usuário (GUI), construída com PyQt5. O Studio atua como a central de controle, permitindo ao usuário configurar o Serviço, monitorar sua operação em tempo real (via visualização de logs), controlar o estado do Serviço (iniciar/parar/reiniciar), e gerenciar as licenças de uso. Ele também oferece uma interface de scripting básica para interações diretas com os ativos (leitura/escrita Modbus, consulta/limpeza SQL).

A interação entre o Studio e o Service é realizada através de um **Named Pipe**, garantindo uma comunicação segura e eficiente para controle e monitoramento.

## Arquitetura

O InLogic Software adota uma arquitetura Cliente-Servidor local:

*   **Servidor (InLogic Service):**
    *   Processo de background (Windows Service).
    *   Lógica de comunicação de baixo nível com hardware/protocolos.
    *   Gerenciamento de threads e filas para paralelismo e resiliência.
    *   Execução das ações de gravação (Excel, SQL) e publicação (MQTT, FCM).
    *   Carrega configuração e licença de arquivos locais criptografados.
    *   Exponha um Named Pipe para comunicação.
*   **Cliente (InLogic Studio):**
    *   Aplicação desktop com GUI.
    *   Interface para configuração (lê/escreve `Setup.cfg` via Serviço/Named Pipe).
    *   Visualização de logs em tempo real (recebe do Serviço via Named Pipe).
    *   Controle do Serviço (iniciar/parar/reiniciar/recarregar via Named Pipe).
    *   Interface de Scripting para comandos diretos (pode se conectar *diretamente* aos ativos ou usar o Serviço como proxy, **verificar implementação específica**).
    *   Gerenciamento de Licença (`Authentication.cfg`).

![Diagrama Conceitual - InLogic Software]([OPCIONAL: Adicione um link para um diagrama de arquitetura simples aqui])

## Funcionalidades Detalhadas

### InLogic Service
*   **Serviço Windows Nativo:** Executa de forma autônoma com o sistema operacional, sem necessidade de login do usuário.
*   **Drivers de Comunicação:** Suporte a Modbus TCP (Delta), Ethernet/IP (ControlLogix via `pycomm3`) e MQTT (Subscriber/Publisher).
*   **Estratégias de Aquisição:** Coleta de dados por **Borda de Subida de Gatilho** (monitora um estado booleano/valor) ou por **Intervalo de Tempo** (temporizador).
*   **Destinos de Dados:**
    *   **Excel:** Gravação automática de dados em arquivos `.xlsx`, organizados por data/tabela em diretórios configuráveis.
    *   **SQL Server:** Armazenamento direto em tabelas de banco de dados via ODBC, com reconexão persistente.
    *   **MQTT Publisher:** Publicação dos dados coletados em tópicos MQTT específicos.
    *   **Firebase Cloud Messaging (FCM):** Envio de notificações push para dispositivos Android via API do Firebase Admin SDK (requer configuração do projeto Firebase e tokens de dispositivo).
*   **Gerenciamento de Filas e Threads:** Utiliza filas (`Queue`) e pool de threads (`ThreadPoolExecutor`) para desacoplar a leitura rápida dos dispositivos do processamento (gravação/publicação), mantendo a interface de comunicação responsiva.
*   **Reprocessamento de Falhas:** Inclui lógica para tentar salvar novamente dados que falharam na gravação inicial (atualmente para Excel e SQL).
*   **Configuração Criptografada:** Lê a configuração de operação (`Setup.cfg`) de um arquivo local criptografado para proteger informações sensíveis como IPs, credenciais de banco de dados, etc.
*   **Logging Avançado:** Geração de logs detalhados com níveis de severidade, rotação automática de arquivos e um buffer de logs recentes.
*   **Comunicação Interprocessos:** Usa Named Pipe para receber comandos de controle (start, stop, reload config) e enviar logs em tempo real para o Studio.
*   **Mecanismo de Licença:** Verifica a validade da licença baseada no ID de hardware da máquina e em um arquivo de licença local criptografado (`Authentication.cfg`).

### InLogic Studio
*   **Interface Gráfica (PyQt5):** Ambiente amigável para interação com o usuário.
*   **Configuração Centralizada:** Permite visualizar, adicionar, editar e remover configurações de ativos (CLPs, MQTT), gatilhos, temporizadores, destinos de gravação/publicação (incluindo tokens FCM), cálculos e gerenciar o caminho da chave de serviço Firebase. **O Studio interage com o Serviço para ler/gravar o arquivo `Setup.cfg` criptografado.**
*   **Visualização de Logs:** Recebe logs do Serviço em tempo real via Named Pipe e os exibe na interface para monitoramento instantâneo.
*   **Controle do Serviço:** Botões na GUI para Iniciar, Parar, Reiniciar e Recarregar a Configuração do InLogic Service (envia comandos via Named Pipe).
*   **Interface de Scripting:** Permite executar comandos básicos diretos (LER/ATUALIZAR Modbus, LER/APAGAR SQL) a partir da GUI. **Observação:** A implementação atual do scripting no Studio parece realizar essas operações *diretamente*, em paralelo ao Serviço, e não através dele.
*   **Gerenciamento de Licença:** Interface para exibir informações de licença, possivelmente gerar ID de hardware para solicitação de licença, e aplicar arquivos de licença.
*   **Download/Upload de Arquivos:** Integração com módulos para download/upload de arquivos (Google Drive, BackupManager).

## Requisitos do Sistema

### Para o InLogic Service
*   Sistema Operacional: Windows (Windows 7, 10, 11, Windows Server - x64 recomendado).
*   Python 3.x (Recomenda-se Python 3.7 ou superior). Instalação com a opção "Add Python to PATH".
*   SQL Server ODBC Driver 17 ou superior (Necessário apenas se for utilizar gravação em SQL Server).
*   Acesso de Firewall: Pode ser necessário liberar portas TCP/UDP para comunicação com CLPs (Modbus: 502 TCP; Ethernet/IP: 44818 TCP/UDP) e Brokers MQTT (padrão: 1883 TCP), e acesso HTTPS (porta 443) para servidores Firebase (se usar FCM).
*   Projeto Firebase configurado (Necessário apenas se for utilizar Notificações FCM), incluindo o arquivo JSON da chave de serviço para o Admin SDK.
*   Privilégios de Administrador são **essenciais** para a instalação e gerenciamento do Serviço Windows e para que o Studio possa criar e interagir com o serviço.

### Para o InLogic Studio
*   Sistema Operacional: Windows (Compatível com o Service).
*   Python 3.x e as bibliotecas listadas no `InlogicStudio/requirements.txt` (principalmente PyQt5).
*   Acesso de Rede Local para comunicação via Named Pipe com o Serviço.
*   Privilégios de Administrador são **requeridos** para funcionalidades que interagem com o Serviço Windows (verificar/criar/controlar) e para o acesso a arquivos de configuração e licença protegidos.

## Instalação

### 1. Instalação do InLogic Service

1.  **Clone o Repositório:**
    ```bash
    git clone [URL DO SEU REPOSITÓRIO GITHUB]
    cd [Nome da Pasta do Repositório]
    ```
2.  **Instale as Dependências Python do Serviço:**
    Abra o prompt de comando ou PowerShell **como Administrador** (necessário para instalar o `pywin32` corretamente como serviço). Navegue até a pasta `InlogicService/`.
    ```bash
    pip install -r requirements.txt
    ```
3.  **Instale o SQL Server ODBC Driver (Se Necessário):** Baixe e instale a versão apropriada para sua arquitetura (x64 ou x86) do site da Microsoft.
4.  **Instale o Serviço Windows:** Ainda no prompt de comando **como Administrador**, navegue até a pasta `InlogicService/`.
    ```bash
    python InlogicService.py install
    ```
    Uma mensagem de sucesso deverá aparecer.
5.  **Verifique a Criação das Pastas:** As pastas `C:\In Logic\Setup ativos` e `C:\In Logic\Logs Inlogic` devem ser criadas na raiz do sistema de arquivos.
6.  **Copie a Chave de Serviço Firebase:** Se você estiver usando FCM, copie o arquivo JSON da chave de serviço (`firebase-adminsdk-*.json`) para um local seguro na máquina onde o serviço rodará. **Este arquivo é confidencial e não deve estar no repositório Git!**

### 2. Instalação do InLogic Studio

[Descreva aqui como instalar o InLogic Studio. Ex: Apenas copie a pasta `InlogicStudio/` para o local desejado, execute um instalador, etc.]

1.  **Instale as Dependências Python do Studio:** Abra o prompt de comando (pode não precisar ser Administrador, dependendo da localização da instalação Python e do ambiente virtual) e navegue até a pasta `InlogicStudio/`.
    ```bash
    pip install -r requirements.txt
    ```
2.  Copie a pasta `Modulos/` para dentro da pasta `InlogicStudio/`, se ela não estiver lá.

### 3. Configuração Inicial (Usando o Studio)

1.  Execute o **InLogic Studio** (pode precisar de privilégios de Administrador para gerenciar o serviço e arquivos de configuração).
2.  Ao iniciar, o Studio verificará a licença e tentará criar os arquivos de configuração e licença básicos em `C:\In Logic\Setup ativos\`.
3.  Use a interface do **InLogic Studio** para:
    *   Gerenciar a **Licença** (aplicar o arquivo de licença `Authentication.cfg`).
    *   Especificar o caminho para o arquivo JSON da **chave de serviço Firebase** na configuração (se usar FCM).
    *   Configurar os **Grupos/Ativos** (IP, tipo, listas de memórias/tags/tópicos).
    *   Configurar os **Gatilhos** e **Intervalos do Temporizador**.
    *   Configurar os **Destinos de Gravação** (caminhos Excel, detalhes de conexão SQL, detalhes de publicação MQTT, lista de tokens de dispositivo FCM para notificações).
    *   Definir **Cálculos** personalizados.
4.  Após salvar a configuração no Studio, use a opção no Studio para **Recarregar Configuração** ou **Reiniciar o Serviço** para que o InLogic Service passe a usar a nova configuração.

## Uso

1.  Execute o **InLogic Studio**.
2.  Verifique o status do **InLogic Service** na interface do Studio. Inicie-o se necessário.
3.  Monitore os **Logs do Sistema** exibidos no Studio para verificar a operação do Serviço e as conexões com os ativos.
4.  Se configurado com gatilhos, o Serviço coletará dados automaticamente quando o gatilho no CLP/MQTT for acionado. Se configurado com temporizador, coletará em intervalos regulares.
5.  Os dados coletados serão gravados/publicados nos destinos configurados (Excel, SQL, MQTT, FCM).
6.  Utilize a interface de **Scripting** no Studio para executar comandos de leitura/escrita em ativos ou gerenciar dados SQL, conforme sua necessidade.

## Interface de Scripting (No Studio)

O InLogic Studio possui uma interface simples para executar comandos diretos:

*   **LER \<IP\> \<ENDEREÇO_MEMORIA\>** : Lê um valor de memória/endereço de um CLP Modbus. Ex: `LER 192.168.2.1 100`.
*   **ATUALIZAR \<IP\> \<ENDEREÇO_MEMORIA\> \<VALOR\>** : Escreve um valor em uma memória/endereço de um CLP Modbus. Ex: `ATUALIZAR 192.168.2.1 100 20`.
*   **LER\_SQL \<NOME\_GRUPO\> LINHAS=\<N\>** : Lê as últimas N linhas da tabela SQL configurada para o grupo especificado. Ex: `LER_SQL BATELADA_P3 LINHAS=10`.
*   **APAGAR\_SQL \<NOME\_GRUPO\>** : Apaga todos os dados da tabela SQL configurada para o grupo especificado. Ex: `APAGAR_SQL BATELADA_P3`.

## Licenciamento

O InLogic Software é um produto licenciado. O **InLogic Service** requer um arquivo de licença válido (`C:\In Logic\Setup ativos\Authentication.cfg`) para operar as funcionalidades de aquisição e gravação. A licença está vinculada ao hardware da máquina onde o Serviço está instalado. O **InLogic Studio** fornece as ferramentas para visualizar as informações de hardware necessárias e gerenciar o arquivo de licença.

## Logs

Os logs detalhados do **InLogic Service** são gravados em arquivos rotativos na pasta `C:\In Logic\Logs Inlogic\`. O **InLogic Studio** se conecta ao Serviço via Named Pipe para exibir esses logs em tempo real na interface do usuário.

## Tecnologias Utilizadas

*   **Linguagem:** Python 3.x
*   **Interface Gráfica:** PyQt5
*   **Comunicação CLP/Industrial:** pyModbusTCP (Modbus TCP), pycomm3 (Ethernet/IP), paho-mqtt (MQTT)
*   **Banco de Dados:** pyodbc (SQL Server)
*   **Arquivo:** openpyxl (Excel)
*   **Cloud Messaging:** firebase-admin (Firebase FCM)
*   **Criptografia:** pycryptodome (AES)
*   **Interprocessos:** pywin32 (Named Pipes)
*   **Sistema Operacional:** pywin32 (Windows Services, Windows API), wmi, psutil (Info sistema)
*   **Threading/Concorrência:** Python `threading`, `queue`, `concurrent.futures`

## Estrutura do Repositório

```bash
InLogic-Software/
├── InlogicService/       # Código e dependências do InLogic Service (Windows Service)
│   ├── InlogicService.py
│   └── requirements.txt
├── InlogicStudio/        # Código e dependências do InLogic Studio (Aplicação Desktop)
│   ├── InLogic_Studio.py
│   ├── requirements.txt
│   └── Modulos/          # Módulos auxiliares do Studio
│       ├── donwload_backup.py
│       ├── modulo_google_drive.py
│       └── validador_licenca.py
├── .gitignore            # Arquivo para o Git ignorar arquivos e pastas sensíveis/não essenciais
└── README.md             # Este arquivo de descrição do sistema
