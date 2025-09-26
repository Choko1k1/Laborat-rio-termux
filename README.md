README.txt - Azzy Lab — Mini Shop (Local Lab)
=============================================

Resumo
------
Azzy Lab é um ambiente local para treinamento de pentest: loja fictícia em Flask + SQLite,
autenticação, endpoint /api/lab (logs em console + DB) e painel administrativo. Projetado
para estudo controlado e análise de payloads. Uso somente em ambiente autorizado.

Pré-requisitos (Termux)
-----------------------
1) Termux atualizado:
   pkg update -y && pkg upgrade -y

2) Pacotes essenciais:
   pkg install -y python git wget unzip termux-api

Estrutura do projeto
--------------------
~/azzy-shop-full/
  ├─ app.py
  ├─ start.sh
  ├─ stop.sh
  ├─ create_db_and_admin.py
  ├─ gen_admin.py
  ├─ requirements.txt
  ├─ data/
  │   ├─ app.db
  │   ├─ products.json
  │   └─ credentials.txt
  ├─ templates/
  └─ static/

Instalação / Provisionamento
----------------------------
1) Copie o instalador para o dispositivo (se ainda não o fez):
   chmod +x install_azzy_lab_full.sh
   ./install_azzy_lab_full.sh

2) Se preferir criar manualmente:
   - clone os arquivos ou copie o conteúdo do instalador para ~/azzy-shop-full
   - verifique requisitos do Python

Iniciar / Parar
---------------
Iniciar:
  cd ~/azzy-shop-full
  ./start.sh
  - Cria venv, instala dependências, cria DB, gera credenciais admin aleatórias.
  - Abre o navegador local (se disponível).
  - Credenciais gravadas em data/credentials.txt e também impressas no console.

Parar:
  cd ~/azzy-shop-full
  ./stop.sh

URLs principais
---------------
- Loja:           http://127.0.0.1:5000/
- Página extra:   http://127.0.0.1:5000/index2
- Produto:        http://127.0.0.1:5000/product/<SKU>
- Login:          http://127.0.0.1:5000/login
- Pós-login:      http://127.0.0.1:5000/post_login
- Admin logs:     http://127.0.0.1:5000/admin/logs   (apenas admin)
- Endpoint test:  http://127.0.0.1:5000/api/lab      (POST JSON)

Credenciais
-----------
- A cada execução de ./start.sh um admin novo é gerado com prefix "admin_".
- Local: data/credentials.txt
- Ex: "admin_xxx:SenhaAleatoria"
- Troque ou revogue credenciais após testes.

Banco de dados
--------------
- SQLite em data/app.db
- Tabelas importantes: users, lab_logs
- Backup recomendado antes de testes destrutivos:
  cp data/app.db data/app.db.bak

Ferramentas recomendadas (prioridade)
------------------------------------
1. Burp Suite (PC) — proxy/interceptor
2. tcpdump / tshark — captura de tráfego
3. sqlmap — automação SQLi
4. nmap — varredura de portas
5. curl / httpie / jq — requests e análise JSON
6. sqlite3 / DB Browser — inspecionar data/app.db

Fluxo de estudo sugerido
------------------------
1. ./start.sh -> recuperar credenciais em data/credentials.txt
2. Configurar Burp (PC) como proxy; direcionar navegador do Android ao proxy
3. Autenticar-se, navegar, interceptar e manipular requests
4. Testar /api/lab com curl/httpie e analisar logs no console e no painel admin
5. Fazer snapshots do DB antes de operações destrutivas
6. Repetir, documentar payloads, resultados e timestamps

Segurança e ética (sem rodeios)
------------------------------
- Execute apenas em máquinas/ambientes nos quais você tem autorização.
- Testes contra terceiros são ilegais.
- Ao usar túnel público (ngrok), saiba que expõe seu lab; monitore logs.
- Remova dados sensíveis após uso.

Troubleshooting rápido
----------------------
App não inicia:
  - Verifique processos: ps aux | grep gunicorn
  - Logs: nohup.out (se existirem) ou console do Termux
Dependências falham:
  - Source venv manualmente:
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
DB não criado:
  - python create_db_and_admin.py
Credenciais não aparecem:
  - cat data/credentials.txt && ls -la data

Boas práticas operacionais
--------------------------
- Versione o lab com git antes de alterações significativas.
- Automatize snapshots do DB (cp data/app.db data/app.db.YYYYMMDD.bak).
- Documente cada vetor testado (payload, headers, resposta, timestamp).
- Não trate o lab como produção — surface e contexto são diferentes.

Notas técnicas
--------------
- Tema visual: neon branco sobre fundo escuro.
- /api/lab grava payloads em DB e imprime no console para análise.
- Vulnerabilidades intencionais existem e são discretas — exijam análise manual.

COPY
----
N4rco
