# ResguardeHash

📑 **ResguardeHash** é uma aplicação em **Python** com interface gráfica (Tkinter) para calcular e registrar **hashes (MD5, SHA-1, SHA-256, SHA-512)** de arquivos.  
Ideal para auditoria, preservação digital e comprovação de integridade de documentos.

---

## ✨ Funcionalidades

- Interface simples e leve em **Tkinter**  
- Seleção de arquivos individuais ou múltiplos  
- Cálculo de hashes: **MD5, SHA-1, SHA-256, SHA-512**  
- Geração automática de **logs em CSV** com:
  - Caminho do arquivo
  - Hash calculado
  - Data e hora do processamento
- Exportação de logs para análise posterior
- Versão **standalone (.exe)** com **PyInstaller**

---

## 🚀 Como usar

### 1. Clonar o repositório
```bash
git clone https://github.com/seu-usuario/resguardehash.git
cd resguardehash
```

### 2. Instalar dependências
Requer Python **3.12+**:
```bash
pip install -r requirements.txt
```

### 3. Executar em modo desenvolvimento
```bash
python hash_logger.py
```

### 4. Gerar executável (Windows)
```bash
pyinstaller --onefile --windowed --name ResguardeHash hash_logger.py
```
O binário será gerado em `dist/ResguardeHash.exe`.

---

## 📊 Estrutura de Logs

Os resultados são salvos em CSV automaticamente:

| Arquivo                 | Hash SHA-256                                                       | Data/Hora           |
|--------------------------|--------------------------------------------------------------------|---------------------|
| C:\docs\contrato.pdf    | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | 2025-08-16 10:22:33 |

---

## 📦 Requisitos

- **Python 3.12+**
- Bibliotecas:
  - `tkinter` (nativo do Python)
  - `hashlib` (nativo do Python)
  - `csv` (nativo do Python)
  - `PyInstaller` (para gerar executável)

---

## 🛠 Roadmap

- [ ] Opção de copiar hash para área de transferência  
- [ ] Verificação de integridade comparando hash calculado vs fornecido  
- [ ] Suporte a arrastar e soltar arquivos  
- [ ] Exportação em **JSON** além de CSV  

---

## 📜 Licença

Distribuído sob a licença **MIT**. Veja `LICENSE` para mais detalhes.

---

## 🤝 Contribuindo

Contribuições são bem-vindas!  
Sinta-se à vontade para abrir **Issues** e **Pull Requests** no repositório.
