import os
import sys
import time
import queue
import hashlib
import threading
from datetime import datetime

print("[boot] iniciando…")  # ajuda a ver se o script está realmente rodando

# ---------------- GUI & Tema ----------------
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import ttkbootstrap as tb

APP_NAME = "Gerador de Hash"
BRAND = "Resguarde - Soluções Inteligentes"
WINDOW_TITLE = f"{APP_NAME} • {BRAND}"

# Arrastar & Soltar (opcional)
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:
    HAS_DND = False

# Contagem de páginas PDF
try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except Exception:
    HAS_PYPDF = False

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except Exception:
    HAS_FITZ = False

# ---------------- Config ----------------
CHUNK_SIZE = 1024 * 1024  # 1 MiB
ALGOS = {
    "MD5": lambda: hashlib.md5(),
    "SHA1": lambda: hashlib.sha1(),
    "SHA256": lambda: hashlib.sha256(),
    "SHA512": lambda: hashlib.sha512(),
    "BLAKE2b": lambda: hashlib.blake2b(),
    "BLAKE2s": lambda: hashlib.blake2s(),
}

# ---------------- Utils ----------------
def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}"

def compute_hash(filepath: str, algo_name: str, progress_cb=None, stop_flag=None):
    hasher = ALGOS[algo_name]()
    total = os.path.getsize(filepath)
    done = 0
    with open(filepath, "rb") as f:
        while True:
            if stop_flag and stop_flag.is_set():
                raise KeyboardInterrupt("Operação cancelada pelo usuário.")
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            done += len(chunk)
            if progress_cb:
                progress_cb(done, total)
    return hasher.hexdigest()

def count_pdf_pages(path: str) -> int | None:
    try:
        if HAS_PYPDF:
            r = PdfReader(path)
            return len(r.pages)
        if HAS_FITZ:
            with fitz.open(path) as doc:
                return doc.page_count
    except Exception:
        return None
    return None

def parse_dnd_file_list(data: str) -> list[str]:
    """Converte payload DND em lista de paths. Ex.: {C:\a 1.pdf} {C:\b.pdf}"""
    out, token, in_brace = [], "", False
    for ch in data:
        if ch == "{":
            in_brace, token = True, ""
        elif ch == "}":
            in_brace = False
            out.append(token)
            token = ""
        elif ch == " " and not in_brace:
            if token:
                out.append(token)
                token = ""
        else:
            token += ch
    if token:
        out.append(token)
    return out

# ---------------- App ----------------
class HashLoggerApp:
    def __init__(self):
        if HAS_DND:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        # Tema inicial
        self.style = tb.Style(theme="journal")
        self.root.title(WINDOW_TITLE)
        self.root.geometry("1120x680")
        self.root.minsize(980, 620)

        # Estado
        self.files: list[str] = []
        self.results: list[dict] = []
        self.worker = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()

        self.build_ui()
        self.after_poll_log()

    # ---------- UI ----------
    def build_ui(self):
        top = tb.Frame(self.root, padding=10)
        top.pack(fill=tb.X)

        self.btn_add = tb.Button(top, text="Adicionar arquivos", bootstyle=tb.PRIMARY,
                                 command=self.add_files, width=22)
        self.btn_add.pack(side=tb.LEFT, padx=(0,8))

        self.btn_add_folder = tb.Button(top, text="Adicionar pasta", bootstyle=tb.SECONDARY,
                                        command=self.add_folder, width=18)
        self.btn_add_folder.pack(side=tb.LEFT, padx=4)

        self.btn_remove = tb.Button(top, text="Remover seleção",
                                    command=self.remove_selected, width=18)
        self.btn_remove.pack(side=tb.LEFT, padx=4)

        self.btn_clear = tb.Button(top, text="Limpar lista",
                                   command=self.clear_list, width=14)
        self.btn_clear.pack(side=tb.LEFT, padx=4)

        tb.Label(top, text="Algoritmo:", anchor="w").pack(side=tb.LEFT, padx=(18,6))
        self.algo_var = tk.StringVar(value="SHA256")
        self.cbo_algo = tb.Combobox(top, textvariable=self.algo_var, state="readonly",
                                    values=list(ALGOS.keys()), width=12)
        self.cbo_algo.pack(side=tb.LEFT)

        self.btn_start = tb.Button(top, text="Calcular", bootstyle=tb.SUCCESS,
                                   command=self.start_hash, width=14)
        self.btn_start.pack(side=tb.LEFT, padx=10)

        self.btn_cancel = tb.Button(top, text="Cancelar", bootstyle=tb.DANGER,
                                    command=self.cancel, width=12)
        self.btn_cancel.pack(side=tb.LEFT)

        # Opções
        opts = tb.Frame(self.root, padding=(10,0,10,0))
        opts.pack(fill=tb.X)
        self.recursive_var = tk.BooleanVar(value=True)
        self.pages_var = tk.BooleanVar(value=False)
        tb.Checkbutton(opts, text="Incluir subpastas (recursivo)",
                       variable=self.recursive_var).pack(side=tb.LEFT, padx=(0,16))
        tb.Checkbutton(opts, text="Contar páginas (PDF)",
                       variable=self.pages_var).pack(side=tb.LEFT)

        # Corpo
        body = tb.Panedwindow(self.root, orient="horizontal", bootstyle=tb.SECONDARY)
        body.pack(fill=tb.BOTH, expand=True, padx=10, pady=(8,10))

        left = tb.Frame(body, padding=(8,8,8,8))
        right = tb.Frame(body, padding=(8,8,8,8))
        body.add(left, weight=4)
        body.add(right, weight=6)

        lf = tb.Labelframe(left, text="Arquivos (arraste & solte aqui)", padding=10)
        lf.pack(fill=tb.BOTH, expand=True)

        cols = ("arquivo", "tamanho")
        self.tree = tb.Treeview(lf, columns=cols, show="headings", height=12, bootstyle=tb.INFO)
        self.tree.heading("arquivo", text="Caminho")
        self.tree.heading("tamanho", text="Tamanho")
        self.tree.column("arquivo", width=680, anchor="w")
        self.tree.column("tamanho", width=120, anchor="e")
        self.tree.pack(fill=tb.BOTH, expand=True)

        if HAS_DND:
            self.tree.drop_target_register(DND_FILES)
            self.tree.dnd_bind("<<Drop>>", self.on_drop_files)

        prog_frame = tb.Frame(left)
        prog_frame.pack(fill=tb.X, pady=(8,0))
        self.progress = tb.Progressbar(prog_frame, mode="determinate", bootstyle=tb.STRIPED)
        self.progress.pack(fill=tb.X, expand=True)

        self.status_var = tk.StringVar(value=f"Pronto – {BRAND}")
        self.status_lbl = tb.Label(prog_frame, textvariable=self.status_var, anchor="w")
        self.status_lbl.pack(fill=tb.X, pady=(6,0))

        logf = tb.Labelframe(right, text="Log", padding=10)
        logf.pack(fill=tb.BOTH, expand=True)

        self.txt = scrolledtext.ScrolledText(logf, height=20, wrap="word")
        self.txt.pack(fill=tb.BOTH, expand=True)
        self.log(f"Aplicativo iniciado – {BRAND}. " +
                 ("Arraste arquivos/pastas para a lista." if HAS_DND else
                  "Instale 'tkinterdnd2' para arrastar & soltar."))

        bottom = tb.Frame(self.root, padding=(10,0,10,10))
        bottom.pack(fill=tb.X)

        self.btn_copy = tb.Button(bottom, text="Copiar log", command=self.copy_log)
        self.btn_copy.pack(side=tb.LEFT)

        self.btn_save_txt = tb.Button(bottom, text="Salvar TXT", command=self.export_txt)
        self.btn_save_txt.pack(side=tb.LEFT, padx=6)

        self.btn_save_csv = tb.Button(bottom, text="Salvar CSV", command=self.export_csv)
        self.btn_save_csv.pack(side=tb.LEFT, padx=6)

        theme_box = tb.Combobox(bottom, state="readonly",
                                values=self.style.theme_names(), width=16)
        theme_box.set(self.style.theme.name)  # journal
        theme_box.pack(side=tb.RIGHT)
        tb.Label(bottom, text="Tema: ").pack(side=tb.RIGHT, padx=(0,6))
        theme_box.bind("<<ComboboxSelected>>", lambda e: self.change_theme(theme_box.get()))

    # ---------- UI helpers ----------
    def change_theme(self, theme):
        try:
            self.style.theme_use(theme)
        except Exception as ex:
            messagebox.showerror("Tema", f"Não foi possível aplicar o tema '{theme}'.\n{ex}")

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Selecione arquivos")
        if not paths:
            return
        for p in paths:
            self._add_path(p)
        self.log(f"{len(paths)} arquivo(s) adicionados.")

    def add_folder(self):
        folder = filedialog.askdirectory(title="Selecione a pasta")
        if not folder:
            return
        count = self._ingest_folder(folder, self.recursive_var.get())
        self.log(f"{count} arquivo(s) adicionados da pasta.")

    def on_drop_files(self, event):
        paths = parse_dnd_file_list(event.data)
        added = 0
        for p in paths:
            if os.path.isdir(p):
                added += self._ingest_folder(p, self.recursive_var.get())
            else:
                if self._add_path(p):
                    added += 1
        self.log(f"{added} item(ns) adicionados via arrastar & soltar.")

    def _ingest_folder(self, folder: str, recursive: bool) -> int:
        count = 0
        if recursive:
            for root, _, files in os.walk(folder):
                for fn in files:
                    if self._add_path(os.path.join(root, fn)):
                        count += 1
        else:
            for fn in os.listdir(folder):
                fp = os.path.join(folder, fn)
                if os.path.isfile(fp) and self._add_path(fp):
                    count += 1
        return count

    def _add_path(self, path: str) -> bool:
        p = os.path.abspath(path)
        if not os.path.isfile(p) or p in self.files:
            return False
        self.files.append(p)
        try:
            size = human_size(os.path.getsize(p))
        except Exception:
            size = "?"
        self.tree.insert("", "end", values=(p, size))
        return True

    def remove_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        removed = 0
        for iid in sel:
            vals = self.tree.item(iid, "values")
            path = vals[0]
            if path in self.files:
                self.files.remove(path)
            self.tree.delete(iid)
            removed += 1
        if removed:
            self.log(f"{removed} arquivo(s) removidos.")

    def clear_list(self):
        self.files.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.log("Lista de arquivos limpa.")

    # ---------- Execução ----------
    def start_hash(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Em andamento", "Já existe um processamento em andamento.")
            return
        if not self.files:
            messagebox.showinfo("Arquivos", "Adicione pelo menos um arquivo.")
            return
        algo = self.algo_var.get()
        if algo not in ALGOS:
            messagebox.showerror("Algoritmo", "Selecione um algoritmo válido.")
            return

        self.results.clear()
        self.txt.delete("1.0", tk.END)
        self.progress.configure(value=0, maximum=max(1, len(self.files)))
        self.status_var.set(f"Iniciando… Algoritmo: {algo}")
        self.stop_event.clear()

        self.worker = threading.Thread(target=self._worker_run, args=(algo,), daemon=True)
        self.worker.start()
        self.log(f"Iniciando cálculo com {algo} para {len(self.files)} arquivo(s).")

    def cancel(self):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self.log("Solicitando cancelamento…")
        else:
            self.log("Nenhum processamento para cancelar.")

    def _worker_run(self, algo):
        started = time.time()
        total_files = len(self.files)
        finished = 0
        try:
            for path in self.files:
                if self.stop_event.is_set():
                    raise KeyboardInterrupt

                fname = os.path.basename(path)
                size = os.path.getsize(path)
                self.qlog(f"[{finished+1}/{total_files}] Processando: {fname} ({human_size(size)})")

                def file_progress(done, total):
                    percent = (done / max(1, total)) * 100.0
                    self.qstatus(f"Arquivo: {fname} — {percent:.1f}%")

                try:
                    hexhash = compute_hash(path, algo, progress_cb=file_progress, stop_flag=self.stop_event)
                except KeyboardInterrupt:
                    raise
                except Exception as ex:
                    self.qlog(f"  ERRO: {ex}")
                    hexhash = None

                paginas = None
                if self.pages_var.get() and path.lower().endswith(".pdf"):
                    paginas = count_pdf_pages(path)

                if hexhash:
                    row = {
                        "arquivo": path,
                        "nome": fname,
                        "tamanho_bytes": size,
                        "tamanho_humano": human_size(size),
                        "algoritmo": algo,
                        "hash": hexhash,
                        "paginas": paginas,
                        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.results.append(row)
                    extra = f" | páginas: {paginas}" if paginas is not None else ""
                    self.qlog(f"  {algo}: {hexhash}{extra}")

                finished += 1
                self.qprogress(finished, total_files)

            elapsed = time.time() - started
            if not self.stop_event.is_set():
                self.qstatus(f"Concluído em {elapsed:.2f}s. Arquivos: {total_files}.")
                self.qlog(f"Finalizado em {elapsed:.2f}s.")
            else:
                self.qstatus("Cancelado.")
                self.qlog("Processamento cancelado.")
        except KeyboardInterrupt:
            self.qstatus("Cancelado.")
            self.qlog("Processamento cancelado pelo usuário.")

    # ---------- Thread-safe UI ----------
    def qlog(self, msg): self.log_queue.put(("log", msg))
    def qstatus(self, msg): self.log_queue.put(("status", msg))
    def qprogress(self, done, total): self.log_queue.put(("progress", (done, total)))

    def after_poll_log(self):
        try:
            while True:
                kind, payload = self.log_queue.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "progress":
                    done, total = payload
                    self.progress.configure(maximum=max(1, total), value=done)
        except queue.Empty:
            pass
        self.root.after(80, self.after_poll_log)

    def log(self, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.txt.insert(tk.END, f"[{timestamp}] {text}\n")
        self.txt.see(tk.END)

    # ---------- Export ----------
    def assert_has_results(self):
        if not self.results:
            messagebox.showinfo("Exportar", "Não há resultados para exportar. Calcule algum hash primeiro.")
            return False
        return True

    def copy_log(self):
        content = self.txt.get("1.0", tk.END).strip()
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.log("Log copiado para a área de transferência.")

    def export_txt(self):
        if not self.assert_has_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt")],
            title="Salvar como TXT"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{APP_NAME} - {BRAND}\n")
                f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("------------------------------------------------------------\n")
                for r in self.results:
                    f.write(
                        f"{r['algoritmo']}; {r['hash']}; {r['nome']}; "
                        f"{r['tamanho_humano']}; paginas={r['paginas']}; "
                        f"{r['arquivo']}; {r['quando']}\n"
                    )
            self.log(f"TXT salvo em: {path}")
        except Exception as ex:
            messagebox.showerror("TXT", f"Falha ao salvar TXT.\n{ex}")

    def export_csv(self):
        if not self.assert_has_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            title="Salvar como CSV"
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow([f"# {APP_NAME} - {BRAND}"])
                writer.writerow(["algoritmo", "hash", "arquivo", "nome",
                                 "tamanho_bytes", "tamanho_humano", "paginas", "quando"])
                for r in self.results:
                    writer.writerow([
                        r["algoritmo"], r["hash"], r["arquivo"], r["nome"],
                        r["tamanho_bytes"], r["tamanho_humano"],
                        (r["paginas"] if r["paginas"] is not None else ""),
                        r["quando"]
                    ])
            self.log(f"CSV salvo em: {path}")
        except Exception as ex:
            messagebox.showerror("CSV", f"Falha ao salvar CSV.\n{ex}")

    # ---------- Mainloop ----------
    def place_window_center(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (sw - w) // 2, (sh - h) // 3
        self.root.geometry(f"+{x}+{y}")

    def run(self):
        self.place_window_center()
        self.root.mainloop()

# -------------- Entry point com diagnóstico --------------
def _fatal(e: Exception):
    try:
        with open("hash_logger_error.log", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {type(e).__name__}: {e}\n")
            import traceback; traceback.print_exc(file=f)
    except Exception:
        pass
    try:
        messagebox.showerror("Erro fatal", f"Ocorreu um erro e o programa será encerrado:\n{e}")
    except Exception:
        pass
    print(f"[fatal] {type(e).__name__}: {e}", file=sys.stderr)

def main():
    try:
        app = HashLoggerApp()
        app.run()
    except SystemExit:
        raise
    except Exception as e:
        _fatal(e)
        raise

if __name__ == "__main__":
    main()
