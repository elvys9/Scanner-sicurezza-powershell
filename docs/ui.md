# Interfaccia Grafica (WPF) — Design e Collaudo Manuale

## 1. Obiettivo e Filosofia di Design

L'interfaccia grafica dello scanner di sicurezza per Windows 11 e' progettata sul modello di **winutil**:
- **Zero installazione**: utilizza esclusivamente WPF (`PresentationFramework`) incluso nativamente in Windows 11 e Windows PowerShell 5.1.
- **Separazione netta tra Vista e Motore**: la finestra non contiene alcuna logica di valutazione dei controlli. Invoca `Invoke-Controlli` e `New-Report` del motore (`src/core`) e usa le funzioni pure di `src/ui/ViewModel.ps1` per ordinamento, filtri, conteggi e formattazione dei dettagli.
- **Sola lettura garantita**: nessun pulsante dell'interfaccia esegue comandi di modifica del sistema o applica rimedi. L'utente puo' solo visualizzare i risultati, copiare i comandi di riferimento negli appunti, esportare il report su file (JSON/HTML) o riavviare l'applicazione come amministratore.

---

## 2. Schermate (Rappresentazione Testuale)

### 2.1 Avvio iniziale (Utente non amministratore, prima della scansione)

```
+----------------------------------------------------------------------------------+
| [Lucchetto] Scanner sicurezza Windows (Sola lettura) [Win 11 Pro | Admin: No] [Tema]|
+----------------------------------------------------------------------------------+
| [!] Avviato senza privilegi di amministratore. I controlli che richiedono        |
|     privilegi elevati risulteranno 'Sconosciuto'.    [Riavvia come amministratore]|
+----------------------------------------------------------------------------------+
| [ Avvia scansione ]  [Annulla (disattivo)]   [------------------] Pronto (0/18)  |
+----------------------------------------------------------------------------------+
| [ [OK] 0 Superati ] [ [X] 0 Falliti ] [ [?] 0 Sconosciuti ] [ [-] 0 N/A ] [ [!] 0]|
+----------------------------------------------------------------------------------+
| Stato: [Tutti v]  Gravita': [Tutte v]  Categoria: [Tutte v]  Cerca: [________]   |
+-----------------------------------------------+----------------------------------+
|                                               | DETTAGLIO CONTROLLO              |
|                                               | Seleziona un controllo           |
|            [Icona Lente]                      | ID: - | Stato: - | Gravita': -   |
|   Premi 'Avvia scansione' per analizzare      | [Semplice] [Tecnico]             |
|        la sicurezza del sistema.              | Perche' conta:                   |
|   La scansione e' in sola lettura e non       | Seleziona una riga nella tabella |
|   apporta alcuna modifica a Windows.          | Valore atteso: - | Trovato: -    |
|                                               | Come correggere: -               |
|                                               | [Spiega con LLM (disattivato)]   |
+-----------------------------------------------+----------------------------------+
| [Esporta JSON] [Esporta HTML] [ ] Includi log tecnico    Riepilogo: 0 valutati   |
| Avviso permanente: l'audit conforme non dimostra l'assenza di compromissioni.    |
+----------------------------------------------------------------------------------+
```

### 2.2 Scansione completata e controllo selezionato

```
+----------------------------------------------------------------------------------+
| [Lucchetto] Scanner sicurezza Windows (Sola lettura) [Win 11 Pro | Admin: Si] [Tema]|
+----------------------------------------------------------------------------------+
| [ Avvia scansione ]  [Annulla (disattivo)]   [##################] Completata(18/18)|
+----------------------------------------------------------------------------------+
| [ [OK] 2 Superati ] [ [X] 1 Falliti ] [ [?] 15 Sconosciuti ] [ [-] 0 N/A ] [[!] 0]|
+----------------------------------------------------------------------------------+
| Stato: [Tutti v]  Gravita': [Tutte v]  Categoria: [Tutte v]  Cerca: [________]   |
+-----------------------------------------------+----------------------------------+
| Stato        | Gravita'| Cat.     | ID        | DETTAGLIO CONTROLLO              |
| > [X] Fallito| Critico | Firewall | HOME-FW.. | Firewall di Windows attivo       |
|   [?] Scon.  | Alto    | UAC      | HOME-UA.. | ID: HOME-FW-001 | [X] Fallito    |
|   [OK] Sup.  | Critico | UAC      | HOME-UA.. | [Semplice] [Tecnico]             |
|   [OK] Sup.  | Critico | Account  | HOME-AC.. | Perche' conta:                   |
|                                               | Il firewall e' la prima linea... |
|                                               | Atteso: Attivi | Trovato: Public |
|                                               | Come correggere:                 |
|                                               | Attiva Windows Defender Firewall |
|                                               | [Set-NetFirewallProfile ...]     |
|                                               | [Copia comando]                  |
|                                               | [Spiega con LLM] (disattivato)   |
+-----------------------------------------------+----------------------------------+
| [Esporta JSON] [Esporta HTML] [ ] Includi log tecnico    Riepilogo: 18 valutati  |
| Avviso permanente: l'audit conforme non dimostra l'assenza di compromissioni.    |
+----------------------------------------------------------------------------------+
```

---

## 3. Scelte di Design

1. **Accessibilita' visiva (mai solo colore)**: ogni stato utilizza contemporaneamente un prefisso simbolico (`[OK]`, `[X]`, `[?]`, `[-]`, `[!]`), un'etichetta testuale (`Superato`, `Fallito`, `Sconosciuto`, `Non applicabile`, `Errore`) e una combinazione cromatica ad alto contrasto.
2. **Ordinamento orientato alle priorita'**: per evitare che l'utente domestico debba cercare i problemi in fondo alla lista, l'ordinamento predefinito mostra sempre per primi i controlli `falliti` ordinati per gravita' decrescente (`critico` -> `alto` -> `medio` -> `basso` -> `informativo`), seguiti da `errore`/`sconosciuto`, poi `superato` e infine `non_applicabile`.
3. **Doppia modalita' di spiegazione (`Semplice` / `Tecnico`)**:
   - La vista **Semplice** mostra il campo `rationale` pensato per l'utente non esperto.
   - La vista **Tecnico** mostra `description`, ID del controllo, edizioni supportate, durata in millisecondi, evidenza JSON raccolta e riferimenti normativi (es. CIS Benchmark).
4. **Reattivita' tramite Runspace e Dispatcher**: la scansione viene eseguita in un `[runspace]` dedicato. Al completamento di ciascun controllo, l'hook `-OnProgress` del `Runner.ps1` invia il risultato al thread UI tramite `$Window.Dispatcher.Invoke(...)`, aggiornando barra di avanzamento, contatori e tabella in tempo reale senza bloccare il ridimensionamento o il pulsante `Annulla`.
5. **Scalabilita' DPI (100%, 125%, 150%)**: il layout usa `Grid` con proporzioni `*`/`Auto`, `UniformGrid`, `WrapPanel` per i filtri e `ScrollViewer` nel pannello di dettaglio, con dimensioni minime `900x600` e `UseLayoutRounding="True"`.

---

## 4. Checklist di Collaudo Manuale (su VM Windows 11)

Eseguire i controlli seguenti su una macchina virtuale Windows 11 (Home o Pro):

- [ ] **1. Apertura rapida (< 3 secondi)**:
  - Eseguire `powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1`.
  - Verificare che la finestra si apra in meno di 3 secondi, con la tabella vuota e il messaggio guida `"Premi 'Avvia scansione' per analizzare la sicurezza del sistema."`.
- [ ] **2. Comportamento Utente Non-Admin**:
  - Avviare lo script da un terminale PowerShell *senza* privilegi di amministratore.
  - Verificare che nell'intestazione compaia `Admin: No` e che sia visibile il banner giallo con il pulsante **"Riavvia come amministratore"**.
  - Avviare la scansione e verificare che i controlli che richiedono privilegi (es. `HOME-FW-001`, `HOME-ACC-001`) abbiano stato `[?] Sconosciuto` e mai `[X] Fallito`.
  - Premere **"Riavvia come amministratore"** e verificare la comparsa del prompt UAC e il riavvio con `Admin: Si`.
- [ ] **3. Scansione in tempo reale e Reattivita'**:
  - Premere **"Avvia scansione"**.
  - Verificare che la finestra resti spostabile e ridimensionabile durante l'esecuzione, che la barra di avanzamento avanzi (`1/18` ... `18/18`) e che i conteggi in alto si aggiornino.
- [ ] **4. Funzionamento del pulsante "Annulla"**:
  - Avviare una scansione e premere subito **"Annulla"**.
  - Verificare che la scansione si interrompa in modo pulito senza blocchi o crash e che lo stato mostri `Annullata (N/18)`.
- [ ] **5. Filtri combinabili e Ricerca**:
  - Selezionare `Stato = superato` o `sconosciuto`, `Gravita' = critico`, `Categoria = Firewall` e digitare `FW-001` o `Firewall` nella casella **Cerca**.
  - Verificare che la tabella si aggiorni istantaneamente e che **"Reimposta filtri"** riporti tutti i controlli.
- [ ] **6. Pannello Dettaglio e Copia Comando**:
  - Selezionare `HOME-FW-001`, `HOME-UAC-001` e `HOME-ACC-001`: verificare il passaggio tra **Semplice** e **Tecnico**, la presenza del comando di rimedio e il funzionamento di **"Copia comando"** (incollare in Blocco Note per verificare il contenuto degli appunti).
  - Selezionare un controllo privo di comando (es. `HOME-UAC-002`): verificare che il riquadro del comando e il pulsante "Copia comando" siano nascosti e venga mostrato solo il testo.
  - Passare il mouse su **"Spiega con LLM (Ollama)"**: verificare che il pulsante sia disattivato e mostri il tooltip `"Disponibile in una fase successiva"`.
- [ ] **7. Export JSON, Export HTML e Log Tecnico**:
  - Premere **"Esporta JSON"**: verificare che il nome file proposto contenga data e ora (`scanner_sicurezza_YYYYMMDD_HHMMSS.json`) e che il contenuto abbia la stessa struttura di `-Headless`.
  - Premere **"Esporta HTML"**: aprire il file `.html` generato nel browser (senza connessione di rete) e verificare che stili, colori, tabella e avviso permanente siano completi e leggibili.
  - Spuntare **"Includi file di log tecnico accanto all'export"**, esportare nuovamente e verificare la creazione del file `.errori.log`.
- [ ] **8. Tema Chiaro / Scuro**:
  - Premere **"Tema: Scuro"** in alto a destra e verificare il contrasto di testo, tabella, pannello dettaglio e schede riepilogo; premere di nuovo per tornare al tema chiaro.
- [ ] **9. Scalabilita' DPI (100%, 125%, 150%)**:
  - Nelle Impostazioni schermo di Windows 11, impostare il ridimensionamento a **125%** e poi a **150%**.
  - Verificare che i testi non vengano tagliati, che i filtri vadano a capo se necessario (`WrapPanel`) e che il pannello dettaglio scorra verticalmente.
- [ ] **10. Navigazione da Tastiera**:
  - Usare il tasto `Tab` e `Shift+Tab` per spostarsi tra i controlli, le frecce `Su`/`Giu'` nella tabella dei risultati, e le scorciatoie `Alt+A` (Avvia), `Alt+N` (Annulla), `Alt+C` (Copia comando), `Alt+J` (Esporta JSON), `Alt+H` (Esporta HTML).
