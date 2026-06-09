## Cosa fa questa PR

<!-- Descrizione concisa: cosa cambia e perché. Se chiude un issue: "Chiude #NNN". -->

## Come è stato testato

<!-- Cosa hai eseguito per verificare la modifica: test unitari, integrazione, manuale. -->

## Documenti toccati

<!-- Elenco dei doc 01–22 aggiornati in questa PR.
     Regola: se il comportamento descritto in un documento è cambiato, il documento
     va aggiornato nella stessa PR (doc 00 + doc 19 §9).
     Se non applicabile: "—" -->

## ADR coinvolti

<!-- Nuova decisione architetturale → nuovo ADR nella stessa PR.
     ADR modificato → stato Superseded sul vecchio + nuovo ADR.
     Se non applicabile: "—" -->

---

## Checklist Definition of Done (doc 19 §10)

- [ ] Compila e passa lint senza warning
- [ ] Test presenti, inclusi i negativi se tocca sicurezza o crittografia (doc 19 §6)
- [ ] CI verde su tutti i job pertinenti (`Gate CI` verde)
- [ ] Documentazione aggiornata se il comportamento descritto nei doc è cambiato (doc 19 §9)
- [ ] Ogni dipendenza nuova: versione verificata all'ultima, bloccata esatta, licenza registrata (doc 19 §5)
- [ ] Nessun segreto in alcun file committato: log, test, fixture, commenti (doc 19 §5)
- [ ] Ogni placeholder/stub marcato `TODO(task-X.Y): … — placeholder` (doc 19 §3)
- [ ] PR piccola (≤ 400 righe esclusi generati/lockfile), una sola cosa (doc 19 §7)
- [ ] GO esplicito del titolare prima del merge su `main` (doc 19 §7)
