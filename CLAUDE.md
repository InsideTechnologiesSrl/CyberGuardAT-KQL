# project-cyberguard-mssentinel-kql

Catalogo di query KQL CyberGuard, distribuito come `index.json` su GitHub raw.

## Pubblicazione Azure

- **Scope:** CyberGuard — account `adm.silviodb@cyberguard.onmicrosoft.com`, sottoscrizione `ce139b6d-0666-48ad-8cba-a6ea1e9dfad1`, profilo az predefinito `~/.azure`
- **Cosa si pubblica:** niente su Azure. Il catalogo è servito da `https://raw.githubusercontent.com/InsideTechnologiesSrl/CyberGuardAT-KQL/main/index.json`: il push su `main` lo pubblica.
- **Come:** GitHub Actions, senza autenticazione Azure: `validate.yml` (`npm run check` su push e PR), `refresh-attack.yml` (aggiornamento mensile MITRE ATT&CK con commit automatico), `close-external-prs.yml`
- **Verifica dopo il deploy:** workflow `validate` verde e `index.json` aggiornato all'URL raw
- **Altre risorse toccate:** nessuna
- **Note:** un push su `main` è già una pubblicazione: verifica `npm run check` prima.
