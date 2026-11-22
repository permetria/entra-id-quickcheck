# Entra ID QuickCheck

Rychlá kontrola 6 základních bezpečnostních nastavení **Microsoft Entra ID** (dříve Azure AD). Skript nastavení jen čte a nic v tenantu nemění.

## Co kontroluje

| # | Kontrola | Proč na tom záleží |
|---|----------|--------------------|
| 1 | Počet globálních administrátorů | Moc adminů zvětšuje prostor pro útok, jeden admin znamená riziko, že se do tenantu nedostanete |
| 2 | Vynucení MFA | Bez MFA stačí útočníkovi k převzetí účtu jedno uniklé heslo |
| 3 | Blokování legacy autentizace | Starší protokoly jako IMAP, POP nebo SMTP AUTH obcházejí MFA |
| 4 | Souhlas uživatelů s aplikacemi | Přes podvodnou aplikaci (consent phishing) může útočník získat přístup k poště a souborům |
| 5 | Registrace aplikací uživateli | Aplikace, které si zaregistrují běžní uživatelé, nikdo nespravuje a mohou mít přístup k datům |
| 6 | Kdo smí zvát hosty | Když může hosty zvát kdokoli, nikdo nemá přehled o externím přístupu |

## Požadavky

- PowerShell 7 nebo novější (Windows, macOS i Linux)
- Modul `Microsoft.Graph.Authentication`
- Účet s rolí **Global Reader** (stačí jen pro čtení)

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## Použití

```powershell
./Invoke-EntraQuickCheck.ps1

# Přihlášení přes device code (když nefunguje interaktivní přihlášení ve Windows)
./Invoke-EntraQuickCheck.ps1 -UseDeviceCode

# Uložení výsledků do CSV
./Invoke-EntraQuickCheck.ps1 -ExportCsv ./vysledky.csv
```

Při prvním spuštění Microsoft požádá o souhlas s oprávněními `Policy.Read.All`, `RoleManagement.Read.Directory` a `Directory.Read.All`. Všechna jsou jen pro čtení.

## Ukázka výstupu

```
[RIZIKO  ] 1. Počet globálních administrátorů
           Aktivních přiřazení: 1 (doporučeno 2–4). admin@firma.cz — chybí záložní (break-glass) účet.
[OK      ] 2. Vynucení MFA
           CA politika pro všechny uživatele: Require MFA
[RIZIKO  ] 3. Blokování legacy autentizace
           Legacy protokoly (IMAP/POP/SMTP AUTH, ActiveSync) nejsou blokovány — obcházejí MFA.
...
Nalezená rizika: 3 z 6 kontrol.
```

## Omezení

- Jde o rychlý orientační test, ne o audit.
- U Conditional Access se nevyhodnocují výjimky (excluded users/groups). Politika „pro všechny“ s rozsáhlými výjimkami projde jako OK.
- Počítají se jen aktivní přiřazení rolí. Oprávnění přidělená přes PIM (eligible) skript nezahrnuje.

## Kompletní audit

Těchto 6 kontrol je malá část z celkem **50 kontrolních bodů**, které prochází audit Entra ID / Microsoft 365 od [Permetria](https://permetria.cz). Součástí auditu je zpráva s doporučeními a akční plán.

📧 martin.pavlicek@permetria.cz · 🌐 [permetria.cz](https://permetria.cz)

## Licence

MIT. Viz [LICENSE](LICENSE).
