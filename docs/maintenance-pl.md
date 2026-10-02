# Automatyczna instalacja i naprawa RDP Wrapper

Nowy program `RDPWMaint.exe` sam sprawdza instalację, obecność i integralność DLL,
rejestrację usługi, wpis INI dla dokładnej wersji Windows, załadowanie biblioteki
oraz lokalną odpowiedź serwera RDP. Działający host pozostawia bez zmian.

Uruchom w terminalu administratora:

```powershell
.\RDPWMaint.exe --check
.\RDPWMaint.exe --auto
```

`--auto` wykonuje potrzebną instalację lub naprawę bez pytań i okien UAC.
Odtwarza DLL z oryginalnej biblioteki zawartej w programie. Importuje wyłącznie
sekcje INI dla dokładnej wersji `termsrv.dll` i brakujące definicje kodów.
RDP w Windows musi już być włączone. Program nie wymaga restartu Windows.

Jeśli istnieje sesja zdalna, także rozłączona, program wstrzymuje zmiany i zwraca
kod 3. Konto zdalne trzeba wylogować; samo zamknięcie okna RDP nie wystarcza.
Nieudany odczyt sesji również blokuje naprawę. Przed zmianami powstaje kopia;
nieudana naprawa próbuje przywrócić wcześniejszy stan z zachowaniem ochrony sesji.

Przy nowej wersji Windows program sprawdza tekstowe konfiguracje w repozytoriach
forka, sebaxakerhtc, asmtron i stascorp. Jeśli brakuje poprawnego wpisu dla tej
dokładnej wersji, zatrzymuje się. Nie tworzy offsetów przez zgadywanie.
Kontrola składni i zakresów offsetów nie potwierdza poprawności instrukcji
maszynowych z konfiguracji społecznościowej.

Możesz podać własny, sprawdzony INI:

```powershell
.\RDPWMaint.exe --auto --source C:\konfiguracje\rdpwrap.ini
```

Opcjonalny harmonogram włączysz jednorazowo jako administrator:

```powershell
.\RDPWMaint.exe --task-plan
.\RDPWMaint.exe --register-task
```

Pierwsza komenda pokazuje plan. Druga zapisuje chronioną kopię programu w
`C:\Program Files\RDP Wrapper Maintenance` i tworzy zadanie SYSTEM: dwie minuty
po starcie Windows oraz co godzinę. Nie potrzebuje hasła ani zalogowanego konta.
Wstrzymana naprawa może zostać podjęta przy kolejnym uruchomieniu.
Samo `--auto` nie tworzy harmonogramu.

Usunięcie zadania: `RDPWMaint.exe --unregister-task` jako administrator.
Raporty i kopie administratora: `C:\ProgramData\RDPWrapperMaintenance`.
Raporty bez uprawnień administratora: `%LOCALAPPDATA%\RDPWrapperMaintenance`.

| Kod zakończenia | Znaczenie |
| --- | --- |
| 0 | Poprawny stan lub naprawa zakończona lokalną weryfikacją |
| 1 | Diagnostyka wymaga uwagi lub nie można potwierdzić załadowania DLL |
| 2 | Błąd; szczegóły w raporcie |
| 3 | Wstrzymano przez sesję zdalną lub inną naprawę |
| 4 | Potrzebne uprawnienia administratora |

Test lokalny nie zastępuje logowania z LAN. Po pierwszej naprawie sprawdź
jednoczesną pracę dwóch osób na osobnych kontach.

Budowanie ze źródeł: `src-maintenance\build.ps1 -Test`.
Potrzebny jest .NET Framework 4.8; dodatkowy SDK, Delphi i pobieranie pakietów
nie są wymagane. Testy operacji instalacji używają atrap usługi i plików
tymczasowych. Szczegóły techniczne są w [maintenance.md](maintenance.md).
