# 🌾 Perceel App

Percelen tekenen op de satellietkaart, banen met GPS-richting en breedte, vakken met soorten, en taken die iedereen live ziet.
Werkt op Android (APK) en op de computer (website die je kunt installeren).

Je hebt **drie gratis accounts** nodig: Supabase (de gedeelde database), GitHub (bouwt de app) en eventueel niks meer.
Reken op een half uurtje voor de eerste keer.

---

## Stap 1 – Database aanmaken (Supabase)

1. Ga naar **supabase.com** en maak een gratis account.
2. Klik **New project**. Kies een naam (bijv. `percelen`), een wachtwoord, en als regio **Frankfurt** (EU).
3. Wacht tot het project klaar is. Ga links naar **SQL Editor**.
4. Open het bestand `supabase/setup.sql`, kopieer alles, plak het in de SQL Editor en klik **Run** (één keer).
5. Maak een **nieuwe, lege query**, plak `supabase/beheer.sql` erin en klik **Run**. Bij de waarschuwing "destructive operations" klik je **Run query**.
   Dit zet de beheerder, rechten, soorten per plant, markeringen, uitgebreide taken en kassen/panden klaar.
   (Dit bestand mag je later gerust nog eens draaien.)
6. Ga naar **Project Settings → API** (of "API Keys"). Kopieer:
   - de **Project URL** (`https://....supabase.co`)
   - de **anon / publishable key**
7. Open `www/config.js` in Kladblok (rechtermuisknop → Openen met → Kladblok) en plak ze tussen de aanhalingstekens. Opslaan.

**Handig:** ga naar **Authentication → Sign In / Providers → Email** en zet **Confirm email** uit.
Dan kan iedereen direct inloggen na het aanmaken van een account, zonder bevestigingsmail.

**Belangrijk voor de veiligheid:** zet in hetzelfde scherm **Allow new users to sign up** uit.
Accounts maak je als beheerder in de app zelf aan (tabblad **Team**), dus niemand anders kan zich aanmelden.
Het allereerste account dat ooit wordt aangemaakt wordt automatisch beheerder.

---

## Stap 2 – Op GitHub zetten (eenmalig)

1. Zorg dat `www/config.js` jouw Supabase-URL en key bevat.
   Gebruik je Netlify? Zet je Netlify-link (bijv. `https://jouwnaam.netlify.app`) in **`app-adres.txt`**.
   De APK opent dan die website, en updates zet je gewoon op Netlify. Laat je het bestand leeg,
   dan gebruikt de APK de GitHub-website.
2. Op github.com: **+ → New repository**, naam `perceel-app`, kies **Public**, klik **Create repository**.
3. Ga in je nieuwe repository naar **Settings → Pages** en zet **Source** op **GitHub Actions**.
4. Ga terug naar het tabblad **Code**, klik **uploading an existing file** en sleep **alles uit de map `perceel-app`** erin
   (de mappen `.github`, `assets`, `signing`, `supabase`, `www` en de losse bestanden). Klik **Commit changes**.
5. Tabblad **Actions**: wacht tot "Bouw de app" groen is (±5–8 minuten).

Daarna heb je:
- **Website / computerversie:** `https://<jouw-github-naam>.github.io/perceel-app/`
  (in Chrome/Edge: installeer-icoontje in de adresbalk → staat als app op je computer)
- **Android-app:** rechts op de hoofdpagina **Releases → PerceelApp.apk**

## Stap 3 – Telefoons (eenmalig)

Open op de telefoon de Releases-pagina, download **PerceelApp.apk**, sta "onbekende bronnen" toe en installeer.
iPhone: open de websitelink in Safari → **Deel → Zet op beginscherm**.

## Locatie delen op de achtergrond

Alleen de **echte Android-app (APK)** kan je locatie blijven delen als het scherm uit is.
Je ziet dan bovenin je telefoon de melding "Perceel App · <tractor>". De website-app (via de link
geïnstalleerd) deelt alleen zolang hij open is en het scherm aan staat.
Tip: zet bij Instellingen → Apps → Perceel App → Batterij op **Onbeperkt**, anders kan Android hem na een tijd stilzetten.

## Automatische updates

De app haalt zichzelf op van je website. Nieuwe versie? Upload de gewijzigde bestanden op GitHub
(**Add file → Upload files**, in de juiste map). Na een paar minuten krijgt iedereen bovenin de melding
**"Er is een nieuwe versie — tik om te verversen"**. Een nieuwe APK installeren is niet meer nodig.

## Zo werkt de app

| Wat | Hoe |
|---|---|
| Veld, kas of pand toevoegen | **＋ Toevoegen** → kies wat het is → tik de hoeken aan → tik op het eerste punt → naam geven |
| Sporen | Open een veld of kas → richting (zelfde graden als de GPS, 0° = noord), breedte, eventueel aantal → **Sporen maken** |
| Sporen op de AB-lijn leggen | **Verschuif (m)** aanpassen tot ze precies goed liggen |
| Planten indelen | Kies een plant → er klapt een rijtje open met de soorten van die plant → kies er een → tik op sporen. Of vul "spoor 1 t/m 12" in |
| Wissel halverwege een spoor | **✂️ Wissel halverwege** → tik op de plek in het spoor (of knip meerdere sporen op X meter) → geef elk stuk een plant |
| Lagen | Per veld: **Blanco** (alleen omtrek), **Sporen**, **Markeringen**. 🗂️ op de kaart zet alle velden in één keer om |
| Markeringen | Laag Markeringen aan → 🚩 vlag met aantekening, ⬛ gebied (bijv. ziekte in de grond), ↔️ kopeinde (lijn over de rand + breedte), ✏️ lijn |
| Taken | **＋ Nieuwe taak**: werkzaamheden, omschrijving, wie, datum, en waar (hele veld, bepaalde sporen of zelf getekend stuk). Tik op een taak → dat stuk licht roze op |
| Mijn taken | Tabblad **Taken** → **Voor mij** |
| Planten en soorten | Tabblad **Planten**: plant toevoegen, aantikken, soorten eronder toevoegen, kleuren kiezen |
| Team (alleen beheerder) | Tabblad **Team**: accounts aanmaken, 🔑 wachtwoord resetten, 🛡️ per persoon aanvinken wat hij mag, ⭐ beheerder maken |
| Eigen wachtwoord | 🔑 bovenin |

Alles wat iemand verandert, zien de anderen direct. Wat iemand niet mag, wordt ook in de database tegengehouden.

## Voor later: tractoren
De tabel `tractoren` staat al klaar. Zodra een GPS-kastje zijn `lat`, `lng` en `naam` daarin schrijft,
verschijnt de tractor 🚜 live op ieders kaart.

## Wat zit erin
- `www/` – de app zelf (index.html) en `config.js` met je database-gegevens
- `supabase/setup.sql` – maakt de database aan
- `.github/workflows/bouw-app.yml` – bouwt de APK en de website
- `assets/` – app-icoon en opstartscherm
- `signing/` – vaste sleutel zodat updates over de oude versie heen installeren
