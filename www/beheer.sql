-- ============================================================
--  Perceel App – beheerder, medewerkers en rechten per persoon
--  Plak dit hele bestand in Supabase → SQL Editor → Run
--  (mag vaker gedraaid worden)
-- ============================================================

-- 1. Profielen met rol en rechten
create table if not exists public.profielen (
  id          uuid primary key references auth.users(id) on delete cascade,
  naam        text not null,
  email       text,
  rol         text not null default 'medewerker' check (rol in ('beheerder','medewerker')),
  rechten     jsonb not null default '{}',
  created_at  timestamptz not null default now()
);
alter table public.profielen add column if not exists rechten jsonb not null default '{}';

-- Standaardrechten voor een nieuwe medewerker
create or replace function public.standaard_rechten() returns jsonb language sql immutable as $$
  select '{"percelen_tekenen":true,"percelen_bewerken":true,"spuitsporen_bewerken":true,"deelvelden_bewerken":true,
           "percelen_uitschakelen":false,"percelen_verwijderen":false,
           "soorten_indelen":true,"soorten_beheren":false,
           "taken_toevoegen":true,"taken_afvinken":true,"werk_registreren":true,"taken_verwijderen":false,
           "markeringen_maken":true,"weer_bekijken":true,"historie_bekijken":true,"seizoen_starten":false,
           "tractoren_volgen":true,"tractor_rijden":true,"tractoren_beheren":false,
           "uren_bekijken":false,"uren_beheren":false,"uren_mailen":false,
           "middelen_beheren":false,"oogst_registreren":true,"oogst_bekijken":true,
           "machines_beheren":false,"kosten_bekijken":false,
           "percelen_aanpassen":false,"kopeinden_bewerken":true,"gerooid_aangeven":true}'::jsonb;
$$;
alter table public.profielen alter column rechten set default public.standaard_rechten();
-- nieuwe rechten aanvullen, bestaande keuzes blijven staan
update public.profielen set rechten = public.standaard_rechten() || rechten where true;

alter table public.profielen enable row level security;
drop policy if exists "lezen" on public.profielen;
create policy "lezen" on public.profielen for select to authenticated using (true);

-- Nieuw account → automatisch een profiel (allereerste account wordt beheerder)
create or replace function public.nieuw_profiel() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profielen (id, naam, email, rol)
  values (new.id,
          coalesce(nullif(new.raw_user_meta_data->>'naam',''), split_part(new.email,'@',1)),
          new.email,
          case when exists (select 1 from public.profielen) then 'medewerker' else 'beheerder' end)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists bij_nieuw_account on auth.users;
create trigger bij_nieuw_account after insert on auth.users
  for each row execute function public.nieuw_profiel();

-- Bestaande accounts een profiel geven, en Siem hoofdbeheerder maken
insert into public.profielen (id, naam, email)
select id, coalesce(nullif(raw_user_meta_data->>'naam',''), split_part(email,'@',1)), email
from auth.users on conflict (id) do nothing;
update public.profielen set rol = 'beheerder' where lower(email) = 'siem.litjens@outlook.com';

-- 2. Hulpfuncties
create or replace function public.is_beheerder() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profielen where id = auth.uid() and rol = 'beheerder');
$$;
create or replace function public.heeft_recht(r text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profielen
                 where id = auth.uid() and (rol = 'beheerder' or coalesce((rechten->>r)::boolean, false)));
$$;

-- 3. Accounts beheren (alleen beheerder)
drop function if exists public.maak_medewerker(text,text,text,text);
create or replace function public.maak_medewerker(p_email text, p_wachtwoord text, p_naam text,
                                                  p_rol text default 'medewerker', p_rechten jsonb default null)
returns uuid language plpgsql security definer set search_path = '' as $$
declare uid uuid := gen_random_uuid(); e text := lower(trim(p_email));
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag accounts aanmaken'; end if;
  if e !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'Ongeldig e-mailadres'; end if;
  if length(coalesce(p_wachtwoord,'')) < 6 then raise exception 'Wachtwoord moet minimaal 6 tekens zijn'; end if;
  if p_rol not in ('beheerder','medewerker') then raise exception 'Onbekende rol'; end if;
  if exists (select 1 from auth.users where lower(email) = e) then raise exception 'Dit e-mailadres heeft al een account'; end if;

  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change, email_change_token_new)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', e,
    extensions.crypt(p_wachtwoord, extensions.gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}', jsonb_build_object('naam', trim(p_naam)), now(), now(),
    '', '', '', '');

  insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid, uid::text,
    jsonb_build_object('sub', uid::text, 'email', e, 'email_verified', true), 'email', now(), now(), now());

  update public.profielen
     set rol = p_rol, naam = trim(p_naam), rechten = coalesce(p_rechten, public.standaard_rechten())
   where id = uid;
  return uid;
end $$;

create or replace function public.zet_wachtwoord(p_id uuid, p_wachtwoord text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag dit'; end if;
  if length(coalesce(p_wachtwoord,'')) < 6 then raise exception 'Wachtwoord moet minimaal 6 tekens zijn'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_wachtwoord, extensions.gen_salt('bf')), updated_at = now()
  where id = p_id;
end $$;

create or replace function public.wijzig_medewerker(p_id uuid, p_naam text, p_rol text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag dit'; end if;
  if p_id = auth.uid() and p_rol <> 'beheerder' then raise exception 'Je kunt jezelf niet terugzetten naar medewerker'; end if;
  if p_rol not in ('beheerder','medewerker') then raise exception 'Onbekende rol'; end if;
  update public.profielen set naam = coalesce(nullif(trim(p_naam),''), naam), rol = p_rol where id = p_id;
end $$;

create or replace function public.zet_rechten(p_id uuid, p_rechten jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag rechten wijzigen'; end if;
  update public.profielen set rechten = public.standaard_rechten() || p_rechten where id = p_id;
end $$;

create or replace function public.verwijder_medewerker(p_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag dit'; end if;
  if p_id = auth.uid() then raise exception 'Je kunt je eigen account niet verwijderen'; end if;
  delete from auth.users where id = p_id;
end $$;

revoke all on function public.maak_medewerker(text,text,text,text,jsonb), public.zet_wachtwoord(uuid,text),
  public.wijzig_medewerker(uuid,text,text), public.zet_rechten(uuid,jsonb), public.verwijder_medewerker(uuid) from public, anon;
grant execute on function public.maak_medewerker(text,text,text,text,jsonb), public.zet_wachtwoord(uuid,text),
  public.wijzig_medewerker(uuid,text,text), public.zet_rechten(uuid,jsonb), public.verwijder_medewerker(uuid),
  public.is_beheerder(), public.heeft_recht(text) to authenticated;

-- 4. Rechten afdwingen op de tabellen
-- Percelen
drop policy if exists "team" on public.percelen;
drop policy if exists "lezen" on public.percelen;
drop policy if exists "toevoegen" on public.percelen;
drop policy if exists "wijzigen" on public.percelen;
drop policy if exists "verwijderen" on public.percelen;
create policy "lezen"       on public.percelen for select to authenticated using (true);
create policy "toevoegen"   on public.percelen for insert to authenticated with check (public.heeft_recht('percelen_tekenen'));
create policy "wijzigen"    on public.percelen for update to authenticated
  using (public.heeft_recht('percelen_bewerken') or public.heeft_recht('soorten_indelen') or public.heeft_recht('spuitsporen_bewerken')
      or public.heeft_recht('deelvelden_bewerken') or public.heeft_recht('percelen_uitschakelen')) with check (true);
create policy "verwijderen" on public.percelen for delete to authenticated using (public.heeft_recht('percelen_verwijderen'));

-- Soort perceel: veld, trayveld, kas of bedrijfspand
alter table public.percelen add column if not exists type text not null default 'veld';
alter table public.percelen drop constraint if exists percelen_type_check;
alter table public.percelen add constraint percelen_type_check check (type in ('veld','tray','kas','pand'));

-- Vakken: deelgebieden met een eigen rijrichting
alter table public.percelen add column if not exists vakken jsonb not null default '[]';
-- Spuitsporen: {elke, start, extra: [nrs], uit: [nrs]}
alter table public.percelen add column if not exists spuit jsonb;

alter table public.percelen add column if not exists uitgeschakeld boolean not null default false;
-- Vast A-punt van de GPS-lijn ([lengtegraad, breedtegraad]) en of dat punt op het midden of de rand van een spoor ligt
alter table public.percelen add column if not exists ab_punt jsonb;
alter table public.percelen add column if not exists ab_uitlijning text not null default 'midden';
-- Eigen icoontje per plant (emoji of een ingebouwd icoon zoals 'svg:asperge')
alter table public.soorten add column if not exists icoon text;
-- Eén gewas voor het hele perceel (zonder sporen), bijv. braak of groenbemester
alter table public.percelen add column if not exists gewas text;
-- Aantal planten per teelt: {teelt-id: {per_rij, per_m2}}
alter table public.percelen add column if not exists beplanting jsonb not null default '{}';
insert into public.soorten (naam, kleur) select 'Groenbemester', '#9ccc65' where not exists (select 1 from public.soorten where lower(naam) = 'groenbemester');
insert into public.soorten (naam, kleur) select 'Braak', '#8d6e63' where not exists (select 1 from public.soorten where lower(naam) = 'braak');

create or replace function public.controleer_perceel() returns trigger language plpgsql as $$
declare
  nv jsonb := (select coalesce(jsonb_agg(v - 'banen' - 'spuit' - 'gewas'), '[]') from jsonb_array_elements(coalesce(new.vakken, '[]')) v);
  ov jsonb := (select coalesce(jsonb_agg(v - 'banen' - 'spuit' - 'gewas'), '[]') from jsonb_array_elements(coalesce(old.vakken, '[]')) v);
  nb jsonb := (select coalesce(jsonb_agg(jsonb_build_array(v -> 'banen', v -> 'gewas')), '[]') from jsonb_array_elements(coalesce(new.vakken, '[]')) v);
  ob jsonb := (select coalesce(jsonb_agg(jsonb_build_array(v -> 'banen', v -> 'gewas')), '[]') from jsonb_array_elements(coalesce(old.vakken, '[]')) v);
  ns jsonb := (select coalesce(jsonb_agg(v -> 'spuit'), '[]') from jsonb_array_elements(coalesce(new.vakken, '[]')) v);
  os jsonb := (select coalesce(jsonb_agg(v -> 'spuit'), '[]') from jsonb_array_elements(coalesce(old.vakken, '[]')) v);
begin
  if auth.uid() is null then return new; end if;   -- SQL Editor / systeem
  if current_setting('perceel.systeem', true) = '1' then return new; end if;   -- bijv. bij het starten van een seizoen
  if (new.banen is distinct from old.banen or new.gewas is distinct from old.gewas or new.beplanting is distinct from old.beplanting or nb is distinct from ob) and not public.heeft_recht('soorten_indelen') then
    raise exception 'Je mag geen planten op sporen indelen';
  end if;
  if (new.spuit is distinct from old.spuit or ns is distinct from os) and not public.heeft_recht('spuitsporen_bewerken') then
    raise exception 'Je mag geen spuitsporen aanpassen';
  end if;
  if nv is distinct from ov and not public.heeft_recht('deelvelden_bewerken') then
    raise exception 'Je mag geen deelvelden aanpassen';
  end if;
  if new.uitgeschakeld is distinct from old.uitgeschakeld and not public.heeft_recht('percelen_uitschakelen') then
    raise exception 'Je mag percelen niet uit- of inschakelen';
  end if;
  if (new.naam, new.geo, new.richting, new.breedte, new.aantal, new.verschuiving, new.banen_aan, new.type, new.ab_punt, new.ab_uitlijning)
     is distinct from (old.naam, old.geo, old.richting, old.breedte, old.aantal, old.verschuiving, old.banen_aan, old.type, old.ab_punt, old.ab_uitlijning)
     and not public.heeft_recht('percelen_bewerken') then
    raise exception 'Je mag percelen niet bewerken';
  end if;
  return new;
end $$;
drop trigger if exists perceel_rechten on public.percelen;
create trigger perceel_rechten before update on public.percelen for each row execute function public.controleer_perceel();

-- Soorten
drop policy if exists "team" on public.soorten;
drop policy if exists "lezen" on public.soorten;
drop policy if exists "beheer" on public.soorten;
create policy "lezen"  on public.soorten for select to authenticated using (true);
create policy "beheer" on public.soorten for all to authenticated
  using (public.heeft_recht('soorten_beheren')) with check (public.heeft_recht('soorten_beheren'));

-- Taken
drop policy if exists "team" on public.taken;
drop policy if exists "lezen" on public.taken;
drop policy if exists "toevoegen" on public.taken;
drop policy if exists "wijzigen" on public.taken;
drop policy if exists "verwijderen" on public.taken;
create policy "lezen"       on public.taken for select to authenticated using (true);
create policy "toevoegen"   on public.taken for insert to authenticated
  with check ((not klaar and public.heeft_recht('taken_toevoegen')) or (klaar and public.heeft_recht('werk_registreren')));
create policy "wijzigen"    on public.taken for update to authenticated
  using (public.heeft_recht('taken_afvinken') or public.heeft_recht('taken_toevoegen')) with check (true);
create policy "verwijderen" on public.taken for delete to authenticated using (public.heeft_recht('taken_verwijderen'));

-- Uitgebreide taken: werkzaamheden, wie, welk stuk van het veld
alter table public.taken add column if not exists omschrijving   text;
alter table public.taken add column if not exists toegewezen_aan uuid references public.profielen(id) on delete set null;
alter table public.taken add column if not exists gebied         jsonb;     -- zelf getekend stuk van het veld
alter table public.taken add column if not exists spoor_van      integer;   -- of: sporen van … t/m …
alter table public.taken add column if not exists spoor_tot      integer;

-- Uitgevoerd werk: wat er gebruikt is en hoeveel
alter table public.taken add column if not exists product    text;
alter table public.taken add column if not exists dosering   numeric;
alter table public.taken add column if not exists eenheid    text;
alter table public.taken add column if not exists uitvoering text;
-- Verplaatsen: iets (bijv. een Dixi of planten) van de ene naar de andere plek brengen
alter table public.taken add column if not exists soort          text not null default 'werk';
alter table public.taken add column if not exists wat            text;
alter table public.taken add column if not exists aantal         numeric;
alter table public.taken add column if not exists aantal_eenheid text;
alter table public.taken add column if not exists van_perceel    uuid references public.percelen(id) on delete set null;
alter table public.taken add column if not exists van_punt       jsonb;
alter table public.taken add column if not exists naar_perceel   uuid references public.percelen(id) on delete set null;
alter table public.taken add column if not exists naar_punt      jsonb;
alter table public.taken alter column perceel_id drop not null;

-- Bezig: wie er nu mee bezig is
alter table public.taken add column if not exists bezig_door  text;
alter table public.taken add column if not exists bezig_sinds timestamptz;

-- Planning: op welke dag de taak gepland staat
alter table public.taken add column if not exists gepland date;
create index if not exists taken_gepland on public.taken (gepland);

create or replace function public.controleer_taak() returns trigger language plpgsql as $$
begin
  if auth.uid() is null then return new; end if;
  if (new.klaar, new.klaar_door, new.klaar_op, new.product, new.dosering, new.eenheid, new.uitvoering, new.bezig_door, new.bezig_sinds)
     is distinct from (old.klaar, old.klaar_door, old.klaar_op, old.product, old.dosering, old.eenheid, old.uitvoering, old.bezig_door, old.bezig_sinds)
     and not public.heeft_recht('taken_afvinken') then
    raise exception 'Je mag taken niet afvinken';
  end if;
  if (new.tekst, new.deadline, new.gepland, new.perceel_id, new.omschrijving, new.toegewezen_aan, new.gebied, new.spoor_van, new.spoor_tot,
      new.soort, new.wat, new.aantal, new.aantal_eenheid, new.van_perceel, new.van_punt, new.naar_perceel, new.naar_punt)
     is distinct from (old.tekst, old.deadline, old.gepland, old.perceel_id, old.omschrijving, old.toegewezen_aan, old.gebied, old.spoor_van, old.spoor_tot,
      old.soort, old.wat, old.aantal, old.aantal_eenheid, old.van_perceel, old.van_punt, old.naar_perceel, old.naar_punt)
     and not public.heeft_recht('taken_toevoegen') then
    raise exception 'Je mag taken niet wijzigen';
  end if;
  return new;
end $$;
drop trigger if exists taak_rechten on public.taken;
create trigger taak_rechten before update on public.taken for each row execute function public.controleer_taak();

-- Tractoren: iedereen kijken, alleen beheerder wijzigen
drop policy if exists "team" on public.tractoren;
drop policy if exists "lezen" on public.tractoren;
drop policy if exists "beheer" on public.tractoren;
create policy "lezen"  on public.tractoren for select to authenticated using (true);
create policy "beheer" on public.tractoren for all to authenticated
  using (public.heeft_recht('tractoren_beheren')) with check (public.heeft_recht('tractoren_beheren'));

-- 5. Teamlijst en rechten live bijwerken
do $$ begin
  alter publication supabase_realtime add table public.profielen;
exception when duplicate_object then null; end $$;

-- 6. Soorten per plant (bijv. Aardappel → Bintje, Agria)
--    De tabel "soorten" bevat de planten; "rassen" de soorten van elke plant.
create table if not exists public.rassen (
  id          uuid primary key default gen_random_uuid(),
  soort_id    uuid not null references public.soorten(id) on delete cascade,
  naam        text not null,
  kleur       text,
  created_at  timestamptz not null default now()
);
alter table public.rassen enable row level security;
drop policy if exists "lezen" on public.rassen;
drop policy if exists "beheer" on public.rassen;
create policy "lezen"  on public.rassen for select to authenticated using (true);
create policy "beheer" on public.rassen for all to authenticated
  using (public.heeft_recht('soorten_beheren')) with check (public.heeft_recht('soorten_beheren'));
do $$ begin
  alter publication supabase_realtime add table public.rassen;
exception when duplicate_object then null; end $$;

-- 7. Markeringen: vlaggen met aantekeningen, gebieden (bijv. ziekte in de grond), lijnen en kopeindes
create table if not exists public.markeringen (
  id              uuid primary key default gen_random_uuid(),
  perceel_id      uuid references public.percelen(id) on delete cascade,
  soort           text not null check (soort in ('vlag','gebied','lijn','kopeinde')),
  geo             jsonb not null,
  titel           text not null default '',
  notitie         text,
  kleur           text not null default '#e53935',
  breedte         numeric,                       -- breedte van een kopeinde in meters
  aangemaakt_door text,
  created_at      timestamptz not null default now()
);
alter table public.markeringen enable row level security;
drop policy if exists "lezen" on public.markeringen;
drop policy if exists "maken" on public.markeringen;
create policy "lezen" on public.markeringen for select to authenticated using (true);
create policy "maken" on public.markeringen for all to authenticated
  using (public.heeft_recht('markeringen_maken')) with check (public.heeft_recht('markeringen_maken'));
do $$ begin
  alter publication supabase_realtime add table public.markeringen;
exception when duplicate_object then null; end $$;

-- 9. Tractoren live volgen
--    Een telefoon in de trekker (ingelogd) meldt zijn positie via meld_positie().
--    Later kan een GPS-kastje of Traccar dat doen via meld_positie_sleutel() met de geheime sleutel.
alter table public.tractoren add column if not exists bestuurder     text;
alter table public.tractoren add column if not exists nauwkeurigheid numeric;
alter table public.tractoren alter column bijgewerkt drop not null;
alter table public.tractoren alter column bijgewerkt set default null;

create table if not exists public.tractor_sleutels (
  tractor_id uuid primary key references public.tractoren(id) on delete cascade,
  sleutel    uuid not null default gen_random_uuid()
);
alter table public.tractor_sleutels enable row level security;
drop policy if exists "beheerder" on public.tractor_sleutels;
create policy "beheerder" on public.tractor_sleutels for select to authenticated using (public.heeft_recht('tractoren_beheren'));
insert into public.tractor_sleutels (tractor_id) select id from public.tractoren on conflict do nothing;

create or replace function public.nieuwe_tractor_sleutel() returns trigger
language plpgsql security definer set search_path = '' as $$
begin insert into public.tractor_sleutels (tractor_id) values (new.id) on conflict do nothing; return new; end $$;
drop trigger if exists tractor_sleutel on public.tractoren;
create trigger tractor_sleutel after insert on public.tractoren for each row execute function public.nieuwe_tractor_sleutel();

create table if not exists public.tractor_posities (
  id          bigserial primary key,
  tractor_id  uuid not null references public.tractoren(id) on delete cascade,
  lat         double precision not null,
  lng         double precision not null,
  richting    numeric,
  snelheid    numeric,
  tijd        timestamptz not null default now()
);
create index if not exists tractor_posities_tijd on public.tractor_posities (tractor_id, tijd desc);
alter table public.tractor_posities enable row level security;
drop policy if exists "lezen" on public.tractor_posities;
create policy "lezen" on public.tractor_posities for select to authenticated using (true);

create or replace function public.zet_positie(p_tractor uuid, p_lat double precision, p_lng double precision,
  p_richting numeric, p_snelheid numeric, p_nauwkeurigheid numeric, p_bestuurder text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_lat not between -90 and 90 or p_lng not between -180 and 180 then raise exception 'Ongeldige positie'; end if;
  update public.tractoren set lat = p_lat, lng = p_lng, richting = p_richting, snelheid = p_snelheid,
         nauwkeurigheid = p_nauwkeurigheid, bestuurder = coalesce(p_bestuurder, bestuurder), bijgewerkt = now()
   where id = p_tractor;
  if not found then raise exception 'Onbekende tractor'; end if;
  insert into public.tractor_posities (tractor_id, lat, lng, richting, snelheid) values (p_tractor, p_lat, p_lng, p_richting, p_snelheid);
  -- af en toe oude routes opruimen (ouder dan 30 dagen)
  if random() < 0.01 then delete from public.tractor_posities where tijd < now() - interval '30 days'; end if;
end $$;
revoke all on function public.zet_positie(uuid,double precision,double precision,numeric,numeric,numeric,text) from public, anon, authenticated;

-- vanaf een ingelogde telefoon
create or replace function public.meld_positie(p_tractor uuid, p_lat double precision, p_lng double precision,
  p_richting numeric default null, p_snelheid numeric default null, p_nauwkeurigheid numeric default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('tractor_rijden') then raise exception 'Je mag geen locatie delen als tractor'; end if;
  perform public.zet_positie(p_tractor, p_lat, p_lng, p_richting, p_snelheid, p_nauwkeurigheid,
    (select naam from public.profielen where id = auth.uid()));
end $$;

-- vanaf een GPS-kastje of Traccar (zonder inloggen, met de geheime sleutel)
create or replace function public.meld_positie_sleutel(p_sleutel uuid, p_lat double precision, p_lng double precision,
  p_richting numeric default null, p_snelheid numeric default null)
returns void language plpgsql security definer set search_path = '' as $$
declare tid uuid;
begin
  select tractor_id into tid from public.tractor_sleutels where sleutel = p_sleutel;
  if tid is null then raise exception 'Onbekende sleutel'; end if;
  perform public.zet_positie(tid, p_lat, p_lng, p_richting, p_snelheid, null, null);
end $$;

-- stoppen met rijden
create or replace function public.stop_positie(p_tractor uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('tractor_rijden') then return; end if;
  update public.tractoren set bestuurder = null where id = p_tractor;
end $$;

grant execute on function public.meld_positie(uuid,double precision,double precision,numeric,numeric,numeric), public.stop_positie(uuid) to authenticated;
grant execute on function public.meld_positie_sleutel(uuid,double precision,double precision,numeric,numeric) to anon, authenticated;

-- 10. Seizoenen: per seizoen de taken/werkregistratie, en bij een nieuw seizoen een momentopname
--     van elk perceel (wat er stond, sporen, vakken).
create table if not exists public.seizoenen (
  id           uuid primary key default gen_random_uuid(),
  naam         text not null,
  actief       boolean not null default false,
  gestart      timestamptz not null default now(),
  gestart_door text
);
create unique index if not exists seizoenen_een_actief on public.seizoenen (actief) where actief;
create table if not exists public.seizoen_percelen (
  seizoen_id  uuid not null references public.seizoenen(id) on delete cascade,
  perceel_id  uuid not null,
  gegevens    jsonb not null,
  primary key (seizoen_id, perceel_id)
);
alter table public.seizoenen enable row level security;
alter table public.seizoen_percelen enable row level security;
drop policy if exists "lezen" on public.seizoenen;
drop policy if exists "lezen" on public.seizoen_percelen;
create policy "lezen" on public.seizoenen for select to authenticated using (true);
create policy "lezen" on public.seizoen_percelen for select to authenticated using (public.heeft_recht('historie_bekijken'));

insert into public.seizoenen (naam, actief)
select extract(year from now())::text, true where not exists (select 1 from public.seizoenen);

alter table public.taken add column if not exists seizoen_id uuid references public.seizoenen(id) on delete set null;
update public.taken set seizoen_id = (select id from public.seizoenen where actief) where seizoen_id is null;
create index if not exists taken_seizoen on public.taken (seizoen_id);

create or replace function public.taak_seizoen() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.seizoen_id is null then new.seizoen_id := (select id from public.seizoenen where actief); end if;
  return new;
end $$;
drop trigger if exists taak_seizoen on public.taken;
create trigger taak_seizoen before insert on public.taken for each row execute function public.taak_seizoen();

drop function if exists public.start_seizoen(text, boolean, boolean);
create or replace function public.start_seizoen(p_naam text, p_leegmaken boolean, p_open_meenemen boolean, p_inschakelen boolean default true)
returns uuid language plpgsql security definer set search_path = '' as $$
declare oud uuid; nieuw uuid;
begin
  if not public.heeft_recht('seizoen_starten') then raise exception 'Je mag geen nieuw seizoen starten'; end if;
  perform set_config('perceel.systeem', '1', true);
  if coalesce(trim(p_naam), '') = '' then raise exception 'Geef het seizoen een naam'; end if;
  select id into oud from public.seizoenen where actief;
  -- momentopname van alle percelen bij het afsluiten van het oude seizoen
  if oud is not null then
    insert into public.seizoen_percelen (seizoen_id, perceel_id, gegevens)
    select oud, p.id, to_jsonb(p) from public.percelen p
    on conflict (seizoen_id, perceel_id) do update set gegevens = excluded.gegevens;
    update public.seizoenen set actief = false where id = oud;
  end if;
  insert into public.seizoenen (naam, actief, gestart_door)
  values (trim(p_naam), true, (select naam from public.profielen where id = auth.uid())) returning id into nieuw;
  if p_open_meenemen and oud is not null then
    update public.taken set seizoen_id = nieuw where seizoen_id = oud and not klaar;
  end if;
  if p_inschakelen then update public.percelen set uitgeschakeld = false where uitgeschakeld; end if;
  if p_leegmaken then
    update public.percelen set banen = '[]'::jsonb, gewas = null, beplanting = '{}'::jsonb,
      vakken = (select coalesce(jsonb_agg((v - 'gewas') || '{"banen":[]}'::jsonb), '[]'::jsonb) from jsonb_array_elements(coalesce(vakken, '[]'::jsonb)) v)
    where true;   -- Supabase weigert een UPDATE zonder WHERE
  end if;
  return nieuw;
end $$;
create or replace function public.hernoem_seizoen(p_id uuid, p_naam text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('seizoen_starten') then raise exception 'Je mag seizoenen niet beheren'; end if;
  if coalesce(trim(p_naam), '') = '' then raise exception 'Geef het seizoen een naam'; end if;
  update public.seizoenen set naam = trim(p_naam) where id = p_id;
end $$;
revoke all on function public.hernoem_seizoen(uuid, text) from public, anon;
grant execute on function public.hernoem_seizoen(uuid, text) to authenticated;
revoke all on function public.start_seizoen(text, boolean, boolean, boolean) from public, anon;
grant execute on function public.start_seizoen(text, boolean, boolean, boolean) to authenticated;

do $$ begin
  alter publication supabase_realtime add table public.seizoenen;
exception when duplicate_object then null; end $$;

-- ============================================================
-- Uren: hoe lang iemand met een taak bezig is geweest
-- Elke keer dat iemand op "Ik ben bezig" drukt begint er een regel,
-- bij "Niet meer bezig" of afronden stopt hij. Dit gebeurt in de database zelf.
-- ============================================================
create table if not exists public.uren (
  id          uuid primary key default gen_random_uuid(),
  taak_id     uuid references public.taken(id) on delete set null,
  taak_tekst  text,
  perceel_id  uuid references public.percelen(id) on delete set null,
  user_id     uuid references auth.users(id) on delete set null,
  naam        text not null,
  start       timestamptz not null default now(),
  eind        timestamptz,
  opmerking   text,
  handmatig   boolean not null default false,
  created_at  timestamptz not null default now(),
  constraint uren_volgorde check (eind is null or eind >= start)
);
create index if not exists uren_start on public.uren (start);
create index if not exists uren_open  on public.uren (taak_id) where eind is null;

alter table public.uren enable row level security;
drop policy if exists "lezen"       on public.uren;
drop policy if exists "toevoegen"   on public.uren;
drop policy if exists "wijzigen"    on public.uren;
drop policy if exists "verwijderen" on public.uren;
create policy "lezen"       on public.uren for select to authenticated using (public.heeft_recht('uren_bekijken') or user_id = auth.uid());
create policy "toevoegen"   on public.uren for insert to authenticated with check (public.heeft_recht('uren_beheren'));
create policy "wijzigen"    on public.uren for update to authenticated using (public.heeft_recht('uren_beheren')) with check (true);
create policy "verwijderen" on public.uren for delete to authenticated using (public.heeft_recht('uren_beheren'));

create or replace function public.taak_uren() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'DELETE' then
    update public.uren set eind = now() where taak_id = old.id and eind is null;
    return old;
  end if;
  if new.bezig_door is distinct from old.bezig_door
     or (new.bezig_door is not null and new.bezig_sinds is distinct from old.bezig_sinds) then
    update public.uren set eind = greatest(now(), start) where taak_id = new.id and eind is null;
    if new.bezig_door is not null and not new.klaar then
      insert into public.uren (taak_id, taak_tekst, perceel_id, user_id, naam, start)
      values (new.id, new.tekst, coalesce(new.perceel_id, new.van_perceel, new.naar_perceel),
              coalesce(auth.uid(), (select id from public.profielen where naam = new.bezig_door limit 1)),
              new.bezig_door, coalesce(new.bezig_sinds, now()));
    end if;
  end if;
  if new.tekst is distinct from old.tekst then
    update public.uren set taak_tekst = new.tekst where taak_id = new.id;
  end if;
  return new;
end $$;
drop trigger if exists taak_uren on public.taken;
create trigger taak_uren after update on public.taken for each row execute function public.taak_uren();
drop trigger if exists taak_uren_weg on public.taken;
create trigger taak_uren_weg before delete on public.taken for each row execute function public.taak_uren();

-- Wie nu al bezig is, krijgt meteen een lopende regel
insert into public.uren (taak_id, taak_tekst, perceel_id, user_id, naam, start)
select t.id, t.tekst, coalesce(t.perceel_id, t.van_perceel, t.naar_perceel),
       (select id from public.profielen where naam = t.bezig_door limit 1), t.bezig_door, coalesce(t.bezig_sinds, now())
from public.taken t
where t.bezig_door is not null and not t.klaar
  and not exists (select 1 from public.uren u where u.taak_id = t.id and u.eind is null);

do $$ begin
  alter publication supabase_realtime add table public.uren;
exception when duplicate_object then null; end $$;

-- ============================================================
-- Mail: urenoverzicht versturen naar een vast e-mailadres (via Resend)
-- ============================================================
create extension if not exists pg_net with schema extensions;

create table if not exists public.instellingen (
  sleutel text primary key,
  waarde  text
);
alter table public.instellingen enable row level security;
drop policy if exists "lezen" on public.instellingen;
create policy "lezen" on public.instellingen for select to authenticated using (true);

-- Geheime sleutels: niemand kan ze lezen, alleen de functies hieronder
create table if not exists public.geheimen (
  sleutel text primary key,
  waarde  text
);
alter table public.geheimen enable row level security;
revoke all on public.geheimen from anon, authenticated;

create or replace function public.zet_mail(p_aan text, p_van text, p_sleutel text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag dit instellen'; end if;
  insert into public.instellingen values ('mail_aan', nullif(trim(p_aan), ''))
    on conflict (sleutel) do update set waarde = excluded.waarde;
  insert into public.instellingen values ('mail_van', nullif(trim(p_van), ''))
    on conflict (sleutel) do update set waarde = excluded.waarde;
  if p_sleutel is not null then            -- null = sleutel laten zoals hij is, '' = wissen
    if trim(p_sleutel) = '' then
      delete from public.geheimen where sleutel = 'resend';
    else
      insert into public.geheimen values ('resend', trim(p_sleutel))
        on conflict (sleutel) do update set waarde = excluded.waarde;
    end if;
  end if;
  insert into public.instellingen values ('mail_sleutel',
      case when exists (select 1 from public.geheimen where sleutel = 'resend') then '1' else null end)
    on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;

drop function if exists public.verstuur_mail(text, text, text);
create or replace function public.verstuur_mail(p_onderwerp text, p_html text, p_tekst text,
                                               p_bijlage text default null, p_bijlage_naam text default null)
returns bigint language plpgsql security definer set search_path = '' as $$
declare aan text; van text; sl text; req bigint;
begin
  if not public.heeft_recht('uren_mailen') then raise exception 'Je mag geen urenoverzicht mailen'; end if;
  select waarde into aan from public.instellingen where sleutel = 'mail_aan';
  select waarde into van from public.instellingen where sleutel = 'mail_van';
  select waarde into sl  from public.geheimen     where sleutel = 'resend';
  if coalesce(aan, '') = '' then raise exception 'Er is nog geen e-mailadres ingesteld'; end if;
  if coalesce(sl, '') = ''  then raise exception 'Er is nog geen Resend-sleutel ingesteld'; end if;
  select net.http_post(
    url     := 'https://api.resend.com/emails',
    headers := jsonb_build_object('Authorization', 'Bearer ' || sl, 'Content-Type', 'application/json'),
    body    := jsonb_build_object(
      'from',    coalesce(nullif(van, ''), 'Perceel App <onboarding@resend.dev>'),
      'to',      to_jsonb(regexp_split_to_array(regexp_replace(aan, '\s', '', 'g'), '[,;]+')),
      'subject', left(coalesce(p_onderwerp, 'Urenoverzicht'), 200),
      'html',    p_html,
      'text',    p_tekst)
      || case when coalesce(p_bijlage, '') <> '' then jsonb_build_object('attachments', jsonb_build_array(
           jsonb_build_object('filename', coalesce(nullif(p_bijlage_naam, ''), 'uren.xlsx'), 'content', p_bijlage))) else '{}'::jsonb end,
    timeout_milliseconds := 10000) into req;
  return req;
end $$;

create or replace function public.mail_status(p_id bigint)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare r record;
begin
  if not public.heeft_recht('uren_mailen') then return null; end if;
  select status_code, content::text as inhoud, error_msg into r from net._http_response where id = p_id;
  if not found then return null; end if;
  return jsonb_build_object('status', r.status_code, 'inhoud', left(r.inhoud, 500), 'fout', r.error_msg);
end $$;

revoke all on function public.zet_mail(text, text, text), public.verstuur_mail(text, text, text, text, text), public.mail_status(bigint) from public, anon;
grant execute on function public.zet_mail(text, text, text), public.verstuur_mail(text, text, text, text, text), public.mail_status(bigint) to authenticated;

-- ============================================================
-- Foto's bij vlaggen/markeringen en taken
-- De foto's zelf staan in de (niet-openbare) opslagmap "fotos"
-- ============================================================
alter table public.markeringen add column if not exists fotos jsonb not null default '[]';
alter table public.taken       add column if not exists fotos jsonb not null default '[]';

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('fotos', 'fotos', false, 10485760, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "fotos bekijken"    on storage.objects;
drop policy if exists "fotos toevoegen"   on storage.objects;
drop policy if exists "fotos verwijderen" on storage.objects;
create policy "fotos bekijken"    on storage.objects for select to authenticated using (bucket_id = 'fotos');
create policy "fotos toevoegen"   on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('taken_toevoegen')
                                       or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren')));
create policy "fotos verwijderen" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('taken_toevoegen')
                                  or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren')));

-- Aantekeningen bij planten en soorten
alter table public.soorten add column if not exists notitie text;
alter table public.rassen  add column if not exists notitie text;

-- ============================================================
-- MIDDELEN, VOORRAAD EN SPUITREGISTRATIE
-- ============================================================
create table if not exists public.middelen (
  id                 uuid primary key default gen_random_uuid(),
  naam               text not null,
  categorie          text not null default 'gewasbescherming',   -- gewasbescherming, meststof, plantgoed, materiaal, overig
  toelatingsnummer   text,
  werkzame_stof      text,
  max_dosering       numeric,
  dosering_eenheid   text,                                       -- bijv. l/ha
  veiligheidstermijn integer,                                    -- dagen tussen toepassen en oogsten
  max_keer           integer,                                    -- maximaal aantal toepassingen per seizoen
  voorraad           numeric,
  voorraad_eenheid   text,                                       -- kg, liter, stuks, trays
  min_voorraad       numeric,
  prijs              numeric,                                    -- euro per voorraad-eenheid
  notitie            text,
  actief             boolean not null default true,
  created_at         timestamptz not null default now()
);
alter table public.middelen enable row level security;
drop policy if exists "lezen" on public.middelen;
drop policy if exists "beheer" on public.middelen;
create policy "lezen"  on public.middelen for select to authenticated using (true);
create policy "beheer" on public.middelen for all to authenticated
  using (public.heeft_recht('middelen_beheren')) with check (public.heeft_recht('middelen_beheren'));

create table if not exists public.voorraad_log (
  id          uuid primary key default gen_random_uuid(),
  middel_id   uuid not null references public.middelen(id) on delete cascade,
  hoeveelheid numeric not null,          -- + erbij, - eraf
  reden       text,
  taak_id     uuid references public.taken(id) on delete set null,
  door        text,
  created_at  timestamptz not null default now()
);
alter table public.voorraad_log enable row level security;
drop policy if exists "lezen" on public.voorraad_log;
create policy "lezen" on public.voorraad_log for select to authenticated using (true);

-- Voorraad bijboeken of corrigeren (met reden)
create or replace function public.boek_voorraad(p_middel uuid, p_hoeveelheid numeric, p_reden text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('middelen_beheren') then raise exception 'Je mag de voorraad niet aanpassen'; end if;
  update public.middelen set voorraad = coalesce(voorraad, 0) + p_hoeveelheid where id = p_middel;
  insert into public.voorraad_log (middel_id, hoeveelheid, reden, door)
  values (p_middel, p_hoeveelheid, p_reden, (select naam from public.profielen where id = auth.uid()));
end $$;
revoke all on function public.boek_voorraad(uuid, numeric, text) from public, anon;
grant execute on function public.boek_voorraad(uuid, numeric, text) to authenticated;

-- Taken: welk middel en hoeveel er verbruikt is (in de eenheid van de voorraad)
alter table public.taken add column if not exists middel_id uuid references public.middelen(id) on delete set null;
alter table public.taken add column if not exists verbruik  numeric;

-- Bij afronden/registreren gaat het verbruik automatisch van de voorraad af (en terug bij wijzigen/heropenen/verwijderen)
create or replace function public.taak_voorraad() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  o_m uuid; o_v numeric := 0; n_m uuid; n_v numeric := 0; wie text;
begin
  if current_setting('perceel.seizoenweg', true) = '1' then return coalesce(new, old); end if;   -- seizoen verwijderen: voorraad niet terugboeken
  if tg_op <> 'INSERT' and old.klaar and old.middel_id is not null and coalesce(old.verbruik, 0) <> 0 then o_m := old.middel_id; o_v := old.verbruik; end if;
  if tg_op <> 'DELETE' and new.klaar and new.middel_id is not null and coalesce(new.verbruik, 0) <> 0 then n_m := new.middel_id; n_v := new.verbruik; end if;
  if o_m is not distinct from n_m and o_v = n_v then return coalesce(new, old); end if;
  wie := (select naam from public.profielen where id = auth.uid());
  if o_m is not null then
    update public.middelen set voorraad = coalesce(voorraad, 0) + o_v where id = o_m and voorraad is not null;
    insert into public.voorraad_log (middel_id, hoeveelheid, reden, taak_id, door)
    values (o_m, o_v, 'Terug: ' || coalesce(old.tekst, 'taak'), case when tg_op = 'DELETE' then null else old.id end, wie);
  end if;
  if n_m is not null then
    update public.middelen set voorraad = coalesce(voorraad, 0) - n_v where id = n_m and voorraad is not null;
    insert into public.voorraad_log (middel_id, hoeveelheid, reden, taak_id, door)
    values (n_m, -n_v, coalesce(new.tekst, 'taak'), new.id, wie);
  end if;
  return coalesce(new, old);
end $$;
drop trigger if exists taak_voorraad on public.taken;
create trigger taak_voorraad after insert or update on public.taken for each row execute function public.taak_voorraad();
drop trigger if exists taak_voorraad_weg on public.taken;
create trigger taak_voorraad_weg before delete on public.taken for each row execute function public.taak_voorraad();

-- ============================================================
-- HERHALENDE TAKEN
-- ============================================================
alter table public.taken add column if not exists trekker  text;   -- welke trekker je moet pakken
alter table public.taken add column if not exists werktuig text;   -- welke machine erachter (bijv. rotorkopeg)
alter table public.taken add column if not exists herhaal           text;      -- dag, week, 2weken, maand, jaar
alter table public.taken add column if not exists herhaal_tot       date;
alter table public.taken add column if not exists herhaling_gemaakt boolean not null default false;

create or replace function public.taak_herhaal() returns trigger
language plpgsql security definer set search_path = '' as $$
declare stap interval; basis date; volgende date;
begin
  if not (new.klaar and not old.klaar and new.herhaal is not null and not old.herhaling_gemaakt) then return new; end if;
  stap := case new.herhaal when 'dag' then interval '1 day' when 'week' then interval '7 days' when '2weken' then interval '14 days'
                           when 'maand' then interval '1 month' when 'jaar' then interval '1 year' end;
  if stap is null then return new; end if;
  basis := coalesce(new.gepland, new.deadline, (new.klaar_op at time zone 'Europe/Amsterdam')::date, current_date);
  volgende := (basis + stap)::date;
  while volgende < current_date loop volgende := (volgende + stap)::date; end loop;   -- niet in het verleden plannen
  if new.herhaal_tot is not null and volgende > new.herhaal_tot then return new; end if;
  insert into public.taken (perceel_id, tekst, omschrijving, toegewezen_aan, gebied, spoor_van, spoor_tot, soort, wat, aantal, aantal_eenheid,
                            van_perceel, van_punt, naar_perceel, naar_punt, gepland, deadline, herhaal, herhaal_tot, middel_id, trekker, werktuig, aangemaakt_door)
  values (new.perceel_id, new.tekst, new.omschrijving, new.toegewezen_aan, new.gebied, new.spoor_van, new.spoor_tot, new.soort, new.wat, new.aantal, new.aantal_eenheid,
          new.van_perceel, new.van_punt, new.naar_perceel, new.naar_punt, volgende,
          case when new.deadline is not null then (new.deadline + (volgende - basis)) end,
          new.herhaal, new.herhaal_tot, null, new.trekker, new.werktuig, '🔁 herhaling');
  new.herhaling_gemaakt := true;
  return new;
end $$;
drop trigger if exists taak_herhaal on public.taken;
create trigger taak_herhaal before update on public.taken for each row execute function public.taak_herhaal();

-- Rechten per kolom opnieuw, met de nieuwe kolommen erbij
create or replace function public.controleer_taak() returns trigger language plpgsql as $$
begin
  if auth.uid() is null then return new; end if;
  if (new.klaar, new.klaar_door, new.klaar_op, new.product, new.dosering, new.eenheid, new.uitvoering, new.bezig_door, new.bezig_sinds, new.middel_id, new.verbruik)
     is distinct from (old.klaar, old.klaar_door, old.klaar_op, old.product, old.dosering, old.eenheid, old.uitvoering, old.bezig_door, old.bezig_sinds, old.middel_id, old.verbruik)
     and not public.heeft_recht('taken_afvinken') then
    raise exception 'Je mag taken niet afvinken';
  end if;
  if (new.tekst, new.deadline, new.gepland, new.perceel_id, new.omschrijving, new.toegewezen_aan, new.gebied, new.spoor_van, new.spoor_tot,
      new.soort, new.wat, new.aantal, new.aantal_eenheid, new.van_perceel, new.van_punt, new.naar_perceel, new.naar_punt, new.herhaal, new.herhaal_tot, new.trekker, new.werktuig)
     is distinct from (old.tekst, old.deadline, old.gepland, old.perceel_id, old.omschrijving, old.toegewezen_aan, old.gebied, old.spoor_van, old.spoor_tot,
      old.soort, old.wat, old.aantal, old.aantal_eenheid, old.van_perceel, old.van_punt, old.naar_perceel, old.naar_punt, old.herhaal, old.herhaal_tot, old.trekker, old.werktuig)
     and not public.heeft_recht('taken_toevoegen') then
    raise exception 'Je mag taken niet wijzigen';
  end if;
  return new;
end $$;

-- ============================================================
-- OOGST: aantal planten (of trays) dat van het veld komt
-- ============================================================
create table if not exists public.oogst (
  id          uuid primary key default gen_random_uuid(),
  perceel_id  uuid not null references public.percelen(id) on delete cascade,
  teelt_id    uuid,                       -- plant of soort
  vak         text,                       -- bijv. "A" of "spoor 3-8"
  datum       date not null default current_date,
  aantal      integer not null check (aantal >= 0),
  eenheid     text not null default 'planten',   -- planten of trays
  per_tray    integer,                    -- planten per tray (bij trays)
  opmerking   text,
  fotos       jsonb not null default '[]',
  door        text,
  user_id     uuid default auth.uid(),
  seizoen_id  uuid references public.seizoenen(id) on delete set null,
  created_at  timestamptz not null default now()
);
create index if not exists oogst_perceel on public.oogst (perceel_id, datum);
alter table public.oogst enable row level security;
drop policy if exists "lezen" on public.oogst;
drop policy if exists "schrijven" on public.oogst;
create policy "lezen"     on public.oogst for select to authenticated using (public.heeft_recht('oogst_bekijken') or public.heeft_recht('oogst_registreren'));
create policy "schrijven" on public.oogst for all to authenticated
  using (public.heeft_recht('oogst_registreren')) with check (public.heeft_recht('oogst_registreren'));
drop trigger if exists oogst_seizoen on public.oogst;
create trigger oogst_seizoen before insert on public.oogst for each row execute function public.taak_seizoen();

-- ============================================================
-- VRUCHTWISSELING: hoeveel jaar een plant niet op hetzelfde perceel mag
-- ============================================================
alter table public.soorten add column if not exists rust_jaren integer;

-- ============================================================
-- MACHINES EN ONDERHOUD
-- ============================================================
create table if not exists public.machines (
  id                 uuid primary key default gen_random_uuid(),
  naam               text not null,
  soort              text,
  kenteken           text,
  draaiuren          numeric,
  onderhoud_interval numeric,          -- elke zoveel draaiuren
  onderhoud_bij      numeric,          -- draaiuren bij de laatste beurt
  onderhoud_datum    date,
  keuring_datum      date,             -- APK / keuring geldig tot
  tractor_id         uuid references public.tractoren(id) on delete set null,
  notitie            text,
  created_at         timestamptz not null default now()
);
alter table public.machines enable row level security;
drop policy if exists "lezen" on public.machines;
drop policy if exists "beheer" on public.machines;
create policy "lezen"  on public.machines for select to authenticated using (true);
create policy "beheer" on public.machines for all to authenticated
  using (public.heeft_recht('machines_beheren')) with check (public.heeft_recht('machines_beheren'));

create table if not exists public.machine_log (
  id           uuid primary key default gen_random_uuid(),
  machine_id   uuid not null references public.machines(id) on delete cascade,
  datum        date not null default current_date,
  draaiuren    numeric,
  soort        text not null default 'draaiuren',   -- draaiuren, onderhoud, reparatie, overig
  omschrijving text,
  kosten       numeric,
  door         text,
  fotos        jsonb not null default '[]',
  created_at   timestamptz not null default now()
);
alter table public.machine_log enable row level security;
drop policy if exists "lezen" on public.machine_log;
drop policy if exists "toevoegen" on public.machine_log;
drop policy if exists "beheer" on public.machine_log;
drop policy if exists "verwijderen" on public.machine_log;
create policy "lezen"       on public.machine_log for select to authenticated using (true);
create policy "toevoegen"   on public.machine_log for insert to authenticated
  with check (public.heeft_recht('machines_beheren') or public.heeft_recht('tractor_rijden'));
create policy "beheer"      on public.machine_log for update to authenticated using (public.heeft_recht('machines_beheren')) with check (true);
create policy "verwijderen" on public.machine_log for delete to authenticated using (public.heeft_recht('machines_beheren'));

create or replace function public.machine_log_bij() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.draaiuren is not null then
    update public.machines set draaiuren = greatest(coalesce(draaiuren, 0), new.draaiuren) where id = new.machine_id;
  end if;
  if new.soort = 'onderhoud' then
    update public.machines set onderhoud_bij = coalesce(new.draaiuren, draaiuren), onderhoud_datum = new.datum where id = new.machine_id;
  end if;
  return new;
end $$;
drop trigger if exists machine_log_bij on public.machine_log;
create trigger machine_log_bij after insert on public.machine_log for each row execute function public.machine_log_bij();

-- ============================================================
-- KOSTEN PER PERCEEL
-- ============================================================
create table if not exists public.kosten (
  id           uuid primary key default gen_random_uuid(),
  perceel_id   uuid references public.percelen(id) on delete cascade,
  datum        date not null default current_date,
  omschrijving text not null,
  categorie    text,
  bedrag       numeric not null,
  door         text,
  seizoen_id   uuid references public.seizoenen(id) on delete set null,
  created_at   timestamptz not null default now()
);
alter table public.kosten enable row level security;
drop policy if exists "alles" on public.kosten;
create policy "alles" on public.kosten for all to authenticated
  using (public.heeft_recht('kosten_bekijken')) with check (public.heeft_recht('kosten_bekijken'));
drop trigger if exists kosten_seizoen on public.kosten;
create trigger kosten_seizoen before insert on public.kosten for each row execute function public.taak_seizoen();

-- Losse instelling zetten (bijv. uurtarief) – alleen beheerder
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen de beheerder mag dit instellen'; end if;
  if p_sleutel not in ('uurtarief') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;
revoke all on function public.zet_instelling(text, text) from public, anon;
grant execute on function public.zet_instelling(text, text) to authenticated;

-- ============================================================
-- MELDINGEN (bijv. "er is een taak aan je gegeven")
-- ============================================================
create table if not exists public.meldingen (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  tekst       text not null,
  soort       text,
  taak_id     uuid references public.taken(id) on delete cascade,
  perceel_id  uuid references public.percelen(id) on delete cascade,
  gelezen     boolean not null default false,
  created_at  timestamptz not null default now()
);
create index if not exists meldingen_user on public.meldingen (user_id, created_at desc);
alter table public.meldingen enable row level security;
drop policy if exists "eigen" on public.meldingen;
drop policy if exists "eigen lezen" on public.meldingen;
drop policy if exists "eigen wijzigen" on public.meldingen;
drop policy if exists "eigen weg" on public.meldingen;
create policy "eigen lezen"    on public.meldingen for select to authenticated using (user_id = auth.uid());
create policy "eigen wijzigen" on public.meldingen for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "eigen weg"      on public.meldingen for delete to authenticated using (user_id = auth.uid());

create or replace function public.taak_melding() returns trigger
language plpgsql security definer set search_path = '' as $$
declare wie text; waar text;
begin
  if new.toegewezen_aan is null or new.klaar or new.toegewezen_aan = auth.uid() then return new; end if;
  wie  := coalesce((select naam from public.profielen where id = auth.uid()), 'Iemand');
  waar := (select naam from public.percelen where id = coalesce(new.perceel_id, new.van_perceel));
  if tg_op = 'INSERT' or new.toegewezen_aan is distinct from old.toegewezen_aan then
    insert into public.meldingen (user_id, tekst, soort, taak_id, perceel_id)
    values (new.toegewezen_aan, wie || ' heeft je een taak gegeven: ' || new.tekst || coalesce(' · ' || waar, '') ||
            coalesce(' · gepland ' || to_char(new.gepland, 'DD-MM'), ''), 'taak', new.id, new.perceel_id);
  elsif new.gepland is distinct from old.gepland and new.gepland is not null then
    insert into public.meldingen (user_id, tekst, soort, taak_id, perceel_id)
    values (new.toegewezen_aan, 'Je taak "' || new.tekst || '" is verplaatst naar ' || to_char(new.gepland, 'DD-MM'), 'taak', new.id, new.perceel_id);
  end if;
  return new;
end $$;
drop trigger if exists taak_melding on public.taken;
create trigger taak_melding after insert or update on public.taken for each row execute function public.taak_melding();

do $$ begin alter publication supabase_realtime add table public.middelen;    exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.oogst;       exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.machines;    exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.machine_log; exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.kosten;      exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.meldingen;   exception when duplicate_object then null; end $$;


-- ============================================================
-- OUDE SEIZOENEN VERWIJDEREN (met alle taken, oogst en kosten van dat seizoen)
-- Geklokte uren en de voorraadgeschiedenis blijven bewaard.
-- ============================================================
create or replace function public.verwijder_seizoen(p_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('seizoen_starten') then raise exception 'Je mag geen seizoenen verwijderen'; end if;
  if exists (select 1 from public.seizoenen where id = p_id and actief) then raise exception 'Het huidige seizoen kun je niet verwijderen'; end if;
  perform set_config('perceel.seizoenweg', '1', true);
  delete from public.oogst  where seizoen_id = p_id;
  delete from public.kosten where seizoen_id = p_id;
  delete from public.taken  where seizoen_id = p_id;
  delete from public.seizoen_percelen where seizoen_id = p_id;
  delete from public.seizoenen where id = p_id;
end $$;
revoke all on function public.verwijder_seizoen(uuid) from public, anon;
grant execute on function public.verwijder_seizoen(uuid) to authenticated;

-- ============================================================
-- DOWNLOADS (verslagen en Excel in de geïnstalleerde Android-app)
-- ============================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('downloads', 'downloads', false, 52428800, array['application/pdf','application/zip','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "downloads eigen" on storage.objects;
create policy "downloads eigen" on storage.objects for all to authenticated
  using (bucket_id = 'downloads' and name like auth.uid()::text || '/%')
  with check (bucket_id = 'downloads' and name like auth.uid()::text || '/%');


-- ============================================================
-- HOOFDSCHAKELAAR "PERCELEN AANPASSEN" + AANTEKENINGEN + UITGEROOID
-- Zonder "percelen_aanpassen" tellen alle perceel-rechten niet mee (alleen kijken).
-- ============================================================
create or replace function public.heeft_recht(r text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profielen
                 where id = auth.uid()
                   and (rol = 'beheerder'
                        or (coalesce((rechten->>r)::boolean, false)
                            and (r not in ('percelen_tekenen','percelen_bewerken','spuitsporen_bewerken','deelvelden_bewerken',
                                           'percelen_uitschakelen','percelen_verwijderen','soorten_indelen','kopeinden_bewerken')
                                 or coalesce((rechten->>'percelen_aanpassen')::boolean, false)))));
$$;

-- Markering "gerooid": een stuk waar de planten zijn uitgerooid, met datum en welke plant
alter table public.markeringen add column if not exists datum    date;
alter table public.markeringen add column if not exists teelt_id uuid;
alter table public.markeringen drop constraint if exists markeringen_soort_check;
alter table public.markeringen add constraint markeringen_soort_check check (soort in ('vlag','gebied','lijn','kopeinde','gerooid'));

create or replace function public.mag_markering(p_soort text) returns boolean
language sql stable security definer set search_path = '' as $$
  select case when p_soort in ('kopeinde','lijn') then public.heeft_recht('kopeinden_bewerken')
              when p_soort = 'gerooid' then public.heeft_recht('gerooid_aangeven')
              else public.heeft_recht('markeringen_maken') end;
$$;
grant execute on function public.mag_markering(text) to authenticated;
drop policy if exists "maken" on public.markeringen;
create policy "maken" on public.markeringen for all to authenticated
  using (public.mag_markering(soort)) with check (public.mag_markering(soort));

drop policy if exists "fotos toevoegen"   on storage.objects;
drop policy if exists "fotos verwijderen" on storage.objects;
create policy "fotos toevoegen"   on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                       or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                       or public.heeft_recht('machines_beheren') or public.heeft_recht('tractor_rijden')));
create policy "fotos verwijderen" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                  or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                  or public.heeft_recht('machines_beheren')));

-- ============================================================
-- TREKKERS VAN DE KEMP (voertuigenlijst; auto's niet)
-- Alleen toevoegen als de naam nog niet bestaat; daarna vrij aan te passen in 📦 Bedrijf → Machines
-- ============================================================
insert into public.machines (naam, soort, kenteken, notitie)
select v.naam, v.soort, v.kenteken, v.notitie
from (values
  ('T1 - Fendt 412 CW',            'Trekker', 'THN-23-G', 'GPS O'),
  ('T2 - Fendt 211 CW',            'Trekker', 'THN-30-G', 'GPS N'),
  ('T3 - Fendt 311 CW',            'Trekker', 'THN-37-G', 'GPS F'),
  ('T4 - Fendt 411 CW',            'Trekker', 'THN-81-G', 'GPS O'),
  ('T5 - Fendt 307 CW',            'Trekker', 'THN-91-G', null),
  ('T6 - Fendt 311 CW',            'Trekker', 'THN-16-H', 'GPS N'),
  ('T7 - Fendt 516 CW',            'Trekker', 'THN-22-H', null),
  ('T8 - MF 7722 BW',              'Trekker', 'THN-64-S', 'GPS N'),
  ('T9 - Fendt 270V smalspoor',    'Trekker', 'THN-27-H', null),
  ('T10 - Kubota M5112 DTHQ',      'Trekker', 'T-55-FZJ', null),
  ('T11 - New Holland CE 50 CW',   'Trekker', 'THN-39-H', null),
  ('T12 - Agrifac BW',             'Spuitmachine', 'THN-44-N', 'Zelfrijdende spuit'),
  ('T13 - MT 1401D mini trekker CW','Trekker', null, null),
  ('T14 - Hürlimann Prince 325 DTC','Trekker', 'THN-53-H', null),
  ('T15 - Kubota M5091 DTHQ',      'Trekker', 'THD-15-F', null),
  ('T16 - Kubota met kabine',      'Trekker', 'TTK-15-F', null),
  ('T18 - MF 8S.285',              'Trekker', null, 'GPS'),
  ('T20 - Fendt 211 Profi+',       'Trekker', 'T-79-HHL', 'GPS F'),
  ('T21 - Fendt 314',              'Trekker', 'T-92-HHR', 'GPS F'),
  ('TH3 - NEL Fendt 516',          'Trekker', 'TSZ-84-B', 'Nellissen'),
  ('TH6 - NEL Fendt 513',          'Trekker', null, 'Nellissen'),
  ('TH7 - NEL Fendt 411 CW',       'Trekker', 'TSZ-11-G', 'Nellissen'),
  ('TH8 - NEL Fendt 513',          'Trekker', 'TTR-48-G', 'Nellissen'),
  ('TH9 - NEL Fendt 516',          'Trekker', null, 'Nellissen'),
  ('TH10 - NEL Fendt 516',         'Trekker', null, 'Nellissen'),
  ('TH15 - MF 7718 Nellissen',     'Trekker', null, 'Nellissen')
) as v(naam, soort, kenteken, notitie)
where not exists (select 1 from public.machines m where lower(m.naam) = lower(v.naam));

-- =====================================================================
-- FLEETGO: bussen en auto's live op de kaart
-- De inloggegevens staan in een afgeschermde tabel (niet leesbaar via de app).
-- De database haalt zelf de posities op bij FleetGO (extensie "http").
-- Wie het mag zien regel je met het recht "voertuigen_zien" bij Gebruikers.
-- =====================================================================
create extension if not exists http with schema extensions;

create table if not exists public.fleetgo_koppeling (
  id            int primary key default 1 check (id = 1),
  client_id     text, client_secret text, gebruiker text, wachtwoord text,
  token         text, token_tot timestamptz,
  laatste_sync  timestamptz, laatste_fout text, voorbeeld jsonb
);
alter table public.fleetgo_koppeling enable row level security;   -- geen policies: alleen de functies hieronder kunnen erbij
revoke all on public.fleetgo_koppeling from anon, authenticated;

create table if not exists public.voertuigen (
  id          uuid primary key default gen_random_uuid(),
  fleetgo_id  text unique not null,
  kenteken    text, merk text, model text,
  naam        text,                       -- eigen bijnaam, bijv. "Bus Jan"
  soort       text,                       -- bus / auto / vrachtwagen (leeg = raden uit het model)
  verborgen   boolean not null default false,
  lat double precision, lng double precision, snelheid double precision, motor_aan boolean, km double precision,
  gezien      timestamptz,                -- tijd van de laatste positie volgens FleetGO
  bijgewerkt  timestamptz default now()
);
alter table public.voertuigen enable row level security;
grant select, update, delete on public.voertuigen to authenticated;
drop policy if exists "voertuigen zien" on public.voertuigen;
create policy "voertuigen zien" on public.voertuigen for select to authenticated
  using (public.heeft_recht('voertuigen_beheren') or (public.heeft_recht('voertuigen_zien') and not verborgen));
drop policy if exists "voertuigen wijzigen" on public.voertuigen;
create policy "voertuigen wijzigen" on public.voertuigen for update to authenticated
  using (public.heeft_recht('voertuigen_beheren')) with check (public.heeft_recht('voertuigen_beheren'));
drop policy if exists "voertuigen weg" on public.voertuigen;
create policy "voertuigen weg" on public.voertuigen for delete to authenticated using (public.heeft_recht('voertuigen_beheren'));
do $$ begin alter publication supabase_realtime add table public.voertuigen; exception when duplicate_object then null; end $$;

-- tijd uit FleetGO veilig omzetten (zonder tijdzone = Nederlandse tijd)
create or replace function public.fleetgo_tijd(t text) returns timestamptz
language plpgsql stable as $$
begin
  if t is null or t = '' then return null; end if;
  if t ~ '(Z|[+-]\d\d:?\d\d)$' then return t::timestamptz; end if;
  return t::timestamp at time zone 'Europe/Amsterdam';
exception when others then return null;
end $$;

-- Het eigenlijke ophalen (niet direct aan te roepen vanuit de app)
create or replace function public.fleetgo_sync(p_forceer boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  k public.fleetgo_koppeling; r extensions.http_response; j jsonb; e jsonb; n int := 0; poging int;
  la double precision; ln double precision;
begin
  if not pg_try_advisory_xact_lock(470501) then return jsonb_build_object('ok', true, 'bericht', 'wordt al opgehaald'); end if;
  select * into k from public.fleetgo_koppeling where id = 1;
  if k.id is null or coalesce(k.client_id, '') = '' or coalesce(k.gebruiker, '') = '' then
    return jsonb_build_object('ok', false, 'bericht', 'De FleetGO-koppeling is nog niet ingesteld');
  end if;
  if not p_forceer and k.laatste_sync > now() - interval '15 seconds' then
    return jsonb_build_object('ok', true, 'bericht', 'net bijgewerkt');
  end if;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '12000');
  for poging in 1..2 loop
    -- inloggen als er geen geldige sleutel (token) is
    if k.token is null or k.token_tot < now() + interval '1 minute' then
      r := extensions.http_post('https://api.fleetgo.com/api/session/login',
             jsonb_build_object('client_id', k.client_id, 'client_secret', k.client_secret, 'username', k.gebruiker, 'password', k.wachtwoord)::text,
             'application/json');
      begin j := r.content::jsonb; exception when others then j := null; end;
      if r.status <> 200 or j ->> 'access_token' is null then
        update public.fleetgo_koppeling set laatste_fout = 'Inloggen bij FleetGO mislukt (' || r.status || '): ' || left(coalesce(r.content, ''), 300), token = null where id = 1;
        return jsonb_build_object('ok', false, 'bericht', 'Inloggen bij FleetGO mislukt (' || r.status || '). Controleer client ID/secret en gebruikersnaam/wachtwoord.');
      end if;
      k.token := j ->> 'access_token';
      k.token_tot := now() + make_interval(secs => coalesce(nullif(j ->> 'expires_in', '')::numeric, 3600));
      update public.fleetgo_koppeling set token = k.token, token_tot = k.token_tot where id = 1;
    end if;
    r := extensions.http(('GET', 'https://api.fleetgo.com/api/equipment/Getfleet?groupId=0&hasDeviceOnly=false',
           array[extensions.http_header('Authorization', 'Bearer ' || k.token)], null, null)::extensions.http_request);
    exit when r.status <> 401;
    k.token := null;   -- sleutel verlopen: één keer opnieuw inloggen
  end loop;
  begin j := r.content::jsonb; exception when others then j := null; end;
  if r.status <> 200 or j is null or jsonb_typeof(j) <> 'array' then
    update public.fleetgo_koppeling set laatste_fout = 'Voertuigen ophalen mislukt (' || r.status || '): ' || left(coalesce(r.content, ''), 300) where id = 1;
    return jsonb_build_object('ok', false, 'bericht', 'Voertuigen ophalen bij FleetGO mislukt (' || r.status || ')');
  end if;
  for e in select * from jsonb_array_elements(j) loop
    la := nullif(coalesce(e #>> '{Location,Latitude}', e ->> 'Latitude'), '')::double precision;
    ln := nullif(coalesce(e #>> '{Location,Longitude}', e ->> 'Longitude'), '')::double precision;
    if la = 0 and ln = 0 then la := null; ln := null; end if;
    insert into public.voertuigen as v (fleetgo_id, kenteken, merk, model, lat, lng, snelheid, motor_aan, km, gezien, bijgewerkt)
    values (coalesce(e ->> 'Id', e #>> '{EquipmentHeader,EquipmentID}'),
            coalesce(e #>> '{EquipmentHeader,SerialNumber}', e ->> 'LicensePlate'),
            e #>> '{EquipmentHeader,Make}', e #>> '{EquipmentHeader,Model}',
            la, ln, nullif(e ->> 'Speed', '')::double precision, (e ->> 'EngineRunning')::boolean,
            nullif(e ->> 'Odometer', '')::double precision, public.fleetgo_tijd(e #>> '{Location,DateTime}'), now())
    on conflict (fleetgo_id) do update set
      kenteken = excluded.kenteken, merk = excluded.merk, model = excluded.model,
      lat = coalesce(excluded.lat, v.lat), lng = coalesce(excluded.lng, v.lng), snelheid = excluded.snelheid,
      motor_aan = excluded.motor_aan, km = excluded.km, gezien = coalesce(excluded.gezien, v.gezien), bijgewerkt = now()
    where (v.lat, v.lng, v.snelheid, v.motor_aan, v.gezien, v.kenteken) is distinct from
          (coalesce(excluded.lat, v.lat), coalesce(excluded.lng, v.lng), excluded.snelheid, excluded.motor_aan, coalesce(excluded.gezien, v.gezien), excluded.kenteken);
    n := n + 1;
  end loop;
  update public.fleetgo_koppeling set laatste_sync = now(), laatste_fout = null, voorbeeld = j -> 0 where id = 1;
  return jsonb_build_object('ok', true, 'bericht', n || ' voertuigen bijgewerkt', 'aantal', n);
exception when others then
  update public.fleetgo_koppeling set laatste_fout = sqlerrm where id = 1;
  return jsonb_build_object('ok', false, 'bericht', 'Fout bij FleetGO: ' || sqlerrm);
end $$;
revoke all on function public.fleetgo_sync(boolean) from public, anon, authenticated;

-- Vanuit de app: posities verversen (alleen wie voertuigen mag zien). Maximaal elke 15 seconden echt bij FleetGO.
create or replace function public.voertuigen_verversen(p_forceer boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  if not (public.heeft_recht('voertuigen_zien') or public.heeft_recht('voertuigen_beheren')) then
    return jsonb_build_object('ok', false, 'bericht', 'Je mag de voertuigen niet zien');
  end if;
  return public.fleetgo_sync(p_forceer and public.heeft_recht('voertuigen_beheren'));
end $$;
grant execute on function public.voertuigen_verversen(boolean) to authenticated;

-- Koppeling instellen (lege velden = oude waarde houden, zodat je het wachtwoord niet opnieuw hoeft te typen)
create or replace function public.fleetgo_instellen(p_client_id text, p_client_secret text, p_gebruiker text, p_wachtwoord text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('voertuigen_beheren') then raise exception 'Je mag de FleetGO-koppeling niet instellen'; end if;
  insert into public.fleetgo_koppeling (id) values (1) on conflict (id) do nothing;
  update public.fleetgo_koppeling set
    client_id     = coalesce(nullif(trim(p_client_id), ''), client_id),
    client_secret = coalesce(nullif(trim(p_client_secret), ''), client_secret),
    gebruiker     = coalesce(nullif(trim(p_gebruiker), ''), gebruiker),
    wachtwoord    = coalesce(nullif(p_wachtwoord, ''), wachtwoord),
    token = null, token_tot = null, laatste_fout = null
  where id = 1;
end $$;
grant execute on function public.fleetgo_instellen(text, text, text, text) to authenticated;

-- Status voor het beheerscherm (zonder geheimen)
create or replace function public.fleetgo_status() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare k public.fleetgo_koppeling;
begin
  if not public.heeft_recht('voertuigen_beheren') then return null; end if;
  select * into k from public.fleetgo_koppeling where id = 1;
  return jsonb_build_object('ingesteld', coalesce(k.client_id, '') <> '' and coalesce(k.gebruiker, '') <> '',
    'client_id', k.client_id, 'gebruiker', k.gebruiker, 'laatste_sync', k.laatste_sync, 'laatste_fout', k.laatste_fout,
    'velden', (select jsonb_agg(x) from jsonb_object_keys(coalesce(k.voorbeeld, '{}'::jsonb)) x),
    'aantal', (select count(*) from public.voertuigen));
end $$;
grant execute on function public.fleetgo_status() to authenticated;

-- Koppeling weer weghalen
create or replace function public.fleetgo_wissen() returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('voertuigen_beheren') then raise exception 'Je mag de FleetGO-koppeling niet wissen'; end if;
  delete from public.fleetgo_koppeling where id = 1;
end $$;
grant execute on function public.fleetgo_wissen() to authenticated;

-- Optioneel: ook verversen als niemand de app open heeft (elke minuut). Haal de -- weg om aan te zetten:
-- create extension if not exists pg_cron;
-- select cron.schedule('fleetgo', '* * * * *', 'select public.fleetgo_sync()');

-- =====================================================================
-- PLATTEGROND: ingeladen afbeelding per perceel (in de fotomap), met de uitlijning op de kaart
-- =====================================================================
alter table public.percelen add column if not exists plattegrond jsonb;
drop policy if exists "fotos toevoegen"   on storage.objects;
drop policy if exists "fotos verwijderen" on storage.objects;
create policy "fotos toevoegen"   on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                       or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                       or public.heeft_recht('machines_beheren') or public.heeft_recht('tractor_rijden') or public.heeft_recht('percelen_bewerken')));
create policy "fotos verwijderen" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                  or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                  or public.heeft_recht('machines_beheren') or public.heeft_recht('percelen_bewerken')));

-- =====================================================================
-- PERCELEN SAMENVOEGEN: twee percelen worden één; alles wat aan het tweede hing gaat mee
-- (oude seizoenen in seizoen_percelen blijven ongemoeid)
-- =====================================================================
create or replace function public.percelen_samenvoegen(p_hoofd uuid, p_weg uuid, p_geo jsonb, p_naam text default null) returns void
language plpgsql security definer set search_path = '' as $$
declare r record; h public.percelen; w public.percelen;
begin
  if not (public.heeft_recht('percelen_bewerken') and public.heeft_recht('percelen_verwijderen')) then
    raise exception 'Je mag geen percelen samenvoegen';
  end if;
  select * into h from public.percelen where id = p_hoofd;
  select * into w from public.percelen where id = p_weg;
  if h.id is null or w.id is null or h.id = w.id then raise exception 'Perceel niet gevonden'; end if;
  if p_geo is null or p_geo #>> '{geometry,type}' not in ('Polygon', 'MultiPolygon') then raise exception 'Ongeldige vorm'; end if;
  for r in select c.table_name, c.column_name from information_schema.columns c
           join information_schema.tables t on t.table_schema = c.table_schema and t.table_name = c.table_name and t.table_type = 'BASE TABLE'
           where c.table_schema = 'public' and c.column_name in ('perceel_id', 'van_perceel', 'naar_perceel')
             and c.table_name not in ('percelen', 'seizoen_percelen') loop
    begin
      execute format('update public.%I set %I = %L where %I = %L', r.table_name, r.column_name, p_hoofd::text, r.column_name, p_weg::text);
    exception when others then raise notice 'Overslaan %.%: %', r.table_name, r.column_name, sqlerrm;
    end;
  end loop;
  update public.percelen set geo = p_geo, naam = coalesce(nullif(trim(p_naam), ''), naam),
         vakken = coalesce(h.vakken, '[]'::jsonb) || coalesce(w.vakken, '[]'::jsonb), updated_at = now()
   where id = p_hoofd;
  delete from public.percelen where id = p_weg;
end $$;
grant execute on function public.percelen_samenvoegen(uuid, uuid, jsonb, text) to authenticated;

-- =====================================================================
-- PARTIJEN / TEELTGEGEVENS: ingelezen uit Excel (batch, NAK-nummer, ras, klasse, doel per perceel)
-- =====================================================================
create table if not exists public.partijen (
  id            uuid primary key default gen_random_uuid(),
  seizoen_id    uuid references public.seizoenen(id) on delete cascade,
  sleutel       text not null,                        -- vaste sleutel zodat opnieuw inladen bijwerkt i.p.v. dubbel
  perceel_id    uuid references public.percelen(id) on delete set null,
  perceel_tekst text,                                 -- zoals het in het bestand stond
  soort_id      uuid references public.soorten(id) on delete set null,
  ras_id        uuid references public.rassen(id) on delete set null,
  ras_tekst     text,
  teeltdoel     text,                                 -- bijv. vermeerdering / opkweek
  batch text, nak text, klasse text, doel text,
  bio           boolean not null default false,
  extra         jsonb not null default '{}',          -- overige kolommen uit het bestand
  bron          text,                                 -- bestandsnaam
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  unique (seizoen_id, sleutel)
);
create index if not exists partijen_perceel on public.partijen (perceel_id);
alter table public.partijen enable row level security;
grant select, insert, update, delete on public.partijen to authenticated;
drop policy if exists "partijen lezen" on public.partijen;
create policy "partijen lezen" on public.partijen for select to authenticated using (true);
drop policy if exists "partijen beheren" on public.partijen;
create policy "partijen beheren" on public.partijen for all to authenticated
  using (public.heeft_recht('partijen_beheren')) with check (public.heeft_recht('partijen_beheren'));
do $$ begin alter publication supabase_realtime add table public.partijen; exception when duplicate_object then null; end $$;

-- onthouden welke naam in een bestand bij welk perceel hoort
create table if not exists public.perceel_aliassen (
  tekst      text primary key,                        -- in kleine letters
  perceel_id uuid not null references public.percelen(id) on delete cascade
);
alter table public.perceel_aliassen enable row level security;
grant select, insert, update, delete on public.perceel_aliassen to authenticated;
drop policy if exists "aliassen lezen" on public.perceel_aliassen;
create policy "aliassen lezen" on public.perceel_aliassen for select to authenticated using (true);
drop policy if exists "aliassen beheren" on public.perceel_aliassen;
create policy "aliassen beheren" on public.perceel_aliassen for all to authenticated
  using (public.heeft_recht('partijen_beheren')) with check (public.heeft_recht('partijen_beheren'));

-- Alles in één keer inladen: ontbrekende gewassen en rassen worden aangemaakt
create or replace function public.teelt_import(p_seizoen uuid, p_bron text, p_rijen jsonb, p_aliassen jsonb default '[]', p_vervang boolean default true)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  r jsonb; s_id uuid; r_id uuid; n int := 0; ns int := 0; nr int := 0; sz uuid; sleutels text[] := '{}'; kleuren text[] := array['#e53935','#8e24aa','#3949ab','#00897b','#7cb342','#fb8c00','#6d4c41','#546e7a','#d81b60','#00acc1'];
begin
  if not public.heeft_recht('partijen_beheren') then raise exception 'Je mag geen teeltgegevens inladen'; end if;
  sz := coalesce(p_seizoen, (select id from public.seizoenen where actief));
  if sz is null then raise exception 'Er is geen actief seizoen. Start eerst een seizoen.'; end if;
  for r in select * from jsonb_array_elements(coalesce(p_aliassen, '[]')) loop
    insert into public.perceel_aliassen (tekst, perceel_id) values (lower(trim(r->>'tekst')), (r->>'perceel_id')::uuid)
    on conflict (tekst) do update set perceel_id = excluded.perceel_id;
  end loop;
  for r in select * from jsonb_array_elements(p_rijen) loop
    s_id := nullif(r->>'soort_id', '')::uuid;
    if s_id is null and coalesce(trim(r->>'soort_naam'), '') <> '' then
      select id into s_id from public.soorten where lower(naam) = lower(trim(r->>'soort_naam')) limit 1;
      if s_id is null then
        insert into public.soorten (naam, kleur) values (trim(r->>'soort_naam'), kleuren[1 + (ns % 10)]) returning id into s_id; ns := ns + 1;
      end if;
    end if;
    r_id := null;
    if s_id is not null and coalesce(trim(r->>'ras_naam'), '') <> '' then
      select id into r_id from public.rassen where soort_id = s_id and lower(naam) = lower(trim(r->>'ras_naam')) limit 1;
      if r_id is null then
        insert into public.rassen (soort_id, naam, kleur) values (s_id, trim(r->>'ras_naam'), kleuren[1 + ((nr + 3) % 10)]) returning id into r_id; nr := nr + 1;
      end if;
    end if;
    insert into public.partijen as p (seizoen_id, sleutel, perceel_id, perceel_tekst, soort_id, ras_id, ras_tekst, teeltdoel, batch, nak, klasse, doel, bio, extra, bron, updated_at)
    values (sz, r->>'sleutel', nullif(r->>'perceel_id', '')::uuid, r->>'perceel_tekst', s_id, r_id, r->>'ras_tekst', nullif(r->>'teeltdoel', ''),
            nullif(r->>'batch', ''), nullif(r->>'nak', ''), nullif(r->>'klasse', ''), nullif(r->>'doel', ''), coalesce((r->>'bio')::boolean, false),
            coalesce(r->'extra', '{}'), p_bron, now())
    on conflict (seizoen_id, sleutel) do update set perceel_id = excluded.perceel_id, perceel_tekst = excluded.perceel_tekst, soort_id = excluded.soort_id,
      ras_id = excluded.ras_id, ras_tekst = excluded.ras_tekst, teeltdoel = excluded.teeltdoel, batch = excluded.batch, nak = excluded.nak, klasse = excluded.klasse,
      doel = excluded.doel, bio = excluded.bio, extra = excluded.extra, bron = excluded.bron, updated_at = now();
    sleutels := sleutels || (r->>'sleutel'); n := n + 1;
  end loop;
  -- regels die bij een vorige versie van hetzelfde bestand hoorden maar er nu niet meer in staan
  if p_vervang and p_bron is not null then
    delete from public.partijen where seizoen_id is not distinct from sz and bron = p_bron and not (sleutel = any(sleutels));
  end if;
  return jsonb_build_object('partijen', n, 'nieuwe_soorten', ns, 'nieuwe_rassen', nr);
end $$;
grant execute on function public.teelt_import(uuid, text, jsonb, jsonb, boolean) to authenticated;

-- op welke sporen een partij staat: [{"z": zone-id, "nrs": [1,2,3]}]
alter table public.partijen add column if not exists sporen jsonb not null default '[]';

-- =====================================================================
-- Rooien en frezen halen planten weg: sporen gaan op braak, met wat er stond
-- bewaard zodat het terug te draaien is.
-- =====================================================================
alter table public.taken       add column if not exists braak jsonb;
alter table public.markeringen add column if not exists braak jsonb;

-- Planten op sporen bijwerken bij afgerond werk. Mag ook wie zelf geen planten mag indelen,
-- maar alleen banen en gewas: de rest van het perceel (en de vorm van deelvelden) blijft gelijk.
create or replace function public.planten_bijwerken(p_perceel uuid, p_banen jsonb, p_vakken jsonb, p_gewas text)
returns void language plpgsql security definer set search_path = public as $$
declare oud jsonb; nieuw jsonb;
begin
  if not (public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren')
          or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('soorten_indelen')) then
    raise exception 'Je mag dit werk niet registreren';
  end if;
  select coalesce(jsonb_agg(v - 'banen' - 'gewas' order by i), '[]') into oud
    from public.percelen p, jsonb_array_elements(coalesce(p.vakken, '[]')) with ordinality x(v, i) where p.id = p_perceel;
  select coalesce(jsonb_agg(v - 'banen' - 'gewas' order by i), '[]') into nieuw
    from jsonb_array_elements(coalesce(p_vakken, '[]')) with ordinality x(v, i);
  if oud is distinct from nieuw then raise exception 'De deelvelden van dit perceel zijn intussen veranderd, ververs de app'; end if;
  perform set_config('perceel.systeem', '1', true);
  update public.percelen set banen = p_banen, vakken = coalesce(p_vakken, '[]'), gewas = p_gewas, updated_at = now() where id = p_perceel;
  perform set_config('perceel.systeem', '0', true);
end $$;
grant execute on function public.planten_bijwerken(uuid, jsonb, jsonb, text) to authenticated;

-- ingang van een perceel (waar de route in Google Maps naartoe gaat): [lengtegraad, breedtegraad]
alter table public.percelen add column if not exists ingang jsonb;

-- =====================================================================
-- Gebouwen uit de BAG met 3D-model (3DBAG) + foto's/video's voor de film
-- =====================================================================
alter table public.percelen add column if not exists model3d    jsonb;
alter table public.percelen add column if not exists bag        jsonb;
alter table public.percelen add column if not exists film_media jsonb not null default '[]';

-- eigen opslagmap voor de film: foto's én video's tot 50 MB
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('film', 'film', false, 52428800, array['image/jpeg','image/png','image/webp','video/mp4','video/quicktime','video/webm','video/3gpp'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "film bekijken"    on storage.objects;
drop policy if exists "film toevoegen"   on storage.objects;
drop policy if exists "film verwijderen" on storage.objects;
create policy "film bekijken"    on storage.objects for select to authenticated using (bucket_id = 'film');
create policy "film toevoegen"   on storage.objects for insert to authenticated with check (bucket_id = 'film' and public.heeft_recht('percelen_bewerken'));
create policy "film verwijderen" on storage.objects for delete to authenticated using (bucket_id = 'film' and public.heeft_recht('percelen_bewerken'));

-- =====================================================================
-- ALLE MOGELIJKHEDEN ALS RECHT: plattegrond, AI, film, exporteren, instellingen en team
-- =====================================================================
create or replace function public.standaard_rechten() returns jsonb language sql immutable as $$
  select '{"percelen_tekenen":true,"percelen_bewerken":true,"spuitsporen_bewerken":true,"deelvelden_bewerken":true,
           "percelen_uitschakelen":false,"percelen_verwijderen":false,
           "soorten_indelen":true,"soorten_beheren":false,
           "taken_toevoegen":true,"taken_afvinken":true,"werk_registreren":true,"taken_verwijderen":false,
           "markeringen_maken":true,"weer_bekijken":true,"historie_bekijken":true,"seizoen_starten":false,
           "tractoren_volgen":true,"tractor_rijden":true,"tractoren_beheren":false,
           "voertuigen_zien":false,"voertuigen_beheren":false,
           "uren_bekijken":false,"uren_beheren":false,"uren_mailen":false,
           "middelen_beheren":false,"oogst_registreren":true,"oogst_bekijken":true,"partijen_beheren":false,
           "machines_beheren":false,"kosten_bekijken":false,
           "percelen_aanpassen":false,"kopeinden_bewerken":true,"gerooid_aangeven":true,
           "plattegrond_beheren":false,"ai_gebruiken":false,"film_bekijken":true,"film_beheren":false,"exporteren":true,
           "instellingen_beheren":false,"team_beheren":false}'::jsonb;
$$;
update public.profielen set rechten = public.standaard_rechten() || coalesce(rechten, '{}') where true;

create or replace function public.heeft_recht(r text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profielen
                 where id = auth.uid()
                   and (rol = 'beheerder'
                        or (coalesce((rechten->>r)::boolean, false)
                            and (r not in ('percelen_tekenen','percelen_bewerken','spuitsporen_bewerken','deelvelden_bewerken',
                                           'percelen_uitschakelen','percelen_verwijderen','soorten_indelen','kopeinden_bewerken','plattegrond_beheren')
                                 or coalesce((rechten->>'percelen_aanpassen')::boolean, false)))));
$$;

-- percelen bijwerken: ook plattegrond en film (de trigger bewaakt naam, vorm, sporen enz. apart)
drop policy if exists "wijzigen" on public.percelen;
create policy "wijzigen" on public.percelen for update to authenticated
  using (public.heeft_recht('percelen_bewerken') or public.heeft_recht('soorten_indelen') or public.heeft_recht('spuitsporen_bewerken')
      or public.heeft_recht('deelvelden_bewerken') or public.heeft_recht('percelen_uitschakelen')
      or public.heeft_recht('plattegrond_beheren') or public.heeft_recht('film_beheren')) with check (true);

drop policy if exists "fotos toevoegen"   on storage.objects;
drop policy if exists "fotos verwijderen" on storage.objects;
create policy "fotos toevoegen"   on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                       or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                       or public.heeft_recht('machines_beheren') or public.heeft_recht('tractor_rijden') or public.heeft_recht('percelen_bewerken')
                                       or public.heeft_recht('plattegrond_beheren')));
create policy "fotos verwijderen" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                  or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                  or public.heeft_recht('machines_beheren') or public.heeft_recht('percelen_bewerken') or public.heeft_recht('plattegrond_beheren')));
drop policy if exists "film toevoegen"   on storage.objects;
drop policy if exists "film verwijderen" on storage.objects;
create policy "film toevoegen"   on storage.objects for insert to authenticated with check (bucket_id = 'film' and public.heeft_recht('film_beheren'));
create policy "film verwijderen" on storage.objects for delete to authenticated using (bucket_id = 'film' and public.heeft_recht('film_beheren'));

-- instellingen (mail en uurtarief)
create or replace function public.mag_instellingen() returns boolean language sql stable security definer set search_path = '' as $$
  select public.is_beheerder() or public.heeft_recht('instellingen_beheren');
$$;
create or replace function public.zet_mail(p_aan text, p_van text, p_sleutel text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  insert into public.instellingen values ('mail_aan', nullif(trim(p_aan), ''))
    on conflict (sleutel) do update set waarde = excluded.waarde;
  insert into public.instellingen values ('mail_van', nullif(trim(p_van), ''))
    on conflict (sleutel) do update set waarde = excluded.waarde;
  if p_sleutel is not null then
    if trim(p_sleutel) = '' then delete from public.geheimen where sleutel = 'resend';
    else insert into public.geheimen values ('resend', trim(p_sleutel)) on conflict (sleutel) do update set waarde = excluded.waarde;
    end if;
  end if;
  insert into public.instellingen values ('mail_sleutel',
      case when exists (select 1 from public.geheimen where sleutel = 'resend') then '1' else null end)
    on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  if p_sleutel not in ('uurtarief') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;

-- team: beheerders alles; met "team_beheren" alleen medewerkers, en alleen rechten die je zelf hebt
create or replace function public.mag_team(p_doel uuid) returns boolean language sql stable security definer set search_path = '' as $$
  select public.is_beheerder()
      or (public.heeft_recht('team_beheren') and (p_doel is null or (p_doel <> auth.uid()
          and coalesce((select rol from public.profielen where id = p_doel), 'medewerker') <> 'beheerder')));
$$;
-- alleen de rechten die de huidige gebruiker zelf heeft mogen veranderen; de rest blijft zoals hij was
create or replace function public.eigen_rechten_filter(p_nieuw jsonb, p_oud jsonb) returns jsonb language sql stable security definer set search_path = '' as $$
  select case when public.is_beheerder() then p_nieuw
         else coalesce(p_oud, '{}') || coalesce((select jsonb_object_agg(k, v) from jsonb_each(coalesce(p_nieuw, '{}')) x(k, v) where public.heeft_recht(k)), '{}') end;
$$;
create or replace function public.maak_medewerker(p_email text, p_wachtwoord text, p_naam text,
                                                  p_rol text default 'medewerker', p_rechten jsonb default null)
returns uuid language plpgsql security definer set search_path = '' as $$
declare uid uuid := gen_random_uuid(); e text := lower(trim(p_email));
begin
  if not public.mag_team(null) then raise exception 'Je mag geen accounts aanmaken'; end if;
  if p_rol = 'beheerder' and not public.is_beheerder() then raise exception 'Alleen een beheerder mag beheerders aanmaken'; end if;
  if e !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'Ongeldig e-mailadres'; end if;
  if length(coalesce(p_wachtwoord,'')) < 6 then raise exception 'Wachtwoord moet minimaal 6 tekens zijn'; end if;
  if p_rol not in ('beheerder','medewerker') then raise exception 'Onbekende rol'; end if;
  if exists (select 1 from auth.users where lower(email) = e) then raise exception 'Dit e-mailadres heeft al een account'; end if;
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token, email_change, email_change_token_new)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', e,
    extensions.crypt(p_wachtwoord, extensions.gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}', jsonb_build_object('naam', trim(p_naam)), now(), now(), '', '', '', '');
  insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid, uid::text, jsonb_build_object('sub', uid::text, 'email', e, 'email_verified', true), 'email', now(), now(), now());
  update public.profielen
     set rol = p_rol, naam = trim(p_naam),
         rechten = public.eigen_rechten_filter(public.standaard_rechten() || coalesce(p_rechten, '{}'), public.standaard_rechten())
   where id = uid;
  return uid;
end $$;
create or replace function public.zet_wachtwoord(p_id uuid, p_wachtwoord text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_team(p_id) then raise exception 'Je mag dit wachtwoord niet instellen'; end if;
  if length(coalesce(p_wachtwoord,'')) < 6 then raise exception 'Wachtwoord moet minimaal 6 tekens zijn'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_wachtwoord, extensions.gen_salt('bf')), updated_at = now() where id = p_id;
end $$;
create or replace function public.wijzig_medewerker(p_id uuid, p_naam text, p_rol text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_team(p_id) then raise exception 'Je mag deze medewerker niet aanpassen'; end if;
  if p_rol not in ('beheerder','medewerker') then raise exception 'Onbekende rol'; end if;
  if not public.is_beheerder() and p_rol <> 'medewerker' then raise exception 'Alleen een beheerder mag iemand beheerder maken'; end if;
  if p_id = auth.uid() and p_rol <> 'beheerder' then raise exception 'Je kunt jezelf niet terugzetten naar medewerker'; end if;
  update public.profielen set naam = coalesce(nullif(trim(p_naam),''), naam), rol = p_rol where id = p_id;
end $$;
create or replace function public.zet_rechten(p_id uuid, p_rechten jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_team(p_id) then raise exception 'Je mag de rechten van deze persoon niet wijzigen'; end if;
  update public.profielen
     set rechten = case when public.is_beheerder() then public.standaard_rechten() || p_rechten
                        else public.eigen_rechten_filter(p_rechten, public.standaard_rechten() || coalesce(rechten, '{}')) end
   where id = p_id;
end $$;
create or replace function public.verwijder_medewerker(p_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_id = auth.uid() then raise exception 'Je kunt je eigen account niet verwijderen'; end if;
  if not public.mag_team(p_id) then raise exception 'Je mag dit account niet verwijderen'; end if;
  delete from auth.users where id = p_id;
end $$;
revoke all on function public.maak_medewerker(text,text,text,text,jsonb), public.zet_wachtwoord(uuid,text),
  public.wijzig_medewerker(uuid,text,text), public.zet_rechten(uuid,jsonb), public.verwijder_medewerker(uuid) from public, anon;
grant execute on function public.maak_medewerker(text,text,text,text,jsonb), public.zet_wachtwoord(uuid,text),
  public.wijzig_medewerker(uuid,text,text), public.zet_rechten(uuid,jsonb), public.verwijder_medewerker(uuid),
  public.mag_team(uuid), public.mag_instellingen(), public.heeft_recht(text) to authenticated;

-- =====================================================================
-- SPUITREGISTER, WEER, MONSTERS, KOELCEL/LEVERINGEN, KOSTPRIJS, BEMESTING
-- =====================================================================
alter table public.taken    add column if not exists weer jsonb;                       -- weer op het moment van spuiten
alter table public.middelen add column if not exists bio_toegestaan boolean not null default false;
alter table public.middelen add column if not exists n_per_eenheid numeric;            -- kg N per voorraad-eenheid
alter table public.middelen add column if not exists p_per_eenheid numeric;            -- kg P2O5 per voorraad-eenheid
alter table public.soorten  add column if not exists vorstgevoelig boolean;            -- leeg = op naam (aardbei, asperge, fruit)
alter table public.soorten  add column if not exists norm_n numeric;
alter table public.soorten  add column if not exists norm_p numeric;
alter table public.percelen add column if not exists norm_n numeric;
alter table public.percelen add column if not exists norm_p numeric;
alter table public.percelen add column if not exists bio boolean not null default false;

-- grondmonsters en keuringen (over alle seizoenen heen)
create table if not exists public.monsters (
  id         uuid primary key default gen_random_uuid(),
  perceel_id uuid references public.percelen(id) on delete cascade,
  partij_id  uuid references public.partijen(id) on delete set null,
  datum      date not null default current_date,
  soort      text not null default 'overig',     -- verticillium, aaltjes, grond, nak, blad, water, overig
  status     text not null default 'wacht',      -- goed, let, slecht, wacht
  uitslag    text,
  waarde     numeric,
  eenheid    text,
  lab        text,
  notitie    text,
  bestanden  jsonb not null default '[]',
  door       text,
  created_at timestamptz not null default now()
);
create index if not exists monsters_perceel on public.monsters (perceel_id, datum);
alter table public.monsters enable row level security;
grant select, insert, update, delete on public.monsters to authenticated;
drop policy if exists "lezen" on public.monsters;
drop policy if exists "schrijven" on public.monsters;
create policy "lezen"     on public.monsters for select to authenticated using (true);
create policy "schrijven" on public.monsters for all to authenticated using (public.heeft_recht('monsters_beheren')) with check (public.heeft_recht('monsters_beheren'));
do $$ begin alter publication supabase_realtime add table public.monsters; exception when duplicate_object then null; end $$;

-- koelcel en leveringen per partij
create table if not exists public.partij_mutaties (
  id          uuid primary key default gen_random_uuid(),
  partij_id   uuid not null references public.partijen(id) on delete cascade,
  seizoen_id  uuid references public.seizoenen(id) on delete set null,
  datum       date not null default current_date,
  soort       text not null check (soort in ('in','uit','uitval','correctie')),
  aantal      numeric not null,
  eenheid     text not null default 'trays',
  per_eenheid numeric,
  koelcel     text,
  klant       text,
  pakbon      text,
  prijs       numeric,
  notitie     text,
  door        text,
  created_at  timestamptz not null default now()
);
create index if not exists partij_mutaties_partij on public.partij_mutaties (partij_id, datum);
alter table public.partij_mutaties enable row level security;
grant select, insert, update, delete on public.partij_mutaties to authenticated;
drop policy if exists "lezen" on public.partij_mutaties;
drop policy if exists "schrijven" on public.partij_mutaties;
create policy "lezen"     on public.partij_mutaties for select to authenticated using (public.heeft_recht('voorraad_bekijken') or public.heeft_recht('voorraad_beheren'));
create policy "schrijven" on public.partij_mutaties for all to authenticated using (public.heeft_recht('voorraad_beheren')) with check (public.heeft_recht('voorraad_beheren'));
do $$ begin alter publication supabase_realtime add table public.partij_mutaties; exception when duplicate_object then null; end $$;

-- documenten (uitslagen als pdf of foto)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('documenten', 'documenten', false, 20971520, array['application/pdf','image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "documenten bekijken"    on storage.objects;
drop policy if exists "documenten toevoegen"   on storage.objects;
drop policy if exists "documenten verwijderen" on storage.objects;
create policy "documenten bekijken"    on storage.objects for select to authenticated using (bucket_id = 'documenten');
create policy "documenten toevoegen"   on storage.objects for insert to authenticated with check (bucket_id = 'documenten' and public.heeft_recht('monsters_beheren'));
create policy "documenten verwijderen" on storage.objects for delete to authenticated using (bucket_id = 'documenten' and public.heeft_recht('monsters_beheren'));

-- nieuwe rechten standaard
update public.profielen set rechten = '{"monsters_beheren":false,"voorraad_bekijken":true,"voorraad_beheren":false}'::jsonb || coalesce(rechten, '{}') where true;
create or replace function public.standaard_rechten() returns jsonb language sql immutable as $$
  select '{"percelen_tekenen":true,"percelen_bewerken":true,"spuitsporen_bewerken":true,"deelvelden_bewerken":true,
           "percelen_uitschakelen":false,"percelen_verwijderen":false,"soorten_indelen":true,"soorten_beheren":false,
           "taken_toevoegen":true,"taken_afvinken":true,"werk_registreren":true,"taken_verwijderen":false,
           "markeringen_maken":true,"weer_bekijken":true,"historie_bekijken":true,"seizoen_starten":false,
           "tractoren_volgen":true,"tractor_rijden":true,"tractoren_beheren":false,"voertuigen_zien":false,"voertuigen_beheren":false,
           "uren_bekijken":false,"uren_beheren":false,"uren_mailen":false,"middelen_beheren":false,"oogst_registreren":true,"oogst_bekijken":true,
           "partijen_beheren":false,"machines_beheren":false,"kosten_bekijken":false,"percelen_aanpassen":false,"kopeinden_bewerken":true,"gerooid_aangeven":true,
           "plattegrond_beheren":false,"ai_gebruiken":false,"film_bekijken":true,"film_beheren":false,"exporteren":true,"instellingen_beheren":false,"team_beheren":false,
           "monsters_beheren":false,"voorraad_bekijken":true,"voorraad_beheren":false}'::jsonb;
$$;

-- instellingen voor de weerwaarschuwingen
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;

-- ============ STARTSCHERM-ONDERDELEN (ziektes, plantplan, prognose, vruchtwisseling) ============
-- ziektes en plagen die in het veld gezien zijn, op het spoor waar het stond
create table if not exists public.waarnemingen (
  id         uuid primary key default gen_random_uuid(),
  perceel_id uuid references public.percelen(id) on delete cascade,
  seizoen_id uuid,
  datum      date not null default current_date,
  soort      text not null default 'ziekte',      -- ziekte, plaag, virus, onkruid, uitval, overig
  naam       text,
  ernst      int  not null default 1,              -- 1 licht, 2 matig, 3 ernstig
  status     text not null default 'open',         -- open, behandeld
  geo        jsonb,
  zone       text,
  spoor      int,
  notitie    text,
  fotos      jsonb not null default '[]',
  door       text,
  door_id    uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists waarnemingen_perceel on public.waarnemingen (perceel_id, datum);
alter table public.waarnemingen enable row level security;
grant select, insert, update, delete on public.waarnemingen to authenticated;
drop policy if exists "lezen" on public.waarnemingen;
drop policy if exists "toevoegen" on public.waarnemingen;
drop policy if exists "aanpassen" on public.waarnemingen;
drop policy if exists "verwijderen" on public.waarnemingen;
create policy "lezen"       on public.waarnemingen for select to authenticated using (true);
create policy "toevoegen"   on public.waarnemingen for insert to authenticated with check (public.heeft_recht('markeringen_maken') or public.heeft_recht('monsters_beheren'));
create policy "aanpassen"   on public.waarnemingen for update to authenticated using (public.heeft_recht('monsters_beheren') or door_id = auth.uid()) with check (true);
create policy "verwijderen" on public.waarnemingen for delete to authenticated using (public.heeft_recht('monsters_beheren') or door_id = auth.uid());
do $$ begin alter publication supabase_realtime add table public.waarnemingen; exception when duplicate_object then null; end $$;

-- wat er per ras geplant moet worden (zeker nodig + marge), voor het plantplan
create table if not exists public.plantbehoefte (
  id         uuid primary key default gen_random_uuid(),
  seizoen_id uuid,
  soort_id   uuid,
  ras_id     uuid,
  klasse     text,
  bio        boolean not null default false,
  nodig      numeric,
  marge      numeric not null default 0,
  pl_per_m   numeric,
  notitie    text,
  created_at timestamptz not null default now()
);
alter table public.plantbehoefte enable row level security;
grant select, insert, update, delete on public.plantbehoefte to authenticated;
drop policy if exists "lezen" on public.plantbehoefte;
drop policy if exists "schrijven" on public.plantbehoefte;
create policy "lezen"     on public.plantbehoefte for select to authenticated using (true);
create policy "schrijven" on public.plantbehoefte for all to authenticated using (public.heeft_recht('partijen_beheren')) with check (public.heeft_recht('partijen_beheren'));

-- prognose: opbrengst per geplante plant en planten per meter, per gewas
alter table public.soorten add column if not exists opbrengst_per_plant numeric;
alter table public.soorten add column if not exists pl_per_m numeric;
-- vruchtwisseling: wat er vóór de app op een perceel stond [{jaar, soort_id, gewas}]
alter table public.percelen add column if not exists teelthistorie jsonb not null default '[]';

-- losse sporen weghalen: de plekken in het raster die geen spoor meer zijn (deelvelden bewaren dit in vakken)
alter table public.percelen add column if not exists sporen_weg jsonb not null default '[]';

-- machines: gebruikt de machine meststoffen en/of spuitmiddelen ('mest', 'spuit', 'beide' of leeg)
alter table public.machines add column if not exists stoffen text;
-- foto's van machines en werktuigen (zodat je bij een taak ziet wat je moet pakken)
alter table public.machines add column if not exists fotos jsonb not null default '[]';

-- ============ CHAUFFEURS EN GEDEELDE APPARATEN (trekker-tablets) ============
alter table public.profielen add column if not exists chauffeur boolean not null default false;   -- staat in de lijst "wie rijdt er?"
alter table public.profielen add column if not exists apparaat  boolean not null default false;   -- gedeeld apparaat, bijv. de tablet in een trekker
create or replace function public.is_apparaat() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select apparaat from public.profielen where id = auth.uid()), false);
$$;
grant execute on function public.is_apparaat() to authenticated;
-- een trekker-tablet ziet van andere mensen niets (geen e-mail, rechten enz.), alleen zijn eigen profiel
drop policy if exists "lezen" on public.profielen;
create policy "lezen" on public.profielen for select to authenticated using (id = auth.uid() or not public.is_apparaat());
-- de namen van de chauffeurs (alleen naam), voor het kiesscherm op de tablet
create or replace function public.chauffeurs() returns table (id uuid, naam text) language sql stable security definer set search_path = '' as $$
  select p.id, p.naam from public.profielen p where p.chauffeur and not p.apparaat order by p.naam;
$$;
revoke all on function public.chauffeurs() from public, anon;
grant execute on function public.chauffeurs() to authenticated;
-- chauffeur / gedeeld apparaat aan- of uitzetten (gedeeld apparaat alleen door een beheerder)
create or replace function public.zet_profiel_vlag(p_id uuid, p_chauffeur boolean default null, p_apparaat boolean default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_team(p_id) then raise exception 'Je mag deze medewerker niet aanpassen'; end if;
  if p_apparaat is not null and not public.is_beheerder() then raise exception 'Alleen een beheerder mag een account als gedeeld apparaat instellen'; end if;
  update public.profielen set chauffeur = coalesce(p_chauffeur, chauffeur), apparaat = coalesce(p_apparaat, apparaat) where id = p_id;
end $$;
revoke all on function public.zet_profiel_vlag(uuid, boolean, boolean) from public, anon;
grant execute on function public.zet_profiel_vlag(uuid, boolean, boolean) to authenticated;
-- trekker-tablet koppelen aan een trekker: de tablet deelt dan de locatie van die trekker zolang hij aan staat
alter table public.profielen add column if not exists trekker_id uuid references public.tractoren(id) on delete set null;
create or replace function public.zet_trekker(p_id uuid, p_trekker uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder mag een tablet aan een trekker koppelen'; end if;
  update public.profielen set trekker_id = p_trekker where id = p_id;
end $$;
revoke all on function public.zet_trekker(uuid, uuid) from public, anon;
grant execute on function public.zet_trekker(uuid, uuid) to authenticated;

-- positie melden met de naam van de chauffeur (op de trekker-tablet kiest de chauffeur zichzelf)
drop function if exists public.meld_positie(uuid,double precision,double precision,numeric,numeric,numeric);
create or replace function public.meld_positie(p_tractor uuid, p_lat double precision, p_lng double precision,
  p_richting numeric default null, p_snelheid numeric default null, p_nauwkeurigheid numeric default null, p_bestuurder text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.heeft_recht('tractor_rijden') then raise exception 'Je mag geen locatie delen als tractor'; end if;
  perform public.zet_positie(p_tractor, p_lat, p_lng, p_richting, p_snelheid, p_nauwkeurigheid,
    coalesce(nullif(trim(p_bestuurder), ''), (select naam from public.profielen where id = auth.uid())));
end $$;
grant execute on function public.meld_positie(uuid,double precision,double precision,numeric,numeric,numeric,text) to authenticated;
-- wat er achter de trekker hangt (in de trekker-modus te kiezen)
alter table public.tractoren add column if not exists werktuig text;
create or replace function public.zet_werktuig(p_tractor uuid, p_werktuig text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not (public.heeft_recht('tractor_rijden') or public.heeft_recht('tractoren_beheren')) then raise exception 'Je mag dit niet aanpassen'; end if;
  update public.tractoren set werktuig = nullif(trim(p_werktuig), '') where id = p_tractor;
end $$;
revoke all on function public.zet_werktuig(uuid, text) from public, anon;
grant execute on function public.zet_werktuig(uuid, text) to authenticated;
-- voor of achter aangekoppeld, en de kleur van een machine (uit de foto) voor het 3D-model
alter table public.tractoren add column if not exists werktuig_voor text;
alter table public.machines  add column if not exists plek  text;   -- 'voor' of 'achter' (waar hij meestal hangt)
alter table public.machines  add column if not exists kleur text;   -- hoofdkleur, uit de foto of zelf gekozen
drop function if exists public.zet_werktuig(uuid, text);
create or replace function public.zet_werktuig(p_tractor uuid, p_werktuig text, p_voor text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not (public.heeft_recht('tractor_rijden') or public.heeft_recht('tractoren_beheren')) then raise exception 'Je mag dit niet aanpassen'; end if;
  update public.tractoren set werktuig = nullif(trim(p_werktuig), ''), werktuig_voor = nullif(trim(p_voor), '') where id = p_tractor;
end $$;
revoke all on function public.zet_werktuig(uuid, text, text) from public, anon;
grant execute on function public.zet_werktuig(uuid, text, text) to authenticated;
alter table public.machines add column if not exists kleur_zelf boolean default false;   -- kleur zelf gekozen i.p.v. uit de foto

-- ============ trekker-app: voortgang van een taak en pincodes voor de volledige app ============
-- welke sporen van een taak al klaar zijn (bij pauzeren/wisselen op de trekker)
alter table public.taken add column if not exists voortgang jsonb;

-- pincode per medewerker: daarmee opent een chauffeur op de trekkertablet de volledige app.
-- De pincodes staan in een eigen tabel waar niemand direct bij kan (alleen via de functies hieronder), versleuteld.
create extension if not exists pgcrypto with schema extensions;
create table if not exists public.pincodes (
  user_id uuid primary key references auth.users(id) on delete cascade,
  hash text not null,
  fouten int not null default 0,
  geblokkeerd_tot timestamptz,
  bijgewerkt timestamptz not null default now()
);
alter table public.pincodes enable row level security;
revoke all on public.pincodes from anon, authenticated;

create or replace function public.zet_pin(p_user uuid, p_pin text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then raise exception 'De pincode moet 4 tot 8 cijfers zijn'; end if;
  if public.is_apparaat() then raise exception 'Een pincode stel je in op je eigen telefoon of computer'; end if;
  if p_user is distinct from auth.uid() and not public.is_beheerder() then raise exception 'Alleen een beheerder mag de pincode van iemand anders instellen'; end if;
  insert into public.pincodes (user_id, hash) values (p_user, extensions.crypt(p_pin, extensions.gen_salt('bf')))
  on conflict (user_id) do update set hash = excluded.hash, fouten = 0, geblokkeerd_tot = null, bijgewerkt = now();
end $$;
revoke all on function public.zet_pin(uuid, text) from public, anon;
grant execute on function public.zet_pin(uuid, text) to authenticated;

create or replace function public.heeft_pin(p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.pincodes where user_id = p_user);
$$;
revoke all on function public.heeft_pin(uuid) from public, anon;
grant execute on function public.heeft_pin(uuid) to authenticated;

-- controleren: na 5 foute pogingen 10 minuten geblokkeerd
create or replace function public.controleer_pin(p_user uuid, p_pin text) returns text
language plpgsql security definer set search_path = '' as $$
declare r public.pincodes%rowtype;
begin
  select * into r from public.pincodes where user_id = p_user for update;
  if not found then return 'geen'; end if;
  if r.geblokkeerd_tot is not null and r.geblokkeerd_tot > now() then return 'blok'; end if;
  if r.hash = extensions.crypt(coalesce(p_pin, ''), r.hash) then
    update public.pincodes set fouten = 0, geblokkeerd_tot = null where user_id = p_user; return 'ok';
  end if;
  update public.pincodes set fouten = r.fouten + 1,
    geblokkeerd_tot = case when r.fouten + 1 >= 5 then now() + interval '10 minutes' else null end where user_id = p_user;
  return 'fout';
end $$;
revoke all on function public.controleer_pin(uuid, text) from public, anon;
grant execute on function public.controleer_pin(uuid, text) to authenticated;

-- ============ ROOIPLANNING ============
-- per rooi-opdracht: welke dag, wat (partij of in woorden), hoeveel, welke rooier, wie erop, bijrijders en bakkenisten
create table if not exists public.rooiplanning (
  id          uuid primary key default gen_random_uuid(),
  datum       date not null,
  perceel_id  uuid references public.percelen(id) on delete set null,
  partij_id   uuid,
  wat         text,
  vakken      jsonb not null default '[]',     -- vakletters; leeg = hele perceel
  aantal      numeric,
  eenheid     text,
  rooier      text,
  chauffeur_id uuid,
  bijrijders  jsonb not null default '[]',     -- profiel-id's
  bakkenisten jsonb not null default '[]',     -- profiel-id's (achterop de wagen)
  notitie     text,
  taak_id     uuid references public.taken(id) on delete set null,
  door_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);
create index if not exists rooiplanning_datum on public.rooiplanning (datum);
alter table public.rooiplanning enable row level security;
grant select, insert, update, delete on public.rooiplanning to authenticated;
drop policy if exists "lezen" on public.rooiplanning;
drop policy if exists "toevoegen" on public.rooiplanning;
drop policy if exists "aanpassen" on public.rooiplanning;
drop policy if exists "verwijderen" on public.rooiplanning;
create policy "lezen"       on public.rooiplanning for select to authenticated using (true);
create policy "toevoegen"   on public.rooiplanning for insert to authenticated with check (public.heeft_recht('taken_toevoegen'));
create policy "aanpassen"   on public.rooiplanning for update to authenticated using (public.heeft_recht('taken_toevoegen')) with check (true);
create policy "verwijderen" on public.rooiplanning for delete to authenticated using (public.heeft_recht('taken_toevoegen'));
do $$ begin alter publication supabase_realtime add table public.rooiplanning; exception when duplicate_object then null; when undefined_object then null; end $$;

-- ============ trekkers: nep-live (om te laten zien / testen) ============
alter table public.tractoren add column if not exists nep_live boolean not null default false;

-- ============ SPUITREGISTRATIE VOLGENS DE EU-REGELS (2023/564) ============
-- toelatingsnummer stond er al; erbij: EPPO-code per gewas, BBCH-stadium, behandeld oppervlak, vervaldatum van een middel
alter table public.soorten  add column if not exists eppo text;            -- bijv. FRAAN = aardbei
alter table public.taken    add column if not exists bbch text;            -- groeistadium (als het etiket dat vraagt)
alter table public.taken    add column if not exists behandeld_ha numeric; -- behandeld oppervlak (leeg = uit de kaart)
alter table public.middelen add column if not exists vervaldatum date;     -- einddatum toelating (Ctgb)
alter table public.middelen add column if not exists ctgb_id text;

-- Ctgb-middelendatabank opvragen (openbare gegevens). Via de database, omdat de browser het Ctgb niet rechtstreeks mag aanroepen.
create or replace function public.ctgb(p_pad text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare r extensions.http_response;
begin
  if auth.uid() is null then raise exception 'Niet ingelogd'; end if;
  if p_pad !~ '^authorisations(/[0-9]+)?(\?[A-Za-z0-9%=&_.,:+-]*)?$' then raise exception 'Ongeldige vraag aan het Ctgb'; end if;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '15000');
  r := extensions.http(('GET', 'https://public.mst.ctgb.nl/public-api/1.0/' || p_pad,
         array[extensions.http_header('Accept', 'application/json')], null, null)::extensions.http_request);
  if r.status <> 200 then raise exception 'Ctgb gaf foutcode %', r.status; end if;
  return r.content::jsonb;
end $$;
revoke all on function public.ctgb(text) from public, anon;
grant execute on function public.ctgb(text) to authenticated;
alter table public.rooiplanning add column if not exists pl_per_m numeric;   -- planten per meter (bij eenheid planten)
alter table public.rooiplanning add column if not exists chauffeur_naam text;   -- iemand zonder account op de rooier

-- ============ instellingen bij werk: diepte, snelheid, toerental ============
alter table public.machines add column if not exists std_diepte   numeric;   -- cm
alter table public.machines add column if not exists std_snelheid numeric;   -- km/u
alter table public.machines add column if not exists std_toeren   numeric;   -- omw/min
alter table public.taken    add column if not exists diepte       numeric;
alter table public.taken    add column if not exists snelheid     numeric;
alter table public.taken    add column if not exists toeren       numeric;
alter table public.rooiplanning add column if not exists rijen jsonb not null default '[]';   -- losse rijen: ["zone-id:nr", ...]
alter table public.rooiplanning add column if not exists wat_auto boolean not null default false;   -- wat er gerooid wordt automatisch uit de vakken/rijen
alter table public.rooiplanning add column if not exists regels jsonb not null default '[]';   -- per partij: hoeveel, en per rij hoeveel meter er stond

-- ============ meewerk-taken (bijrijder, bakkenist) bij een hoofdtaak ============
-- Een meewerk-taak hoort bij een hoofdtaak (bijv. rooien). Je kunt er alleen "bezig" mee zijn (voor de uren);
-- hij is pas klaar als de hoofdtaak klaar is (dat regelt de database).
alter table public.taken add column if not exists hoofd_taak uuid references public.taken(id) on delete cascade;
alter table public.taken add column if not exists rol text;   -- 'bijrijder' of 'bakkenist'
create index if not exists taken_hoofd on public.taken (hoofd_taak);
create or replace function public.subtaken_mee() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.klaar is distinct from old.klaar then
    update public.taken set klaar = new.klaar,
      klaar_door = case when new.klaar then coalesce(bezig_door, klaar_door, new.klaar_door) else null end,
      klaar_op   = case when new.klaar then new.klaar_op else null end,
      bezig_door = null, bezig_sinds = null
    where hoofd_taak = new.id and klaar is distinct from new.klaar;
  end if;
  return new;
end $$;
drop trigger if exists taken_subtaken on public.taken;
create trigger taken_subtaken after update of klaar on public.taken for each row execute function public.subtaken_mee();

-- ============ bakkenist: uren lopen mee met de rooier ============
-- De bakkenist (achterop de wagen) heeft geen eigen taak of tablet. Zodra de chauffeur met de rooitaak bezig is,
-- lopen de uren van de bakkenist(en) uit de rooiplanning mee: op hun eigen naam, en bij een account ook op hun account.
create or replace function public.taak_uren_bakkenist() returns trigger
language plpgsql security definer set search_path = '' as $$
declare r record; b text;
begin
  if new.bezig_door is not null and not new.klaar
     and (new.bezig_door is distinct from old.bezig_door or new.bezig_sinds is distinct from old.bezig_sinds) then
    for r in select * from public.rooiplanning where taak_id = new.id loop
      for b in select jsonb_array_elements_text(coalesce(r.bakkenisten, '[]'::jsonb)) loop
        insert into public.uren (taak_id, taak_tekst, perceel_id, user_id, naam, start)
        values (new.id, new.tekst || ' (bakkenist)', coalesce(new.perceel_id, new.van_perceel),
                case when b like '~%' then null else (select id from public.profielen where id::text = b) end,
                case when b like '~%' then substr(b, 2) else coalesce((select naam from public.profielen where id::text = b), 'bakkenist') end,
                coalesce(new.bezig_sinds, now()));
      end loop;
    end loop;
  end if;
  return new;
end $$;
drop trigger if exists taak_uren_bakkenist on public.taken;   -- na taak_uren (die eerst alle open uren van de taak afsluit)
create trigger taak_uren_bakkenist after update on public.taken for each row execute function public.taak_uren_bakkenist();
-- bakkenisten hebben geen eigen meewerk-taak meer
delete from public.taken where hoofd_taak is not null and rol like 'bakkenist|%' and not klaar;

-- ============ INKLOKKEN (iPad in de kantine) ============
-- Een prikklok-account (gedeeld apparaat in de kantine) toont alle namen; tik je naam aan om in of uit te klokken.
-- Staat "inklokken verplicht" aan, dan kun je pas taken afvinken / oppakken en vlaggen of waarnemingen zetten als je vandaag bent ingeklokt.
-- Een beheerder mag altijd alles.
alter table public.profielen add column if not exists prikklok boolean not null default false;
create table if not exists public.klok (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  naam    text not null,
  binnen  timestamptz not null default now(),
  buiten  timestamptz,
  pauze_min int,                       -- pauze in minuten (gevraagd bij uitklokken)
  door    uuid default auth.uid()
);
alter table public.klok add column if not exists pauze_min int;
create index if not exists klok_dag on public.klok (binnen);
alter table public.klok enable row level security;
grant select on public.klok to authenticated;
drop policy if exists "lezen" on public.klok;
create policy "lezen" on public.klok for select to authenticated using (true);
do $$ begin alter publication supabase_realtime add table public.klok; exception when duplicate_object then null; when undefined_object then null; end $$;

create or replace function public.vandaag_begin() returns timestamptz language sql stable set search_path = '' as $$
  select (date_trunc('day', now() at time zone 'Europe/Amsterdam')) at time zone 'Europe/Amsterdam';
$$;
create or replace function public.is_prikklok() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select prikklok from public.profielen where id = auth.uid()), false);
$$;
grant execute on function public.is_prikklok() to authenticated;
create or replace function public.klokplicht() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select waarde from public.instellingen where sleutel = 'klokplicht'), '') = 'ja';
$$;
create or replace function public.ingeklokt(p_uid uuid) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.klok where user_id = p_uid and buiten is null and binnen >= public.vandaag_begin());
$$;
create or replace function public.ingeklokt_naam(p_naam text) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.klok k where k.buiten is null and k.binnen >= public.vandaag_begin()
                 and (lower(k.naam) = lower(trim(p_naam)) or k.user_id in (select id from public.profielen where lower(naam) = lower(trim(p_naam)))));
$$;
grant execute on function public.ingeklokt(uuid) to authenticated;
grant execute on function public.ingeklokt_naam(text) to authenticated;

-- de namenlijst voor de kantine-iPad (alleen naam, geen andere gegevens)
create or replace function public.klok_namen() returns table (id uuid, naam text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.naam from public.profielen p
  where (public.is_prikklok() or public.is_beheerder()) and coalesce(p.apparaat, false) = false and p.naam is not null
  order by p.naam;
$$;
revoke all on function public.klok_namen() from public, anon;
grant execute on function public.klok_namen() to authenticated;

-- in- of uitklokken: op de kantine-iPad of door een beheerder
drop function if exists public.klok_zet(uuid, boolean);
create or replace function public.klok_zet(p_user uuid, p_in boolean, p_pauze int default null) returns text
language plpgsql security definer set search_path = '' as $$
declare n text;
begin
  if not (public.is_prikklok() or public.is_beheerder()) then raise exception 'Inklokken kan alleen op de iPad in de kantine'; end if;
  select naam into n from public.profielen where id = p_user; if n is null then raise exception 'Onbekende medewerker'; end if;
  if p_in then
    if public.ingeklokt(p_user) then return 'al'; end if;
    insert into public.klok (user_id, naam) values (p_user, n); return 'in';
  else
    update public.klok set buiten = now(), pauze_min = greatest(0, coalesce(p_pauze, 0)) where user_id = p_user and buiten is null; return 'uit';
  end if;
end $$;
revoke all on function public.klok_zet(uuid, boolean, int) from public, anon;
grant execute on function public.klok_zet(uuid, boolean, int) to authenticated;

-- prikklok-account instellen (beheerder); het is meteen ook een gedeeld apparaat (geen persoonlijke gegevens)
create or replace function public.zet_prikklok(p_id uuid, p_aan boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder mag een prikklok-account instellen'; end if;
  update public.profielen set prikklok = p_aan, apparaat = case when p_aan then true else apparaat end where id = p_id;
end $$;
revoke all on function public.zet_prikklok(uuid, boolean) from public, anon;
grant execute on function public.zet_prikklok(uuid, boolean) to authenticated;

-- instelling "inklokken verplicht"
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
end $$;

-- controle: taken oppakken/afvinken alleen als je ingeklokt bent
create or replace function public.klok_taak() returns trigger
language plpgsql security definer set search_path = '' as $$
declare wie text;
begin
  if auth.uid() is null or not public.klokplicht() or public.is_beheerder() then return new; end if;
  if (new.bezig_door is not null and new.bezig_door is distinct from old.bezig_door) or (new.klaar and not old.klaar) then
    wie := case when new.klaar and not old.klaar then new.klaar_door else new.bezig_door end;
    if public.is_apparaat() then
      if not public.ingeklokt_naam(wie) then raise exception 'NIET_INGEKLOKT: % is vandaag nog niet ingeklokt', wie; end if;
    elsif not public.ingeklokt(auth.uid()) then raise exception 'NIET_INGEKLOKT: je bent vandaag nog niet ingeklokt'; end if;
  end if;
  return new;
end $$;
drop trigger if exists klok_taak on public.taken;
create trigger klok_taak before update on public.taken for each row execute function public.klok_taak();

-- controle: vlaggen, gebieden en waarnemingen alleen als je ingeklokt bent (trekker-tablets mogen wel)
create or replace function public.klok_maken() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null or not public.klokplicht() or public.is_beheerder() or public.is_apparaat() then return new; end if;
  if not public.ingeklokt(auth.uid()) then raise exception 'NIET_INGEKLOKT: je bent vandaag nog niet ingeklokt'; end if;
  return new;
end $$;
drop trigger if exists klok_markering on public.markeringen;
create trigger klok_markering before insert on public.markeringen for each row execute function public.klok_maken();
drop trigger if exists klok_waarneming on public.waarnemingen;
create trigger klok_waarneming before insert on public.waarnemingen for each row execute function public.klok_maken();

-- alleen een beheerder kan iemand anders "niet meer bezig" zetten (of zijn taak overnemen)
create or replace function public.bezig_eigen() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null or public.is_beheerder() or public.is_apparaat() then return new; end if;   -- trekkertablet: de app regelt het per chauffeur
  if old.bezig_door is not null and new.bezig_door is distinct from old.bezig_door and not (new.klaar and not old.klaar)
     and lower(old.bezig_door) <> lower(coalesce((select naam from public.profielen where id = auth.uid()), '')) then
    raise exception 'BEZIG_ANDER: % is hiermee bezig', old.bezig_door;
  end if;
  return new;
end $$;
drop trigger if exists bezig_eigen on public.taken;
create trigger bezig_eigen before update on public.taken for each row execute function public.bezig_eigen();

-- =====================================================================================
-- ============ RESULTATENREGISTRATIE (poten → rooien → kiepen → sorteren → telling) ============
-- =====================================================================================
-- Eén database voor het hele seizoen; het seizoen is een veld (geen nieuw bestand per jaar).
-- Alles wordt met datum, tijd en naam vastgelegd. Invoer wordt nooit overschreven: een correctie is een
-- nieuwe regel (met reden en naam) die naar de oorspronkelijke regel verwijst.

-- 1. Poten en zaaien: extra velden op de partij (één partij = één NAK-nummer/blok)
alter table public.partijen add column if not exists teelt            text;     -- frigo / vers / stekjes / potplanten …
alter table public.partijen add column if not exists pootdatum        date;
alter table public.partijen add column if not exists herkomst         text;
alter table public.partijen add column if not exists gevraagde_klasse text;
alter table public.partijen add column if not exists sortering        text;
alter table public.partijen add column if not exists pl_per_m         numeric;
alter table public.partijen add column if not exists geleverd         numeric;
alter table public.partijen add column if not exists retour           numeric;
alter table public.partijen add column if not exists gepoot           numeric;
alter table public.partijen add column if not exists ha               numeric;
alter table public.partijen add column if not exists bedden           numeric;
alter table public.partijen add column if not exists bedlengte        numeric;  -- m (later uit de GPS van de perceel-app)
alter table public.partijen add column if not exists totale_meters    numeric;  -- leeg = bedden × bedlengte, of uit de kaart

-- 2. Lijsten die per bedrijf in te stellen zijn
create table if not exists public.res_sorteringen (
  id uuid primary key default gen_random_uuid(),
  teelt text,                                  -- leeg = voor alle teelten
  naam text not null,
  volgorde int not null default 0,
  actief boolean not null default true
);
create table if not exists public.res_baksoorten (
  id uuid primary key default gen_random_uuid(),
  naam text not null,
  planten_gem numeric,                         -- gemiddeld aantal planten in een bak
  actief boolean not null default true
);
alter table public.res_sorteringen enable row level security;
alter table public.res_baksoorten  enable row level security;
grant select, insert, update, delete on public.res_sorteringen, public.res_baksoorten to authenticated;
drop policy if exists "lezen" on public.res_sorteringen;   create policy "lezen" on public.res_sorteringen for select to authenticated using (true);
drop policy if exists "beheren" on public.res_sorteringen; create policy "beheren" on public.res_sorteringen for all to authenticated using (public.heeft_recht('resultaten_beheren')) with check (public.heeft_recht('resultaten_beheren'));
drop policy if exists "lezen" on public.res_baksoorten;    create policy "lezen" on public.res_baksoorten for select to authenticated using (true);
drop policy if exists "beheren" on public.res_baksoorten;  create policy "beheren" on public.res_baksoorten for all to authenticated using (public.heeft_recht('resultaten_beheren')) with check (public.heeft_recht('resultaten_beheren'));
insert into public.res_baksoorten (naam) select 'Bak' where not exists (select 1 from public.res_baksoorten);

-- 3. Prognose per partij (of per ras), per sortering; handmatig aangepast = gemarkeerd
create table if not exists public.res_prognose (
  id uuid primary key default gen_random_uuid(),
  seizoen_id uuid references public.seizoenen(id) on delete cascade,
  partij_id uuid references public.partijen(id) on delete cascade,
  teelt text, ras text,
  sortering text,                              -- leeg = totaal
  planten numeric,                             -- verwacht aantal planten
  per_ha numeric,                              -- of: planten per hectare
  handmatig boolean not null default false,
  bron text,                                   -- '5jaar' / 'hand' / 'exact' / 'import'
  door text, created_at timestamptz not null default now()
);
create index if not exists res_prognose_partij on public.res_prognose (partij_id);
alter table public.res_prognose enable row level security;
grant select, insert, update, delete on public.res_prognose to authenticated;
drop policy if exists "lezen" on public.res_prognose;   create policy "lezen" on public.res_prognose for select to authenticated using (public.heeft_recht('resultaten_bekijken') or public.heeft_recht('resultaten_beheren'));
drop policy if exists "beheren" on public.res_prognose; create policy "beheren" on public.res_prognose for all to authenticated using (public.heeft_recht('resultaten_beheren')) with check (public.heeft_recht('resultaten_beheren'));

-- 4. Alle invoer: rooien, kiepen, sorteren (SSOR), logistieke telling – één regel per actie
create table if not exists public.res_invoer (
  id uuid primary key default gen_random_uuid(),
  seizoen_id uuid references public.seizoenen(id) on delete cascade,
  soort text not null check (soort in ('rooien', 'kiepen', 'sorteren', 'telling')),
  datum date not null default current_date,
  partij_id uuid not null references public.partijen(id) on delete cascade,
  vak text,                                    -- bed / vak / rijen
  bedden numeric, meters numeric, bakken numeric, baksoort text,
  sortering text, klasse text, planten numeric,
  bron text not null default 'hand',           -- hand / trekker / ssor / import
  ref text,                                    -- unieke sleutel (bijv. SSOR-regel of trekker-rij) tegen dubbel inlezen
  correctie_van uuid references public.res_invoer(id) on delete set null,
  reden text,                                  -- verplicht bij een correctie
  opmerking text,
  door text, user_id uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists res_invoer_partij on public.res_invoer (partij_id, soort);
create unique index if not exists res_invoer_ref on public.res_invoer (ref) where ref is not null;
alter table public.res_invoer enable row level security;
grant select, insert, update, delete on public.res_invoer to authenticated;
drop policy if exists "lezen" on public.res_invoer;
create policy "lezen" on public.res_invoer for select to authenticated using (true);
drop policy if exists "invoeren" on public.res_invoer;
create policy "invoeren" on public.res_invoer for insert to authenticated with check (
  case when soort in ('sorteren') or correctie_van is not null then public.heeft_recht('resultaten_beheren')
       else public.heeft_recht('resultaten_invoeren') or public.heeft_recht('resultaten_beheren') or public.is_apparaat() end);   -- trekker-tablets mogen rooien invoeren
-- niets overschrijven of weggooien (correctie = nieuwe regel); alleen een beheerder kan in noodgevallen verwijderen
drop policy if exists "verwijderen" on public.res_invoer;
create policy "verwijderen" on public.res_invoer for delete to authenticated using (public.is_beheerder());
do $$ begin alter publication supabase_realtime add table public.res_invoer; exception when duplicate_object then null; when undefined_object then null; end $$;

-- controles bij het opslaan
create or replace function public.res_controle() returns trigger
language plpgsql security definer set search_path = '' as $$
declare gerooid numeric; gekiept numeric;
begin
  if new.seizoen_id is null then select seizoen_id into new.seizoen_id from public.partijen where id = new.partij_id; end if;
  if new.door is null then new.door := coalesce((select naam from public.profielen where id = auth.uid()), 'onbekend'); end if;
  if new.correctie_van is not null and coalesce(trim(new.reden), '') = '' then raise exception 'RES: bij een correctie hoort een reden'; end if;
  if new.soort = 'kiepen' then
    select coalesce(sum(bakken), 0) into gerooid from public.res_invoer where partij_id = new.partij_id and soort = 'rooien';
    select coalesce(sum(bakken), 0) into gekiept from public.res_invoer where partij_id = new.partij_id and soort = 'kiepen';
    if gekiept + coalesce(new.bakken, 0) > gerooid then
      raise exception 'RES: er kunnen niet meer bakken gekiept worden dan er gerooid zijn (gerooid %, al gekiept %)', gerooid, gekiept;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists res_controle on public.res_invoer;
create trigger res_controle before insert on public.res_invoer for each row execute function public.res_controle();

-- 5. Rechten (standaard: invoeren mag iedereen die het krijgt; bekijken/beheren zet de beheerder aan)
-- (resultaten_invoeren, resultaten_bekijken, resultaten_beheren staan in de app bij Team → rechten)

-- =====================================================================================
-- ============ GEBEURTENISSEN (wie deed wat, wanneer) ============
-- =====================================================================================
create table if not exists public.gebeurtenissen (
  id uuid primary key default gen_random_uuid(),
  tijd timestamptz not null default now(),
  user_id uuid default auth.uid(),
  naam text,
  soort text,                                  -- taak / resultaat / klok / uren / ziek / instelling
  tekst text not null,
  ref_id uuid
);
create index if not exists gebeurtenissen_tijd on public.gebeurtenissen (tijd desc);
alter table public.gebeurtenissen enable row level security;
grant select on public.gebeurtenissen to authenticated;
drop policy if exists "lezen" on public.gebeurtenissen;
create policy "lezen" on public.gebeurtenissen for select to authenticated using (public.heeft_recht('historie_bekijken') or user_id = auth.uid());
do $$ begin alter publication supabase_realtime add table public.gebeurtenissen; exception when duplicate_object then null; when undefined_object then null; end $$;

create or replace function public.gebeurtenis(p_soort text, p_tekst text, p_ref uuid default null, p_naam text default null) returns void
language sql security definer set search_path = '' as $$
  insert into public.gebeurtenissen (naam, soort, tekst, ref_id)
  values (coalesce(p_naam, (select naam from public.profielen where id = auth.uid()), 'systeem'), p_soort, p_tekst, p_ref);
$$;
grant execute on function public.gebeurtenis(text, text, uuid, text) to authenticated;

create or replace function public.log_taak() returns trigger
language plpgsql security definer set search_path = '' as $$
declare p text;
begin
  select naam into p from public.percelen where id = coalesce(new.perceel_id, old.perceel_id);
  if tg_op = 'INSERT' then
    perform public.gebeurtenis('taak', 'Nieuwe taak: ' || new.tekst || coalesce(' · ' || p, '') || coalesce(' · gepland ' || to_char(new.gepland, 'DD-MM'), ''), new.id);
  elsif tg_op = 'DELETE' then
    perform public.gebeurtenis('taak', 'Taak verwijderd: ' || old.tekst || coalesce(' · ' || p, ''), old.id);
  else
    if new.klaar and not old.klaar then perform public.gebeurtenis('taak', '✓ Klaar: ' || new.tekst || coalesce(' · ' || p, ''), new.id, new.klaar_door);
    elsif old.klaar and not new.klaar then perform public.gebeurtenis('taak', '↶ Weer open: ' || new.tekst || coalesce(' · ' || p, ''), new.id);
    elsif new.bezig_door is not null and new.bezig_door is distinct from old.bezig_door then perform public.gebeurtenis('taak', '▶ Begonnen: ' || new.tekst || coalesce(' · ' || p, ''), new.id, new.bezig_door);
    elsif new.bezig_door is null and old.bezig_door is not null and not new.klaar then perform public.gebeurtenis('taak', '⏸ Gestopt: ' || new.tekst || coalesce(' · ' || p, ''), new.id, old.bezig_door);
    elsif (new.gepland, new.toegewezen_aan, new.tekst, new.product, new.dosering) is distinct from (old.gepland, old.toegewezen_aan, old.tekst, old.product, old.dosering) then
      perform public.gebeurtenis('taak', '✏️ Aangepast: ' || new.tekst || coalesce(' · ' || p, ''), new.id);
    end if;
  end if;
  return coalesce(new, old);
end $$;
drop trigger if exists log_taak on public.taken;
create trigger log_taak after insert or update or delete on public.taken for each row execute function public.log_taak();

create or replace function public.log_res() returns trigger
language plpgsql security definer set search_path = '' as $$
declare pt text;
begin
  select coalesce(nak, batch, ras_tekst) into pt from public.partijen where id = new.partij_id;
  perform public.gebeurtenis('resultaat', initcap(new.soort) || ' · ' || coalesce(pt, '?') ||
    coalesce(' · ' || new.bakken || ' bakken', '') || coalesce(' · ' || new.meters || ' m', '') || coalesce(' · ' || new.planten || ' planten', '') ||
    case when new.correctie_van is not null then ' · correctie: ' || coalesce(new.reden, '') else '' end, new.id, new.door);
  return new;
end $$;
drop trigger if exists log_res on public.res_invoer;
create trigger log_res after insert on public.res_invoer for each row execute function public.log_res();

create or replace function public.log_klok() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' then perform public.gebeurtenis('klok', '🟢 Ingeklokt', new.id, new.naam);
  elsif new.buiten is not null and old.buiten is null then perform public.gebeurtenis('klok', '👋 Uitgeklokt' || coalesce(' (' || new.pauze_min || ' min pauze)', ''), new.id, new.naam);
  end if;
  return new;
end $$;
drop trigger if exists log_klok on public.klok;
create trigger log_klok after insert or update on public.klok for each row execute function public.log_klok();

-- =====================================================================================
-- ============ CORRECTIEVERZOEK UREN (in- en uitklokken) ============
-- =====================================================================================
-- De kantine-iPad is leidend. Wie een fout ziet, dient een verzoek in; een beheerder keurt met één klik goed.
create table if not exists public.klok_verzoek (
  id uuid primary key default gen_random_uuid(),
  klok_id uuid references public.klok(id) on delete set null,   -- leeg = een dag die helemaal ontbrak
  user_id uuid not null default auth.uid(),
  naam text,
  binnen timestamptz not null, buiten timestamptz, pauze_min int,
  reden text not null,
  status text not null default 'open' check (status in ('open', 'goed', 'afgewezen')),
  behandeld_door text, behandeld_op timestamptz,
  created_at timestamptz not null default now()
);
alter table public.klok_verzoek enable row level security;
grant select, insert on public.klok_verzoek to authenticated;
drop policy if exists "lezen" on public.klok_verzoek;
create policy "lezen" on public.klok_verzoek for select to authenticated using (user_id = auth.uid() or public.is_beheerder() or public.heeft_recht('uren_beheren'));
drop policy if exists "indienen" on public.klok_verzoek;
create policy "indienen" on public.klok_verzoek for insert to authenticated with check (user_id = auth.uid() and not public.is_apparaat());
do $$ begin alter publication supabase_realtime add table public.klok_verzoek; exception when duplicate_object then null; when undefined_object then null; end $$;

create or replace function public.klok_verzoek_besluit(p_id uuid, p_goed boolean) returns void
language plpgsql security definer set search_path = '' as $$
declare v public.klok_verzoek%rowtype; wie text;
begin
  if not (public.is_beheerder() or public.heeft_recht('uren_beheren')) then raise exception 'Alleen een beheerder kan dit goedkeuren'; end if;
  select * into v from public.klok_verzoek where id = p_id for update;
  if not found or v.status <> 'open' then raise exception 'Dit verzoek is al behandeld'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'beheerder');
  if p_goed then
    if v.klok_id is not null then update public.klok set binnen = v.binnen, buiten = v.buiten, pauze_min = v.pauze_min where id = v.klok_id;
    else insert into public.klok (user_id, naam, binnen, buiten, pauze_min) values (v.user_id, coalesce(v.naam, (select naam from public.profielen where id = v.user_id)), v.binnen, v.buiten, v.pauze_min); end if;
  end if;
  update public.klok_verzoek set status = case when p_goed then 'goed' else 'afgewezen' end, behandeld_door = wie, behandeld_op = now() where id = p_id;
  perform public.gebeurtenis('uren', case when p_goed then '✓ Correctie uren goedgekeurd voor ' else '✕ Correctie uren afgewezen voor ' end || coalesce(v.naam, ''), p_id);
end $$;
revoke all on function public.klok_verzoek_besluit(uuid, boolean) from public, anon;
grant execute on function public.klok_verzoek_besluit(uuid, boolean) to authenticated;
-- de klok zelf: alleen via de functies (beheerder kan direct)
drop policy if exists "beheer wijzigen" on public.klok;
grant update on public.klok to authenticated;
create policy "beheer wijzigen" on public.klok for update to authenticated using (public.is_beheerder()) with check (public.is_beheerder());

-- =====================================================================================
-- ============ ZIEKMELDING ============
-- =====================================================================================
create table if not exists public.ziek (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  naam text not null,
  van date not null default current_date,
  tot date,                                    -- leeg = nog ziek
  door text, created_at timestamptz not null default now()
);
alter table public.ziek enable row level security;
grant select, insert, update on public.ziek to authenticated;
drop policy if exists "lezen" on public.ziek;   create policy "lezen" on public.ziek for select to authenticated using (true);
drop policy if exists "melden" on public.ziek;  create policy "melden" on public.ziek for insert to authenticated with check (user_id = auth.uid() or public.is_beheerder() or public.heeft_recht('taken_toevoegen'));
drop policy if exists "beter" on public.ziek;   create policy "beter" on public.ziek for update to authenticated using (user_id = auth.uid() or public.is_beheerder() or public.heeft_recht('taken_toevoegen'));
do $$ begin alter publication supabase_realtime add table public.ziek; exception when duplicate_object then null; when undefined_object then null; end $$;
create or replace function public.log_ziek() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' then perform public.gebeurtenis('ziek', '🤒 Ziek gemeld: ' || new.naam || ' vanaf ' || to_char(new.van, 'DD-MM'), new.id);
  elsif new.tot is not null and old.tot is null then perform public.gebeurtenis('ziek', '💪 Beter gemeld: ' || new.naam, new.id); end if;
  return new;
end $$;
drop trigger if exists log_ziek on public.ziek;
create trigger log_ziek after insert or update on public.ziek for each row execute function public.log_ziek();

-- =====================================================================================
-- ============ PLANNING: soort werk met prioriteit ============
-- =====================================================================================
alter table public.taken add column if not exists categorie text;   -- spuiten / beregenen / machinaal / handwerk
-- instellingen erbij
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() and not (p_sleutel like 'res_%' and public.heeft_recht('resultaten_beheren')) then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' = ' || coalesce(p_waarde, '(leeg)'));
end $$;

-- =====================================================================================
-- ============ ROOIEN: WAGENS, KIEPLIJST (HEFTRUCK), KISTJES PER KWALITEIT, WERKPLEK ============
-- =====================================================================================
-- De rooier meldt elke wagen die naar het bedrijf gaat (10-, 14-, 16- of 18-bakker) en van welke partij(en) de bakken zijn.
-- De heftruckchauffeur bij de sorteerlijn tikt per bak aan welke partij hij kiept. De scangegevens (Dacom/SSOR) geven
-- per kwaliteit het aantal kistjes; met het aantal planten per kistje (per gewas, eventueel per ras) rekent de app de rest uit.
alter table public.res_invoer add column if not exists kistjes  numeric;   -- sorteren: aantal kistjes (planten = kistjes × inhoud)
alter table public.res_invoer add column if not exists wagen    text;      -- rooien: bijv. '14-bakker'
alter table public.res_invoer add column if not exists wagen_id uuid;      -- één wagen met meerdere partijen = zelfde wagen_id
alter table public.res_invoer add column if not exists taak_id  uuid references public.taken(id) on delete set null;
create index if not exists res_invoer_wagen on public.res_invoer (wagen_id) where wagen_id is not null;

-- eigen tik binnen 30 minuten terugdraaien ("oeps"): een gekiepte bak of een gemelde wagen
drop policy if exists "eigen terug" on public.res_invoer;
create policy "eigen terug" on public.res_invoer for delete to authenticated using (
  user_id = auth.uid() and correctie_van is null and created_at > now() - interval '30 minutes'
  and (soort = 'kiepen' or (soort = 'rooien' and wagen_id is not null)));

-- ook het terugdraaien komt in de gebeurtenissen
create or replace function public.log_res() returns trigger
language plpgsql security definer set search_path = '' as $$
declare pt text; r public.res_invoer%rowtype;
begin
  r := coalesce(new, old);
  select coalesce(nullif(concat_ws(' ', (select naam from public.rassen where id = p.ras_id), p.batch), ''), p.nak, p.ras_tekst) into pt from public.partijen p where p.id = r.partij_id;
  perform public.gebeurtenis('resultaat', case when tg_op = 'DELETE' then '↶ Teruggedraaid: ' else '' end || initcap(r.soort) || ' · ' || coalesce(pt, '?') ||
    coalesce(' · ' || r.wagen, '') ||
    coalesce(' · ' || r.bakken || ' bakken', '') || coalesce(' · ' || r.meters || ' m', '') || coalesce(' · ' || r.kistjes || ' kistjes', '') || coalesce(' · ' || r.planten || ' planten', '') ||
    case when r.correctie_van is not null then ' · correctie: ' || coalesce(r.reden, '') else '' end, r.id, r.door);
  return r;
end $$;
drop trigger if exists log_res on public.res_invoer;
create trigger log_res after insert or delete on public.res_invoer for each row execute function public.log_res();

-- kistjes per gewas en planten per kistje per kwaliteit (eventueel per ras; dat getal gaat dan voor)
create table if not exists public.res_kisten (
  id uuid primary key default gen_random_uuid(),
  soort_id uuid references public.soorten(id) on delete cascade,   -- gewas (leeg = standaard voor alles)
  naam text not null,
  actief boolean not null default true
);
create table if not exists public.res_kistinhoud (
  id uuid primary key default gen_random_uuid(),
  soort_id uuid references public.soorten(id) on delete cascade,
  ras_id uuid references public.rassen(id) on delete cascade,      -- leeg = geldt voor het hele gewas
  kwaliteit text not null,
  planten numeric not null check (planten > 0),
  door text, updated_at timestamptz not null default now()
);
create unique index if not exists res_kistinhoud_uniek on public.res_kistinhoud
  (coalesce(soort_id, '00000000-0000-0000-0000-000000000000'::uuid), coalesce(ras_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(kwaliteit));
alter table public.res_kisten enable row level security;
alter table public.res_kistinhoud enable row level security;
grant select, insert, update, delete on public.res_kisten, public.res_kistinhoud to authenticated;
drop policy if exists "lezen" on public.res_kisten;     create policy "lezen" on public.res_kisten for select to authenticated using (true);
drop policy if exists "beheren" on public.res_kisten;   create policy "beheren" on public.res_kisten for all to authenticated using (public.heeft_recht('resultaten_beheren')) with check (public.heeft_recht('resultaten_beheren'));
drop policy if exists "lezen" on public.res_kistinhoud;   create policy "lezen" on public.res_kistinhoud for select to authenticated using (true);
drop policy if exists "beheren" on public.res_kistinhoud; create policy "beheren" on public.res_kistinhoud for all to authenticated using (public.heeft_recht('resultaten_beheren')) with check (public.heeft_recht('resultaten_beheren'));
do $$ begin alter publication supabase_realtime add table public.res_kistinhoud; exception when duplicate_object then null; when undefined_object then null; end $$;

-- standaard kwaliteiten (alleen als er nog niets is ingesteld)
insert into public.res_sorteringen (naam, volgorde)
select k, i from (values ('A++', 1), ('A+', 2), ('A', 3), ('A-', 4), ('B', 5)) v(k, i)
where not exists (select 1 from public.res_sorteringen);

-- werkplek van een gedeeld apparaat: 'kiep' = telefoon van de heftruck (opent meteen de kieplijst)
alter table public.profielen add column if not exists werkplek text;
create or replace function public.zet_werkplek(p_id uuid, p_werkplek text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder mag dit instellen'; end if;
  if p_werkplek is not null and p_werkplek not in ('kiep') then raise exception 'Onbekende werkplek'; end if;
  update public.profielen set werkplek = p_werkplek, apparaat = case when p_werkplek is not null then true else apparaat end where id = p_id;
end $$;
revoke all on function public.zet_werkplek(uuid, text) from public, anon;
grant execute on function public.zet_werkplek(uuid, text) to authenticated;

-- instellingen: ook de wagens (bijv. '10,14,16,18')
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen() and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren')) then raise exception 'Je mag de instellingen niet aanpassen'; end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' = ' || coalesce(p_waarde, '(leeg)'));
end $$;

-- resultaten invoeren staat standaard aan (zoals in de app); alleen uit als de beheerder het uitzet
create or replace function public.mag_res_invoeren() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select coalesce((p.rechten->>'resultaten_invoeren')::boolean, true) from public.profielen p where p.id = auth.uid()), false);
$$;
grant execute on function public.mag_res_invoeren() to authenticated;
drop policy if exists "invoeren" on public.res_invoer;
create policy "invoeren" on public.res_invoer for insert to authenticated with check (
  case when soort in ('sorteren') or correctie_van is not null then public.heeft_recht('resultaten_beheren')
       else public.heeft_recht('resultaten_beheren') or public.is_apparaat()
         or public.mag_res_invoeren() end);

-- =====================================================================================
-- ============ AI-GEHEUGEN: vaste afspraken die de AI-assistent elke keer meekrijgt ============
-- =====================================================================================
-- De AI leert niet vanzelf. Wat hier staat ("onthoud: …" of een correctie die je bevestigt), krijgt hij bij elke vraag mee.
create table if not exists public.ai_geheugen (
  id uuid primary key default gen_random_uuid(),
  tekst text not null,
  door text, user_id uuid default auth.uid(),
  created_at timestamptz not null default now()
);
alter table public.ai_geheugen enable row level security;
grant select, insert, delete on public.ai_geheugen to authenticated;
drop policy if exists "lezen" on public.ai_geheugen;     create policy "lezen" on public.ai_geheugen for select to authenticated using (public.heeft_recht('ai_gebruiken'));
drop policy if exists "toevoegen" on public.ai_geheugen; create policy "toevoegen" on public.ai_geheugen for insert to authenticated with check (public.heeft_recht('ai_gebruiken') and not public.is_apparaat());
drop policy if exists "weghalen" on public.ai_geheugen;  create policy "weghalen" on public.ai_geheugen for delete to authenticated using (public.is_beheerder() or user_id = auth.uid());

-- ============ ROOIPLANNING: gegevens voor het afdrukformulier (rooiteam, starttijd, trekkers, wagens, laden/lossen) ============
alter table public.rooiplanning add column if not exists rooiteam  text;                          -- bijv. 'RT 1'
alter table public.rooiplanning add column if not exists starttijd text;                          -- bijv. '07:00'
alter table public.rooiplanning add column if not exists tractoren jsonb not null default '{}';   -- {"rooier": "T3 311", "<bijrijder>": "TH15 516"}
alter table public.rooiplanning add column if not exists wagens    jsonb not null default '{}';   -- {"<bijrijder>": "16"}  (16-bakker)
alter table public.rooiplanning add column if not exists laden     jsonb not null default '[]';   -- [{"naam": "Istvan", "tijd": "07:00"}]
alter table public.rooiplanning add column if not exists bakken    numeric;                       -- verwacht aantal bakken (als er geen regels per partij zijn)

-- =====================================================================================
-- ============ TAKEN: gezamenlijk, doorschuiven en iemand erbij halen ============
-- =====================================================================================
-- gezamenlijk = voor iedereen zichtbaar, wie hem pakt krijgt hem. meewerkers = extra mensen op dezelfde taak.
alter table public.taken add column if not exists gezamenlijk boolean not null default false;
alter table public.taken add column if not exists meewerkers  uuid[]  not null default '{}';

-- de rechten-controle per kolom: met de nieuwe kolommen erbij, en de functies hieronder mogen er langs
create or replace function public.controleer_taak() returns trigger language plpgsql as $$
begin
  if auth.uid() is null or current_setting('app.taak_rpc', true) = '1' then return new; end if;
  if (new.klaar, new.klaar_door, new.klaar_op, new.product, new.dosering, new.eenheid, new.uitvoering, new.bezig_door, new.bezig_sinds, new.middel_id, new.verbruik)
     is distinct from (old.klaar, old.klaar_door, old.klaar_op, old.product, old.dosering, old.eenheid, old.uitvoering, old.bezig_door, old.bezig_sinds, old.middel_id, old.verbruik)
     and not public.heeft_recht('taken_afvinken') then
    raise exception 'Je mag taken niet afvinken';
  end if;
  if (new.tekst, new.deadline, new.gepland, new.perceel_id, new.omschrijving, new.toegewezen_aan, new.gebied, new.spoor_van, new.spoor_tot,
      new.soort, new.wat, new.aantal, new.aantal_eenheid, new.van_perceel, new.van_punt, new.naar_perceel, new.naar_punt, new.herhaal, new.herhaal_tot, new.trekker, new.werktuig,
      new.gezamenlijk, new.meewerkers)
     is distinct from (old.tekst, old.deadline, old.gepland, old.perceel_id, old.omschrijving, old.toegewezen_aan, old.gebied, old.spoor_van, old.spoor_tot,
      old.soort, old.wat, old.aantal, old.aantal_eenheid, old.van_perceel, old.van_punt, old.naar_perceel, old.naar_punt, old.herhaal, old.herhaal_tot, old.trekker, old.werktuig,
      old.gezamenlijk, old.meewerkers)
     and not public.heeft_recht('taken_toevoegen') then
    raise exception 'Je mag taken niet wijzigen';
  end if;
  return new;
end $$;

-- mag ik met deze taak schuiven? (de planner altijd; anders alleen je eigen taak, of een gezamenlijke)
create or replace function public.mag_taak_schuiven(t public.taken, wie uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select public.heeft_recht('taken_toevoegen') or public.is_apparaat()
      or (public.heeft_recht('taken_afvinken') and (t.toegewezen_aan = wie or wie = any(t.meewerkers) or t.gezamenlijk or t.toegewezen_aan is null));
$$;

-- doorschuiven naar iemand anders, zelf pakken (p_aan = jezelf) of gezamenlijk maken (p_aan = null)
-- p_ik: op de trekkertablet de gekozen chauffeur, anders jijzelf
create or replace function public.taak_toewijzen(p_taak uuid, p_aan uuid, p_ik uuid default null) returns void
language plpgsql security definer set search_path = '' as $$
declare t public.taken; ik uuid := coalesce(case when public.is_apparaat() then p_ik end, auth.uid());
begin
  select * into t from public.taken where id = p_taak; if not found then raise exception 'Taak niet gevonden'; end if;
  if t.klaar then raise exception 'Deze taak is al klaar'; end if;
  if not public.mag_taak_schuiven(t, ik) then raise exception 'Je mag deze taak niet doorschuiven'; end if;
  perform set_config('app.taak_rpc', '1', true);
  update public.taken set toegewezen_aan = p_aan, gezamenlijk = (p_aan is null),
         meewerkers = array_remove(meewerkers, p_aan)
   where id = p_taak;
  perform set_config('app.taak_rpc', '', true);
end $$;
grant execute on function public.taak_toewijzen(uuid, uuid, uuid) to authenticated;

-- iemand bij je taak halen (of weer weghalen)
create or replace function public.taak_meewerker(p_taak uuid, p_wie uuid, p_erbij boolean default true, p_ik uuid default null) returns void
language plpgsql security definer set search_path = '' as $$
declare t public.taken; ik uuid := coalesce(case when public.is_apparaat() then p_ik end, auth.uid()); wienaam text;
begin
  select * into t from public.taken where id = p_taak; if not found then raise exception 'Taak niet gevonden'; end if;
  if not public.mag_taak_schuiven(t, ik) then raise exception 'Je mag niemand bij deze taak zetten'; end if;
  perform set_config('app.taak_rpc', '1', true);
  update public.taken set meewerkers = case when p_erbij then array_append(array_remove(meewerkers, p_wie), p_wie) else array_remove(meewerkers, p_wie) end
   where id = p_taak;
  perform set_config('app.taak_rpc', '', true);
  if p_erbij and p_wie is distinct from auth.uid() then
    wienaam := coalesce((select naam from public.profielen where id = ik), 'Iemand');
    insert into public.meldingen (user_id, tekst, soort, taak_id, perceel_id)
    values (p_wie, wienaam || ' heeft je bij een taak gezet: ' || t.tekst, 'taak', t.id, t.perceel_id);
  end if;
end $$;
grant execute on function public.taak_meewerker(uuid, uuid, boolean, uuid) to authenticated;

-- =====================================================================================
-- ============ WAGENS VAN HET VELD: onderweg → legen → in de koelcel ============
-- =====================================================================================
-- De rooier meldt "wagen weg" (met de bijrijder). De bijrijder krijgt een melding, geeft aan dat hij aan het legen is,
-- en daarna staan de bakken in de koelcel-lijst (Verkoop en voorraad → Koelcel).
create table if not exists public.wagens_weg (
  id           uuid primary key,                                  -- zelfde als res_invoer.wagen_id
  taak_id      uuid references public.taken(id) on delete set null,
  perceel_id   uuid references public.percelen(id) on delete set null,
  bijrijder    text,                                              -- profiel-id, of ~Naam (zonder account)
  bijrijder_id uuid references public.profielen(id) on delete set null,
  wagen        text,                                              -- bijv. '14-bakker'
  bakken       numeric,
  inhoud       jsonb not null default '[]',                       -- [{"partij_id": "...", "naam": "Flair 260047", "bakken": 2}]
  tekst        text,
  status       text not null default 'onderweg' check (status in ('onderweg','legen','koelcel','uit')),
  gemeld_door  text,
  gemeld_op    timestamptz not null default now(),
  legen_op     timestamptz, legen_door text,
  koelcel_op   timestamptz, koelcel_door text,
  uit_op       timestamptz, uit_door text,
  seizoen_id   uuid references public.seizoenen(id) on delete set null
);
create or replace function public.wagen_seizoen() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.seizoen_id is null then new.seizoen_id := (select id from public.seizoenen where actief limit 1); end if;
  return new;
end $$;
drop trigger if exists wagen_seizoen on public.wagens_weg;
create trigger wagen_seizoen before insert on public.wagens_weg for each row execute function public.wagen_seizoen();
alter table public.wagens_weg enable row level security;
grant select, insert, update, delete on public.wagens_weg to authenticated;
drop policy if exists "lezen" on public.wagens_weg;      create policy "lezen" on public.wagens_weg for select to authenticated using (true);
drop policy if exists "melden" on public.wagens_weg;     create policy "melden" on public.wagens_weg for insert to authenticated
  with check (public.is_apparaat() or public.heeft_recht('taken_afvinken') or public.heeft_recht('resultaten_beheren'));
drop policy if exists "bijwerken" on public.wagens_weg;  create policy "bijwerken" on public.wagens_weg for update to authenticated
  using (bijrijder_id = auth.uid() or public.is_apparaat() or public.heeft_recht('taken_afvinken') or public.heeft_recht('resultaten_beheren') or public.heeft_recht('voorraad_beheren'))
  with check (true);
drop policy if exists "weghalen" on public.wagens_weg;   create policy "weghalen" on public.wagens_weg for delete to authenticated
  using (public.is_apparaat() or public.heeft_recht('taken_afvinken') or public.heeft_recht('resultaten_beheren'));

-- melding voor de bijrijder als zijn wagen weg is gemeld
create or replace function public.wagen_melding() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.bijrijder_id is not null and new.bijrijder_id is distinct from auth.uid() then
    insert into public.meldingen (user_id, tekst, soort, taak_id, perceel_id)
    values (new.bijrijder_id, '🚛 Je ' || coalesce(new.wagen, 'wagen') || ' is weg gemeld' || coalesce(': ' || new.tekst, '') ||
            '. Tik bij je taken op "Ik ben aan het legen" als je op het bedrijf bent.', 'taak', new.taak_id, new.perceel_id);
  end if;
  return new;
end $$;
drop trigger if exists wagen_melding on public.wagens_weg;
create trigger wagen_melding after insert on public.wagens_weg for each row execute function public.wagen_melding();
do $$ begin alter publication supabase_realtime add table public.wagens_weg; exception when duplicate_object then null; end $$;

-- =====================================================================================
-- ============ PLANTEN EN ZAAIEN: planning (ras eerst, batch later) + standaard spooropbouw ============
-- =====================================================================================
create table if not exists public.plantplanning (
  id          uuid primary key default gen_random_uuid(),
  perceel_id  uuid references public.percelen(id) on delete cascade,
  soort_id    uuid references public.soorten(id) on delete set null,
  ras_id      uuid references public.rassen(id) on delete set null,
  werk        text not null default 'planten' check (werk in ('planten','zaaien')),
  teeltwijze  text not null default 'opkweek' check (teeltwijze in ('opkweek','vermeerdering')),
  datum       date,
  vakken      text[] not null default '{}',          -- vakletters (leeg = hele perceel)
  rijen       text[] not null default '{}',          -- losse sporen 'zone:nr'
  sporen      jsonb,                                 -- uitgerekend: [{"z": zone-id, "nrs": [1,2,3]}], leeg = hele perceel
  aantal      numeric, eenheid text,
  notitie     text,
  status      text not null default 'gepland' check (status in ('gepland','geplant')),
  geplant_op  timestamptz, geplant_door text,
  partij_id   uuid references public.partijen(id) on delete set null,
  taak_id     uuid references public.taken(id) on delete set null,
  gemaakt_door text,
  created_at  timestamptz not null default now(),
  seizoen_id  uuid references public.seizoenen(id) on delete set null
);
create or replace function public.plantplan_seizoen() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.seizoen_id is null then new.seizoen_id := (select id from public.seizoenen where actief limit 1); end if;
  return new;
end $$;
drop trigger if exists plantplan_seizoen on public.plantplanning;
create trigger plantplan_seizoen before insert on public.plantplanning for each row execute function public.plantplan_seizoen();
alter table public.plantplanning enable row level security;
grant select, insert, update, delete on public.plantplanning to authenticated;
drop policy if exists "lezen" on public.plantplanning;   create policy "lezen" on public.plantplanning for select to authenticated using (true);
drop policy if exists "plannen" on public.plantplanning; create policy "plannen" on public.plantplanning for all to authenticated
  using (public.heeft_recht('taken_toevoegen') or public.heeft_recht('soorten_indelen'))
  with check (public.heeft_recht('taken_toevoegen') or public.heeft_recht('soorten_indelen'));
do $$ begin alter publication supabase_realtime add table public.plantplanning; exception when duplicate_object then null; end $$;

-- instellingen: standaard spooropbouw erbij (ook voor wie spuitsporen mag bewerken)
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken'))) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw') then raise exception 'Onbekende instelling'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;

-- planten en zaaien op de kaart: per gebied een eigen sporensysteem en hoeveel meter het moet worden
alter table public.plantplanning add column if not exists opbouw     jsonb;     -- {"naam","breedte","patroon","rijtjes","spuitRijtjes"} of null = zoals het veld
alter table public.plantplanning add column if not exists meters_doel numeric;  -- zoveel meter moet het worden (voor het opschuiven bij afronden)
alter table public.plantplanning add column if not exists gedaan     jsonb;     -- wat er bij het afronden echt is gedaan

-- =====================================================================================
-- ============ WIJZIGINGEN: alles wat iemand aanpast, met ongedaan maken ============
-- =====================================================================================
create table if not exists public.wijzigingen (
  id           bigserial primary key,
  tabel        text not null,
  rij_id       text not null,
  actie        text not null,                 -- insert / update / delete
  velden       text[],                        -- bij update: welke kolommen veranderden
  oud          jsonb,
  nieuw        jsonb,
  door         uuid default auth.uid(),
  door_naam    text,
  op           timestamptz not null default now(),
  herstel_van  bigint,                        -- deze regel is het ongedaan maken van een andere
  hersteld_op  timestamptz,
  hersteld_door text
);
create index if not exists wijzigingen_op on public.wijzigingen (op desc);
create index if not exists wijzigingen_door on public.wijzigingen (door, op desc);
alter table public.wijzigingen enable row level security;
grant select on public.wijzigingen to authenticated;
grant usage, select on sequence public.wijzigingen_id_seq to authenticated;
drop policy if exists "eigen of beheer" on public.wijzigingen;
create policy "eigen of beheer" on public.wijzigingen for select to authenticated
  using (door = auth.uid() or public.is_beheerder() or public.heeft_recht('historie_bekijken'));

create or replace function public.log_wijziging() returns trigger
language plpgsql security definer set search_path = '' as $$
declare o jsonb; n jsonb; v text[]; k text;
  stil constant text[] := array['updated_at','bezig_door','bezig_sinds','laatst_gezien','positie'];
begin
  if auth.uid() is null then return coalesce(new, old); end if;   -- systeem/cron: niet loggen
  if tg_op = 'UPDATE' then
    o := to_jsonb(old); n := to_jsonb(new);
    select array_agg(key) into v from jsonb_each(n) where key <> all(stil) and (o -> key) is distinct from value;
    if v is null then return new; end if;
    insert into public.wijzigingen (tabel, rij_id, actie, velden, oud, nieuw, door_naam, herstel_van)
    values (tg_table_name, new.id::text, 'update', v,
            (select jsonb_object_agg(x, o -> x) from unnest(v) x), (select jsonb_object_agg(x, n -> x) from unnest(v) x),
            (select naam from public.profielen where id = auth.uid()), nullif(current_setting('app.herstel_van', true), '')::bigint);
  elsif tg_op = 'INSERT' then
    insert into public.wijzigingen (tabel, rij_id, actie, nieuw, door_naam, herstel_van)
    values (tg_table_name, new.id::text, 'insert', to_jsonb(new), (select naam from public.profielen where id = auth.uid()), nullif(current_setting('app.herstel_van', true), '')::bigint);
  else
    insert into public.wijzigingen (tabel, rij_id, actie, oud, door_naam, herstel_van)
    values (tg_table_name, old.id::text, 'delete', to_jsonb(old), (select naam from public.profielen where id = auth.uid()), nullif(current_setting('app.herstel_van', true), '')::bigint);
  end if;
  if random() < 0.01 then delete from public.wijzigingen where op < now() - interval '120 days'; end if;
  return coalesce(new, old);
end $$;

do $$ declare t text; begin
  foreach t in array array['percelen','partijen','taken','plantplanning','rooiplanning','markeringen','soorten','rassen','wagens_weg','res_invoer'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop trigger if exists log_wijziging on public.%I', t);
      execute format('create trigger log_wijziging after insert or update or delete on public.%I for each row execute function public.log_wijziging()', t);
    end if;
  end loop;
end $$;

-- ongedaan maken: eigen wijzigingen altijd, die van anderen alleen als beheerder
create or replace function public.herstel_wijziging(p_id bigint) returns text
language plpgsql security definer set search_path = '' as $$
declare w public.wijzigingen; cols text; later int;
begin
  select * into w from public.wijzigingen where id = p_id; if not found then raise exception 'Niet gevonden'; end if;
  if w.hersteld_op is not null then raise exception 'Dit is al ongedaan gemaakt'; end if;
  if w.door is distinct from auth.uid() and not public.is_beheerder() then raise exception 'Alleen de beheerder kan wijzigingen van anderen ongedaan maken'; end if;
  if w.tabel not in ('percelen','partijen','taken','plantplanning','rooiplanning','markeringen','soorten','rassen','wagens_weg','res_invoer','teeltplanning') then raise exception 'Kan niet'; end if;
  perform set_config('app.taak_rpc', '1', true);
  perform set_config('app.herstel_van', p_id::text, true);
  if w.actie = 'insert' then
    execute format('delete from public.%I where id::text = $1', w.tabel) using w.rij_id;
  elsif w.actie = 'delete' then
    execute format('insert into public.%I select * from jsonb_populate_record(null::public.%I, $1) on conflict (id) do nothing', w.tabel, w.tabel) using w.oud;
  else
    select string_agg(format('%I', c), ', ') into cols from unnest(w.velden) c;
    execute format('update public.%I t set (%s) = (select %s from jsonb_populate_record(null::public.%I, $1)) where t.id::text = $2',
                   w.tabel, cols, cols, w.tabel) using w.oud, w.rij_id;
  end if;
  update public.wijzigingen set hersteld_op = now(), hersteld_door = (select naam from public.profielen where id = auth.uid()) where id = p_id;
  -- is er daarna nog iets aan dezelfde velden veranderd? dan even melden
  select count(*) into later from public.wijzigingen x where x.tabel = w.tabel and x.rij_id = w.rij_id and x.id > w.id and x.herstel_van is null and x.actie = 'update' and x.velden && coalesce(w.velden, '{}');
  perform set_config('app.herstel_van', '', true); perform set_config('app.taak_rpc', '', true);
  return case when later > 0 then 'later' else 'ok' end;
end $$;
grant execute on function public.herstel_wijziging(bigint) to authenticated;
do $$ begin alter publication supabase_realtime add table public.wijzigingen; exception when duplicate_object then null; end $$;

-- plannen met meerdere rassen achter elkaar: precies welk stuk van welk spoor, in welke volgorde
alter table public.plantplanning add column if not exists delen   jsonb;     -- [{"z": zone, "nr": 5, "van": 0, "tot": 20}] (meters vanaf het begin van het spoor)
alter table public.plantplanning add column if not exists volgorde int;
alter table public.plantplanning add column if not exists groep   text;      -- plannen die in één keer zijn gemaakt

-- =====================================================================================
-- ============ TEELTPLANNING: van verwachte verkoop naar ha veld, moederplanten, kas en PBM-bestelling ============
-- =====================================================================================
-- per seizoen per ras één regel met alles (verkoop, opkweek, planten van derden, kengetallen); ras_id leeg = de standaard kengetallen
create table if not exists public.teeltplanning (
  id         uuid primary key default gen_random_uuid(),
  seizoen_id uuid references public.seizoenen(id) on delete cascade,
  ras_id     uuid references public.rassen(id) on delete cascade,
  data       jsonb not null default '{}',
  bijgewerkt timestamptz not null default now(),
  door       text
);
create unique index if not exists teeltplanning_uniek on public.teeltplanning (coalesce(seizoen_id, '00000000-0000-0000-0000-000000000000'::uuid), coalesce(ras_id, '00000000-0000-0000-0000-000000000000'::uuid));
alter table public.teeltplanning enable row level security;
grant select, insert, update, delete on public.teeltplanning to authenticated;
drop policy if exists "lezen" on public.teeltplanning;    create policy "lezen" on public.teeltplanning for select to authenticated using (true);
drop policy if exists "plannen" on public.teeltplanning;  create policy "plannen" on public.teeltplanning for all to authenticated
  using (public.is_beheerder() or public.heeft_recht('taken_toevoegen') or public.heeft_recht('resultaten_beheren'))
  with check (public.is_beheerder() or public.heeft_recht('taken_toevoegen') or public.heeft_recht('resultaten_beheren'));
do $$ begin
  if to_regclass('public.teeltplanning') is not null then
    drop trigger if exists log_wijziging on public.teeltplanning;
    create trigger log_wijziging after insert or update or delete on public.teeltplanning for each row execute function public.log_wijziging();
  end if;
end $$;

-- ============ PRIVACY: prikklok en ziekmeldingen afschermen ============
-- iPads/trekkertablets (apparaat-accounts) zien geen urenhistorie en geen ziekmeldingen.
-- Prikklok: van vandaag ziet iedereen wie er binnen is (nodig voor het kantinescherm en "ingeklokt?"),
-- oudere dagen alleen je eigen regels, of met het recht "uren van iedereen bekijken" / beheerder.
drop policy if exists "lezen" on public.klok;
create policy "lezen" on public.klok for select to authenticated using (
  user_id = auth.uid() or binnen >= current_date
  or (not public.is_apparaat() and (public.is_beheerder() or public.heeft_recht('uren_bekijken'))));
-- Ziekmeldingen: je eigen, en verder alleen beheerder en planners (taken toevoegen / uren bekijken), nooit op een apparaat
drop policy if exists "lezen" on public.ziek;
create policy "lezen" on public.ziek for select to authenticated using (
  user_id = auth.uid()
  or (not public.is_apparaat() and (public.is_beheerder() or public.heeft_recht('taken_toevoegen') or public.heeft_recht('uren_bekijken'))));
-- Logboek en historie: nooit op een apparaat (daar staan namen, ziek- en klokmeldingen in)
drop policy if exists "lezen" on public.gebeurtenissen;
create policy "lezen" on public.gebeurtenissen for select to authenticated using (
  user_id = auth.uid() or (not public.is_apparaat() and public.heeft_recht('historie_bekijken')));
drop policy if exists "eigen of beheer" on public.wijzigingen;
create policy "eigen of beheer" on public.wijzigingen for select to authenticated using (
  door = auth.uid() or (not public.is_apparaat() and (public.is_beheerder() or public.heeft_recht('historie_bekijken'))));

-- ============ VOORRAAD: BESTEMMINGEN (eigen gebruik, orders) ============
-- Een bestemming is een "bak" waar je planten uit de koelcel naartoe sleept: eigen gebruik, een order van een klant enz.
-- Reserveren haalt nog niets uit de koelcel; pas bij "geleverd" wordt er een levering (partij_mutaties 'uit') geboekt.
create table if not exists public.voorraad_bestemmingen (
  id uuid primary key default gen_random_uuid(),
  seizoen_id uuid references public.seizoenen(id) on delete set null,
  naam text not null,
  soort text not null default 'order' check (soort in ('eigen','order','overig')),
  klant text, ordernr text, leverdatum date, notitie text,
  klaar boolean not null default false,
  volgorde int not null default 0,
  door text, created_at timestamptz not null default now()
);
create table if not exists public.voorraad_reserveringen (
  id uuid primary key default gen_random_uuid(),
  bestemming_id uuid not null references public.voorraad_bestemmingen(id) on delete cascade,
  partij_id uuid not null references public.partijen(id) on delete cascade,
  koelcel text,
  planten numeric not null check (planten > 0),
  door text, created_at timestamptz not null default now()
);
create index if not exists voorraad_res_partij on public.voorraad_reserveringen (partij_id);
alter table public.voorraad_bestemmingen enable row level security;
alter table public.voorraad_reserveringen enable row level security;
grant select, insert, update, delete on public.voorraad_bestemmingen, public.voorraad_reserveringen to authenticated;
drop policy if exists "lezen" on public.voorraad_bestemmingen;
create policy "lezen" on public.voorraad_bestemmingen for select to authenticated using (not public.is_apparaat() and (public.heeft_recht('voorraad_bekijken') or public.heeft_recht('voorraad_beheren') or public.heeft_recht('taken_toevoegen')));
drop policy if exists "schrijven" on public.voorraad_bestemmingen;
create policy "schrijven" on public.voorraad_bestemmingen for all to authenticated using (public.heeft_recht('voorraad_beheren')) with check (public.heeft_recht('voorraad_beheren'));
drop policy if exists "lezen" on public.voorraad_reserveringen;
create policy "lezen" on public.voorraad_reserveringen for select to authenticated using (not public.is_apparaat() and (public.heeft_recht('voorraad_bekijken') or public.heeft_recht('voorraad_beheren') or public.heeft_recht('taken_toevoegen')));
drop policy if exists "schrijven" on public.voorraad_reserveringen;
create policy "schrijven" on public.voorraad_reserveringen for all to authenticated using (public.heeft_recht('voorraad_beheren')) with check (public.heeft_recht('voorraad_beheren'));
do $$ begin
  if to_regprocedure('public.log_wijziging()') is not null then
    drop trigger if exists log_wijziging on public.voorraad_bestemmingen;
    create trigger log_wijziging after insert or update or delete on public.voorraad_bestemmingen for each row execute function public.log_wijziging();
    drop trigger if exists log_wijziging on public.voorraad_reserveringen;
    create trigger log_wijziging after insert or update or delete on public.voorraad_reserveringen for each row execute function public.log_wijziging();
  end if;
end $$;

-- ============ TEELTJAAR EN SEIZOENEN PER PERCEEL ============
-- Teeltjaar = het bedrijfsjaar (verkoop, voorraad, uren, taken). Het begint elk jaar vanzelf op de ingestelde dag (instelling teeltjaar_start = 'MM-DD').
-- Seizoen per perceel = wat er op dat perceel geteeld wordt (bijv. "Aardbei voorjaar 2026"). Meerdere per jaar kan; bij een nieuw seizoen
-- wordt wat er stond bewaard (archief) en is het perceel weer leeg, behalve de sporen, kopeinden, spuitsporen en deelvelden.
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel = 'koelcellen' and public.heeft_recht('voorraad_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;

-- wordt bij het openen van de app aangeroepen: is de startdag voorbij, dan begint het nieuwe teeltjaar (zonder iets leeg te maken)
create or replace function public.teeltjaar_automatisch() returns text
language plpgsql security definer set search_path = '' as $$
declare s text; m int; d int; start date; oud public.seizoenen; nieuw uuid; naam text;
begin
  select waarde into s from public.instellingen where sleutel = 'teeltjaar_start';
  if s is null or s !~ '^\d{2}-\d{2}$' then return null; end if;
  m := split_part(s, '-', 1)::int; d := least(split_part(s, '-', 2)::int, 28 + (case when m = 2 then 0 else 2 end));
  start := make_date(extract(year from current_date)::int, m, d);
  if start > current_date then start := make_date(extract(year from current_date)::int - 1, m, d); end if;
  perform pg_advisory_xact_lock(424242);
  select * into oud from public.seizoenen where actief;
  if oud.id is not null and oud.gestart::date >= start then return null; end if;
  naam := case when m = 1 and d = 1 then extract(year from start)::text else extract(year from start)::text || '-' || (extract(year from start)::int + 1)::text end;
  perform set_config('perceel.systeem', '1', true);
  if oud.id is not null then
    insert into public.seizoen_percelen (seizoen_id, perceel_id, gegevens)
    select oud.id, p.id, to_jsonb(p) from public.percelen p
    on conflict (seizoen_id, perceel_id) do update set gegevens = excluded.gegevens;
    update public.seizoenen set actief = false where id = oud.id;
  end if;
  insert into public.seizoenen (naam, actief, gestart, gestart_door) values (naam, true, start::timestamptz, 'automatisch') returning id into nieuw;
  if oud.id is not null then update public.taken set seizoen_id = nieuw where seizoen_id = oud.id and not klaar; end if;
  return naam;
end $$;
revoke all on function public.teeltjaar_automatisch() from public, anon;
grant execute on function public.teeltjaar_automatisch() to authenticated;

create table if not exists public.perceel_seizoenen (
  id uuid primary key default gen_random_uuid(),
  perceel_id uuid not null references public.percelen(id) on delete cascade,
  naam text not null,
  soort_id uuid references public.soorten(id) on delete set null,
  van date not null default current_date,
  tot date,                                    -- leeg = loopt nog
  seizoen_id uuid references public.seizoenen(id) on delete set null,   -- teeltjaar waarin het begon
  gegevens jsonb, partijen jsonb, plantplanning jsonb, rooiplanning jsonb,   -- bewaard bij het afsluiten
  notitie text, gestart_door text, afgesloten_door text,
  created_at timestamptz not null default now()
);
create unique index if not exists perceel_seizoen_een_open on public.perceel_seizoenen (perceel_id) where tot is null;
alter table public.perceel_seizoenen enable row level security;
grant select, update on public.perceel_seizoenen to authenticated;
drop policy if exists "lezen" on public.perceel_seizoenen;
create policy "lezen" on public.perceel_seizoenen for select to authenticated using (true);
drop policy if exists "wijzigen" on public.perceel_seizoenen;
create policy "wijzigen" on public.perceel_seizoenen for update to authenticated
  using (public.heeft_recht('seizoen_starten') or public.heeft_recht('percelen_bewerken')) with check (public.heeft_recht('seizoen_starten') or public.heeft_recht('percelen_bewerken'));
alter table public.partijen add column if not exists afgesloten_in uuid references public.perceel_seizoenen(id) on delete set null;
alter table public.plantplanning add column if not exists afgesloten_in uuid references public.perceel_seizoenen(id) on delete set null;
alter table public.rooiplanning add column if not exists afgesloten_in uuid references public.perceel_seizoenen(id) on delete set null;
do $$ begin
  begin alter publication supabase_realtime add table public.perceel_seizoenen; exception when others then null; end;
  if to_regprocedure('public.log_wijziging()') is not null then
    drop trigger if exists log_wijziging on public.perceel_seizoenen;
    create trigger log_wijziging after insert or update or delete on public.perceel_seizoenen for each row execute function public.log_wijziging();
  end if;
end $$;

-- nieuw seizoen op een perceel: het lopende (of wat er stond) bewaren en het perceel leegmaken; daarna het nieuwe seizoen openen
create or replace function public.perceel_seizoen_starten(p_perceel uuid, p_naam text, p_soort uuid default null, p_van date default current_date,
  p_oud_naam text default null, p_leegmaken boolean default true)
returns uuid language plpgsql security definer set search_path = '' as $$
declare oud public.perceel_seizoenen; nieuw uuid; wie text; p public.percelen; heeft boolean;
begin
  if not (public.heeft_recht('seizoen_starten') or public.heeft_recht('percelen_bewerken')) then raise exception 'Je mag geen nieuw seizoen starten op een perceel'; end if;
  if public.is_apparaat() then raise exception 'Dat kan niet op een tablet'; end if;
  if coalesce(trim(p_naam), '') = '' then raise exception 'Geef het seizoen een naam'; end if;
  select * into p from public.percelen where id = p_perceel; if p.id is null then raise exception 'Perceel niet gevonden'; end if;
  wie := (select naam from public.profielen where id = auth.uid());
  perform set_config('perceel.systeem', '1', true); perform set_config('app.taak_rpc', '1', true);
  select * into oud from public.perceel_seizoenen where perceel_id = p_perceel and tot is null for update;
  heeft := jsonb_path_exists(coalesce(p.banen, '[]'::jsonb), '$[*] ? (@ != null)') or exists (select 1 from public.partijen where perceel_id = p_perceel and afgesloten_in is null)
    or exists (select 1 from public.plantplanning where perceel_id = p_perceel and afgesloten_in is null);
  -- stond er al iets zonder seizoen? dan dat als (naamloos) seizoen bewaren
  if oud.id is null and heeft and p_leegmaken then
    insert into public.perceel_seizoenen (perceel_id, naam, van, seizoen_id, gestart_door)
    values (p_perceel, coalesce(nullif(trim(p_oud_naam), ''), 'Tot ' || to_char(p_van, 'DD-MM-YYYY')), coalesce((select min(created_at)::date from public.partijen where perceel_id = p_perceel and afgesloten_in is null), p_van),
      (select id from public.seizoenen where actief), wie) returning * into oud;
  end if;
  if oud.id is not null then
    if p_leegmaken then
      update public.perceel_seizoenen set tot = greatest(van, p_van), afgesloten_door = wie,
        naam = coalesce(nullif(trim(p_oud_naam), ''), naam),
        gegevens = to_jsonb(p),
        partijen = (select coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb) from public.partijen x where x.perceel_id = p_perceel and x.afgesloten_in is null),
        plantplanning = (select coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb) from public.plantplanning x where x.perceel_id = p_perceel and x.afgesloten_in is null),
        rooiplanning = (select coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb) from public.rooiplanning x where x.perceel_id = p_perceel and x.afgesloten_in is null)
      where id = oud.id;
      update public.partijen set afgesloten_in = oud.id, sporen = '[]'::jsonb, perceel_id = null where perceel_id = p_perceel and afgesloten_in is null;
      update public.plantplanning set afgesloten_in = oud.id where perceel_id = p_perceel and afgesloten_in is null;
      update public.rooiplanning set afgesloten_in = oud.id where perceel_id = p_perceel and afgesloten_in is null;
      update public.percelen set banen = '[]'::jsonb, gewas = null, beplanting = '{}'::jsonb,
        vakken = (select coalesce(jsonb_agg((v - 'gewas') || '{"banen":[]}'::jsonb), '[]'::jsonb) from jsonb_array_elements(coalesce(vakken, '[]'::jsonb)) v)
      where id = p_perceel;
    else
      update public.perceel_seizoenen set tot = greatest(van, p_van), afgesloten_door = wie, naam = coalesce(nullif(trim(p_oud_naam), ''), naam), gegevens = to_jsonb(p) where id = oud.id;
    end if;
  end if;
  insert into public.perceel_seizoenen (perceel_id, naam, soort_id, van, seizoen_id, gestart_door)
  values (p_perceel, trim(p_naam), p_soort, p_van, (select id from public.seizoenen where actief), wie) returning id into nieuw;
  perform public.gebeurtenis('seizoen', '🌱 Nieuw seizoen op ' || p.naam || ': ' || trim(p_naam), nieuw);
  return nieuw;
end $$;
revoke all on function public.perceel_seizoen_starten(uuid, text, uuid, date, text, boolean) from public, anon;
grant execute on function public.perceel_seizoen_starten(uuid, text, uuid, date, text, boolean) to authenticated;

-- ============ KOELCEL: PALLETS ============
-- kistjes staan op pallets (tot 64 hoog); op één pallet kunnen meerdere partijen/rassen staan
alter table public.partij_mutaties add column if not exists pallet text;
create index if not exists partij_mutaties_pallet on public.partij_mutaties (pallet) where pallet is not null;

-- ============ EIGEN MENU ============
-- iedereen kan zijn eigen hoofdmenu indelen: titels, icoontjes, volgorde en welke tegel onder welk kopje
alter table public.profielen add column if not exists menu jsonb;
create or replace function public.zet_mijn_menu(p_menu jsonb) returns void
language sql security definer set search_path = '' as $$
  update public.profielen set menu = case when p_menu is null or p_menu = '{}'::jsonb then null else p_menu end where id = auth.uid();
$$;
revoke all on function public.zet_mijn_menu(jsonb) from public, anon;
grant execute on function public.zet_mijn_menu(jsonb) to authenticated;

-- ============ EIGEN TREKKERKASTJE (ESP32) ============
-- Het kastje stuurt elke paar seconden een pakketje punten: positie, snelheid, en uit de CAN-bus (J1939) toerental,
-- motoruren, brandstof, aftakas en hefinrichting. Welke machine erachter hangt ziet hij aan het Bluetooth-baken.
alter table public.tractoren add column if not exists toeren numeric;
alter table public.tractoren add column if not exists motoruren numeric;
alter table public.tractoren add column if not exists brandstof_lh numeric;
alter table public.tractoren add column if not exists brandstof_pct numeric;
alter table public.tractoren add column if not exists aftakas numeric;
alter table public.tractoren add column if not exists hef numeric;
alter table public.tractoren add column if not exists koelvloeistof numeric;
alter table public.tractoren add column if not exists werktuig_id uuid references public.machines(id) on delete set null;
alter table public.tractoren add column if not exists kastje_gezien timestamptz;
alter table public.tractoren add column if not exists kastje_info jsonb;
alter table public.tractor_posities add column if not exists toeren numeric;
alter table public.tractor_posities add column if not exists aftakas numeric;
alter table public.tractor_posities add column if not exists hef numeric;
alter table public.tractor_posities add column if not exists werktuig_id uuid;
alter table public.machines add column if not exists baken text;   -- Bluetooth-id van het baken op de machine (bijv. PA-PLOEG of het MAC-adres)

create or replace function public.meld_kastje(p_sleutel uuid, p_punten jsonb, p_info jsonb default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare tid uuid; p jsonb; n int := 0; laatst jsonb; wt uuid; bakens text[]; t timestamptz;
begin
  select tractor_id into tid from public.tractor_sleutels where sleutel = p_sleutel;
  if tid is null then raise exception 'Onbekende sleutel'; end if;
  if jsonb_typeof(p_punten) <> 'array' or jsonb_array_length(p_punten) > 500 then raise exception 'Verkeerd pakket'; end if;
  for p in select * from jsonb_array_elements(p_punten) order by coalesce((value->>'t')::bigint, 0) loop
    if (p->>'lat') is null or (p->>'lng') is null or abs((p->>'lat')::float) > 90 or abs((p->>'lng')::float) > 180 then continue; end if;
    t := case when (p->>'t') is not null and (p->>'t')::bigint > 1600000000 then to_timestamp((p->>'t')::bigint) else now() end;
    if t > now() + interval '5 minutes' then t := now(); end if;
    -- werktuig: het eerste baken dat bij een machine hoort
    wt := null;
    if jsonb_typeof(p->'b') = 'array' then
      select array_agg(value) into bakens from jsonb_array_elements_text(p->'b');
      select id into wt from public.machines where baken is not null and lower(baken) = any (select lower(x) from unnest(bakens) x) limit 1;
    end if;
    insert into public.tractor_posities (tractor_id, lat, lng, richting, snelheid, tijd, toeren, aftakas, hef, werktuig_id)
    values (tid, (p->>'lat')::float, (p->>'lng')::float, (p->>'r')::numeric, (p->>'v')::numeric, t, (p->>'rpm')::numeric, (p->>'pto')::numeric, (p->>'hef')::numeric, wt);
    n := n + 1; laatst := coalesce(laatst, '{}'::jsonb) || jsonb_strip_nulls(p) || jsonb_build_object('_t', t, '_wt', wt);   -- ontbrekende waarden uit eerdere punten
  end loop;
  if laatst is not null then
    update public.tractoren set lat = (laatst->>'lat')::float, lng = (laatst->>'lng')::float, richting = (laatst->>'r')::numeric, snelheid = (laatst->>'v')::numeric,
      nauwkeurigheid = (laatst->>'acc')::numeric, bijgewerkt = greatest(coalesce(bijgewerkt, '-infinity'), (laatst->>'_t')::timestamptz),
      toeren = (laatst->>'rpm')::numeric, aftakas = (laatst->>'pto')::numeric, hef = (laatst->>'hef')::numeric,
      brandstof_lh = coalesce((laatst->>'lh')::numeric, brandstof_lh), brandstof_pct = coalesce((laatst->>'tank')::numeric, brandstof_pct),
      koelvloeistof = coalesce((laatst->>'temp')::numeric, koelvloeistof), motoruren = coalesce((laatst->>'uren')::numeric, motoruren),
      werktuig_id = (laatst->>'_wt')::uuid, kastje_gezien = now(), kastje_info = coalesce(p_info, kastje_info)
    where id = tid;
    -- motoruren ook bij de trekker in Machines (voor het onderhoud)
    if (laatst->>'uren') is not null then
      update public.machines set draaiuren = round((laatst->>'uren')::numeric, 1)
      where tractor_id = tid and (soort ~* 'trekker|tractor|zelfrijdend') and coalesce(draaiuren, 0) <= (laatst->>'uren')::numeric;
    end if;
  else
    update public.tractoren set kastje_gezien = now(), kastje_info = coalesce(p_info, kastje_info) where id = tid;
  end if;
  if random() < 0.01 then delete from public.tractor_posities where tijd < now() - interval '30 days'; end if;
  return jsonb_build_object('ok', n);
end $$;
revoke all on function public.meld_kastje(uuid, jsonb, jsonb) from public;
grant execute on function public.meld_kastje(uuid, jsonb, jsonb) to anon, authenticated;

-- =====================================================================
-- ETIKETTEN: pallet- en boxkaarten met QR-code (november 2026)
-- Elk afgedrukt etiket krijgt een eigen nummer (P17 = pallet 17, B230 = box 230).
-- Scannen opent het etiket in de app: inslaan, verplaatsen, leveren en terugzoeken.
-- =====================================================================
create table if not exists public.etiketten (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique,                 -- P17 / B230 (staat in de QR-code)
  soort       text not null check (soort in ('pallet','box')),
  nr          integer not null,                     -- palletnummer of boxnummer
  partij_id   uuid references public.partijen(id) on delete set null,
  seizoen_id  uuid references public.seizoenen(id) on delete set null,
  data        jsonb not null default '{}',          -- wat er op het etiket staat (ras, sortering, klasse, batch, perceel, datum, bio …)
  door        text,
  created_at  timestamptz not null default now()
);
create index if not exists etiketten_soort_nr on public.etiketten (soort, nr desc);
create index if not exists etiketten_partij on public.etiketten (partij_id);
alter table public.etiketten enable row level security;
grant select, insert, update, delete on public.etiketten to authenticated;
drop policy if exists "lezen" on public.etiketten;
drop policy if exists "maken" on public.etiketten;
drop policy if exists "wijzigen" on public.etiketten;
drop policy if exists "verwijderen" on public.etiketten;
create policy "lezen"       on public.etiketten for select to authenticated
  using (public.heeft_recht('voorraad_bekijken') or public.heeft_recht('voorraad_beheren') or public.heeft_recht('etiketten_printen'));
create policy "maken"       on public.etiketten for insert to authenticated
  with check (public.heeft_recht('voorraad_beheren') or public.heeft_recht('etiketten_printen'));
create policy "wijzigen"    on public.etiketten for update to authenticated
  using (public.heeft_recht('voorraad_beheren')) with check (public.heeft_recht('voorraad_beheren'));
create policy "verwijderen" on public.etiketten for delete to authenticated using (public.heeft_recht('voorraad_beheren'));
do $$ begin alter publication supabase_realtime add table public.etiketten; exception when duplicate_object then null; end $$;

-- instellingen voor de etiketten (lijsten, kleuren per ras, SKAL, adres) en het logo
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel in ('koelcellen', 'etiket', 'etiket_logo') and public.heeft_recht('voorraad_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen', 'etiket', 'etiket_logo') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  if p_sleutel = 'etiket_logo' and length(coalesce(p_waarde, '')) > 400000 then raise exception 'Het logo is te groot'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;

-- =====================================================================
-- BESTELLEN: iedereen kan iets aanvragen, iemand met het recht keurt het goed of af,
-- daarna: besteld → binnen. De aanvrager en de goedkeurders krijgen een melding.
-- =====================================================================
-- mag deze gebruiker iets aanvragen? Standaard ja (behalve gedeelde apparaten zoals een trekkertablet)
create or replace function public.mag_bestellen() returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profielen where id = auth.uid()
                   and (rol = 'beheerder' or coalesce((rechten->>'bestellen')::boolean, not coalesce(apparaat, false))));
$$;
grant execute on function public.mag_bestellen() to authenticated;

create table if not exists public.bestellingen (
  id               uuid primary key default gen_random_uuid(),
  wat              text not null,
  aantal           numeric,
  eenheid          text,
  categorie        text,
  toelichting      text,                         -- waarvoor is het nodig
  nodig_op         date,
  spoed            boolean not null default false,
  leverancier      text,
  link             text,
  prijs            numeric,                      -- geschatte prijs per stuk (excl. btw)
  machine_id       uuid references public.machines(id) on delete set null,
  perceel_id       uuid references public.percelen(id) on delete set null,
  fotos            jsonb not null default '[]',
  status           text not null default 'aangevraagd' check (status in ('aangevraagd','goedgekeurd','afgekeurd','besteld','binnen','geannuleerd')),
  aangevraagd_door uuid default auth.uid() references auth.users(id) on delete set null,
  aanvrager        text,                         -- naam (ook als iemand op een gedeeld apparaat werkt)
  beoordeeld_door  text,
  beoordeeld_op    timestamptz,
  reden            text,                         -- waarom afgekeurd / opmerking bij goedkeuren
  besteld_door     text,
  besteld_op       timestamptz,
  bestelnummer     text,
  verwacht_op      date,
  binnen_door      text,
  binnen_op        timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists bestellingen_status on public.bestellingen (status, created_at desc);
create index if not exists bestellingen_door on public.bestellingen (aangevraagd_door);
alter table public.bestellingen enable row level security;
grant select, insert, update, delete on public.bestellingen to authenticated;
drop policy if exists "lezen" on public.bestellingen;
drop policy if exists "aanvragen" on public.bestellingen;
drop policy if exists "eigen aanpassen" on public.bestellingen;
drop policy if exists "eigen weg" on public.bestellingen;
-- iedereen die mag bestellen ziet alle aanvragen (dan zie je ook wat er al is aangevraagd)
create policy "lezen" on public.bestellingen for select to authenticated
  using (aangevraagd_door = auth.uid() or public.mag_bestellen() or public.heeft_recht('bestellingen_goedkeuren'));
create policy "aanvragen" on public.bestellingen for insert to authenticated
  with check (public.mag_bestellen() and aangevraagd_door = auth.uid() and status = 'aangevraagd'
              and beoordeeld_door is null and besteld_door is null and binnen_door is null);
-- je eigen aanvraag aanpassen kan zolang hij nog niet beoordeeld is; de status verandert alleen via bestelling_status()
create policy "eigen aanpassen" on public.bestellingen for update to authenticated
  using (aangevraagd_door = auth.uid() and status = 'aangevraagd')
  with check (aangevraagd_door = auth.uid() and status = 'aangevraagd' and beoordeeld_door is null and besteld_door is null and binnen_door is null);
create policy "eigen weg" on public.bestellingen for delete to authenticated
  using ((aangevraagd_door = auth.uid() and status in ('aangevraagd','geannuleerd')) or public.is_beheerder());
do $$ begin alter publication supabase_realtime add table public.bestellingen; exception when duplicate_object then null; end $$;

create or replace function public.bestelling_bijgewerkt() returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;
-- de naam van de aanvrager zet de database zelf (alleen op een gedeeld apparaat geldt de gekozen chauffeur)
create or replace function public.bestelling_nieuw() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_apparaat() or nullif(trim(coalesce(new.aanvrager, '')), '') is null then
    new.aanvrager := coalesce((select naam from public.profielen where id = auth.uid()), new.aanvrager);
  end if;
  return new;
end $$;
drop trigger if exists bestelling_nieuw on public.bestellingen;
create trigger bestelling_nieuw before insert on public.bestellingen for each row execute function public.bestelling_nieuw();
drop trigger if exists bestelling_bijgewerkt on public.bestellingen;
create trigger bestelling_bijgewerkt before update on public.bestellingen for each row execute function public.bestelling_bijgewerkt();

-- nieuwe aanvraag → melding voor iedereen die mag goedkeuren (behalve de aanvrager zelf)
create or replace function public.bestelling_melding() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.meldingen (user_id, tekst, soort)
  select p.id, case when new.spoed then '🔥 SPOED · ' else '' end || '🛒 ' || coalesce(new.aanvrager, 'Iemand') || ' vraagt: '
               || coalesce(trim(to_char(new.aantal, 'FM999999990.##')) || ' ' || coalesce(new.eenheid, '') || ' ', '') || new.wat || ' · wacht op goedkeuring', 'bestelling'
    from public.profielen p
   where p.id is distinct from new.aangevraagd_door
     and coalesce(p.apparaat, false) = false
     and (p.rol = 'beheerder' or coalesce((p.rechten->>'bestellingen_goedkeuren')::boolean, false));
  return new;
end $$;
drop trigger if exists bestelling_melding on public.bestellingen;
create trigger bestelling_melding after insert on public.bestellingen for each row execute function public.bestelling_melding();

-- status wijzigen: goedkeuren / afkeuren (goedkeurders), besteld (goedkeurders), binnen (goedkeurders of de aanvrager), annuleren (aanvrager)
create or replace function public.bestelling_status(p_id uuid, p_status text, p_reden text default null, p_extra jsonb default '{}'::jsonb, p_naam text default null)
returns public.bestellingen language plpgsql security definer set search_path = '' as $$
declare b public.bestellingen; keur boolean := public.heeft_recht('bestellingen_goedkeuren');
        wie text := coalesce(case when public.is_apparaat() then nullif(trim(p_naam), '') end, (select naam from public.profielen where id = auth.uid()), 'Iemand');
        eigen boolean; tekst text;
begin
  select * into b from public.bestellingen where id = p_id for update; if not found then raise exception 'Bestelling niet gevonden'; end if;
  eigen := b.aangevraagd_door = auth.uid();
  if p_status in ('goedgekeurd', 'afgekeurd') then
    if not keur then raise exception 'Je mag geen bestellingen goedkeuren'; end if;
    if eigen and not public.is_beheerder() then raise exception 'Je kunt je eigen aanvraag niet goedkeuren; dat moet iemand anders doen'; end if;
    if b.status not in ('aangevraagd', 'goedgekeurd', 'afgekeurd') then raise exception 'Deze bestelling is al besteld of afgerond'; end if;
    if p_status = 'afgekeurd' and nullif(trim(coalesce(p_reden, '')), '') is null then raise exception 'Geef een reden waarom je afkeurt'; end if;
    update public.bestellingen set status = p_status, beoordeeld_door = wie, beoordeeld_op = now(), reden = nullif(trim(coalesce(p_reden, '')), '') where id = p_id returning * into b;
  elsif p_status = 'besteld' then
    if not keur then raise exception 'Alleen wie bestellingen goedkeurt kan ze als besteld zetten'; end if;
    if b.status not in ('goedgekeurd', 'besteld') then raise exception 'Keur de aanvraag eerst goed'; end if;
    update public.bestellingen set status = 'besteld', besteld_door = wie, besteld_op = coalesce(b.besteld_op, now()),
           leverancier = coalesce(nullif(p_extra->>'leverancier', ''), b.leverancier), bestelnummer = coalesce(nullif(p_extra->>'bestelnummer', ''), b.bestelnummer),
           verwacht_op = coalesce(nullif(p_extra->>'verwacht_op', '')::date, b.verwacht_op), prijs = coalesce(nullif(p_extra->>'prijs', '')::numeric, b.prijs)
     where id = p_id returning * into b;
  elsif p_status = 'binnen' then
    if not (keur or eigen) then raise exception 'Alleen de aanvrager of een goedkeurder kan dit als binnen melden'; end if;
    if b.status not in ('goedgekeurd', 'besteld') then raise exception 'Deze bestelling is nog niet goedgekeurd'; end if;
    update public.bestellingen set status = 'binnen', binnen_door = wie, binnen_op = now() where id = p_id returning * into b;
  elsif p_status = 'geannuleerd' then
    if not (eigen or public.is_beheerder()) then raise exception 'Alleen de aanvrager kan zijn aanvraag intrekken'; end if;
    if b.status not in ('aangevraagd', 'goedgekeurd') then raise exception 'Deze bestelling is al besteld; overleg even met wie hem besteld heeft'; end if;
    update public.bestellingen set status = 'geannuleerd', reden = coalesce(nullif(trim(coalesce(p_reden, '')), ''), b.reden) where id = p_id returning * into b;
  else raise exception 'Onbekende status %', p_status; end if;
  -- melding naar de aanvrager (niet als hij het zelf deed)
  if b.aangevraagd_door is not null and not eigen then
    tekst := case p_status when 'goedgekeurd' then '✅ ' || wie || ' heeft je aanvraag goedgekeurd: ' || b.wat
                           when 'afgekeurd'   then '❌ ' || wie || ' heeft je aanvraag afgekeurd: ' || b.wat || coalesce(' · ' || b.reden, '')
                           when 'besteld'     then '📦 Besteld: ' || b.wat || coalesce(' · verwacht ' || to_char(b.verwacht_op, 'DD-MM'), '')
                           when 'binnen'      then '📥 Binnen: ' || b.wat end;
    if tekst is not null then insert into public.meldingen (user_id, tekst, soort) values (b.aangevraagd_door, tekst, 'bestelling'); end if;
  end if;
  perform public.gebeurtenis('bestelling', 'Bestelling "' || b.wat || '" → ' || p_status);
  return b;
end $$;
grant execute on function public.bestelling_status(uuid, text, text, jsonb, text) to authenticated;

-- foto's bij een aanvraag (bijv. van het kapotte onderdeel)
drop policy if exists "fotos toevoegen"   on storage.objects;
drop policy if exists "fotos verwijderen" on storage.objects;
create policy "fotos toevoegen"   on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                       or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                       or public.heeft_recht('machines_beheren') or public.heeft_recht('tractor_rijden') or public.heeft_recht('percelen_bewerken')
                                       or public.heeft_recht('plattegrond_beheren') or public.mag_bestellen()));
create policy "fotos verwijderen" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (public.heeft_recht('markeringen_maken') or public.heeft_recht('gerooid_aangeven') or public.heeft_recht('taken_toevoegen')
                                  or public.heeft_recht('taken_afvinken') or public.heeft_recht('werk_registreren') or public.heeft_recht('oogst_registreren')
                                  or public.heeft_recht('machines_beheren') or public.heeft_recht('percelen_bewerken') or public.heeft_recht('plattegrond_beheren')
                                  or public.mag_bestellen()));

-- bestellen: de goedkeurder kan zelf de link toevoegen waar het besteld wordt (plus artikelnummer),
-- zodat de bestellijst per winkel gegroepeerd kan worden en in één keer besteld
alter table public.bestellingen add column if not exists bestel_link text;
alter table public.bestellingen add column if not exists artikelnummer text;
create or replace function public.bestelling_info(p_id uuid, p_info jsonb)
returns public.bestellingen language plpgsql security definer set search_path = '' as $$
declare b public.bestellingen;
begin
  if not public.heeft_recht('bestellingen_goedkeuren') then raise exception 'Alleen wie bestellingen goedkeurt kan dit aanpassen'; end if;
  select * into b from public.bestellingen where id = p_id for update; if not found then raise exception 'Bestelling niet gevonden'; end if;
  if b.status not in ('aangevraagd', 'goedgekeurd', 'besteld') then raise exception 'Deze bestelling is al afgerond'; end if;
  update public.bestellingen set
    bestel_link   = case when p_info ? 'bestel_link'   then nullif(trim(p_info->>'bestel_link'), '')   else bestel_link end,
    artikelnummer = case when p_info ? 'artikelnummer' then nullif(trim(p_info->>'artikelnummer'), '') else artikelnummer end,
    leverancier   = case when p_info ? 'leverancier'   then nullif(trim(p_info->>'leverancier'), '')   else leverancier end,
    aantal        = case when p_info ? 'aantal'        then nullif(p_info->>'aantal', '')::numeric      else aantal end,
    prijs         = case when p_info ? 'prijs'         then nullif(p_info->>'prijs', '')::numeric       else prijs end
  where id = p_id returning * into b;
  return b;
end $$;
grant execute on function public.bestelling_info(uuid, jsonb) to authenticated;

-- bestellen: vaste artikellijst. Wie iets nodig heeft tikt een artikel aan (link, winkel en prijs zitten er al bij)
-- of vraagt iets nieuws aan; de goedkeurder voegt dan de website toe en bewaart het als artikel voor de volgende keer.
create table if not exists public.bestel_artikelen (
  id            uuid primary key default gen_random_uuid(),
  naam          text not null,
  categorie     text,
  eenheid       text,
  omschrijving  text,
  link          text,          -- waar het besteld wordt
  winkel        text,
  artikelnummer text,
  prijs         numeric,
  actief        boolean not null default true,
  door          text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists bestel_artikelen_naam on public.bestel_artikelen (lower(naam));
alter table public.bestel_artikelen enable row level security;
grant select, insert, update, delete on public.bestel_artikelen to authenticated;
drop policy if exists "lezen" on public.bestel_artikelen;
drop policy if exists "beheren" on public.bestel_artikelen;
create policy "lezen"   on public.bestel_artikelen for select to authenticated using (public.mag_bestellen() or public.heeft_recht('bestellingen_goedkeuren'));
create policy "beheren" on public.bestel_artikelen for all to authenticated
  using (public.heeft_recht('bestellingen_goedkeuren')) with check (public.heeft_recht('bestellingen_goedkeuren'));
do $$ begin alter publication supabase_realtime add table public.bestel_artikelen; exception when duplicate_object then null; end $$;
drop trigger if exists bestel_artikel_bijgewerkt on public.bestel_artikelen;
create trigger bestel_artikel_bijgewerkt before update on public.bestel_artikelen for each row execute function public.bestelling_bijgewerkt();

alter table public.bestellingen add column if not exists artikel_id uuid references public.bestel_artikelen(id) on delete set null;

-- bij een nieuwe aanvraag van een artikel uit de lijst: link, winkel, artikelnummer en prijs komen uit de lijst
create or replace function public.bestelling_nieuw() returns trigger language plpgsql security definer set search_path = '' as $$
declare a public.bestel_artikelen;
begin
  if not public.is_apparaat() or nullif(trim(coalesce(new.aanvrager, '')), '') is null then
    new.aanvrager := coalesce((select naam from public.profielen where id = auth.uid()), new.aanvrager);
  end if;
  if new.artikel_id is not null then
    select * into a from public.bestel_artikelen where id = new.artikel_id;
    if found then
      new.wat := coalesce(nullif(trim(new.wat), ''), a.naam);
      new.bestel_link := a.link; new.artikelnummer := a.artikelnummer;
      new.leverancier := coalesce(a.winkel, new.leverancier); new.prijs := coalesce(a.prijs, new.prijs);
      new.categorie := coalesce(a.categorie, new.categorie); new.eenheid := coalesce(nullif(new.eenheid, ''), a.eenheid);
    end if;
  end if;
  return new;
end $$;

-- link toevoegen door de goedkeurder; met "opslaan" komt hij ook in de artikellijst (of wordt dat artikel bijgewerkt)
create or replace function public.bestelling_info(p_id uuid, p_info jsonb)
returns public.bestellingen language plpgsql security definer set search_path = '' as $$
declare b public.bestellingen; nieuw uuid;
begin
  if not public.heeft_recht('bestellingen_goedkeuren') then raise exception 'Alleen wie bestellingen goedkeurt kan dit aanpassen'; end if;
  select * into b from public.bestellingen where id = p_id for update; if not found then raise exception 'Bestelling niet gevonden'; end if;
  if b.status not in ('aangevraagd', 'goedgekeurd', 'besteld') then raise exception 'Deze bestelling is al afgerond'; end if;
  update public.bestellingen set
    bestel_link   = case when p_info ? 'bestel_link'   then nullif(trim(p_info->>'bestel_link'), '')   else bestel_link end,
    artikelnummer = case when p_info ? 'artikelnummer' then nullif(trim(p_info->>'artikelnummer'), '') else artikelnummer end,
    leverancier   = case when p_info ? 'leverancier'   then nullif(trim(p_info->>'leverancier'), '')   else leverancier end,
    aantal        = case when p_info ? 'aantal'        then nullif(p_info->>'aantal', '')::numeric      else aantal end,
    prijs         = case when p_info ? 'prijs'         then nullif(p_info->>'prijs', '')::numeric       else prijs end
  where id = p_id returning * into b;
  if coalesce((p_info->>'opslaan')::boolean, false) then
    if b.artikel_id is null then
      insert into public.bestel_artikelen (naam, categorie, eenheid, link, winkel, artikelnummer, prijs, door)
      values (coalesce(nullif(trim(p_info->>'naam'), ''), b.wat), b.categorie, b.eenheid, b.bestel_link, b.leverancier, b.artikelnummer, b.prijs,
              (select naam from public.profielen where id = auth.uid()))
      returning id into nieuw;
      update public.bestellingen set artikel_id = nieuw where id = p_id returning * into b;
    else
      update public.bestel_artikelen set link = b.bestel_link, winkel = b.leverancier, artikelnummer = b.artikelnummer, prijs = b.prijs where id = b.artikel_id;
    end if;
  end if;
  return b;
end $$;

-- =====================================================================
-- P&O-DASHBOARD (overgenomen uit "Dashboard - P&O - Algemeen.xlsx")
-- Uren en geproduceerde eenheden komen uit SSOR (Firebird) via een klein
-- sync-programma op de server (ssor-sync.ps1); budget, toelichting en
-- personeelskosten vul je in de app in (of lees je in uit Excel).
-- Alleen zichtbaar met het recht "pno_bekijken", nooit op gedeelde apparaten.
-- =====================================================================
create or replace function public.mag_pno() returns boolean language sql stable security definer set search_path = '' as $$
  select not public.is_apparaat() and public.heeft_recht('pno_bekijken');
$$;
create or replace function public.mag_pno_beheren() returns boolean language sql stable security definer set search_path = '' as $$
  select not public.is_apparaat() and public.heeft_recht('pno_beheren');
$$;
grant execute on function public.mag_pno() to authenticated;
grant execute on function public.mag_pno_beheren() to authenticated;

-- boekjaar De Kemp loopt van 1 oktober t/m 30 september
create or replace function public.pno_boekjaar(d date) returns text language sql immutable as $$
  select case when extract(month from d) >= 10 then extract(year from d)::int || '-' || (extract(year from d)::int + 1)
              else (extract(year from d)::int - 1) || '-' || extract(year from d)::int end;
$$;
-- maand in het boekjaar: 1 = oktober … 12 = september
create or replace function public.pno_bjmaand(d date) returns smallint language sql immutable as $$
  select (((extract(month from d)::int + 2) % 12) + 1)::smallint;
$$;
-- "Week De Kemp": 01/40 … 01/52, 02/01 … 02/39 (01 = eerste kalenderjaar van het boekjaar)
create or replace function public.pno_week(d date) returns text language sql immutable as $$
  select case when extract(isoyear from d)::int = (case when extract(month from d) >= 10 then extract(year from d)::int else extract(year from d)::int - 1 end)
              then '01' else '02' end || '/' || lpad(extract(week from d)::int::text, 2, '0');
$$;

-- stamgegevens uit SSOR (alleen wat nodig is: geen adressen, BSN, IBAN e.d.)
create table if not exists public.ssor_activiteitgroepen (id bigint primary key, nummer text, naam text, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_activiteiten (id bigint primary key, nummer text, naam text, groep_id bigint, norm numeric, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_kostenplaatsen (id bigint primary key, nummer text, naam text, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_locaties (id bigint primary key, nummer text, naam text, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_medewerkers (id bigint primary key, nummer text, naam text, actief boolean, contracttype text, bijgewerkt timestamptz not null default now());
-- uren (SSOR-tabel HOURS) en geproduceerde eenheden (SSOR-tabel UNIT)
create table if not exists public.ssor_uren (
  id bigint primary key, datum date not null, uren numeric not null default 0,
  activiteit_id bigint, kostenplaats_id bigint, dagtaak_id bigint, medewerker_id bigint, locatie_id bigint, sublocatie_id bigint,
  boekjaar text generated always as (public.pno_boekjaar(datum)) stored,
  bjmaand smallint generated always as (public.pno_bjmaand(datum)) stored,
  week text generated always as (public.pno_week(datum)) stored);
create table if not exists public.ssor_eenheden (
  id bigint primary key, datum date not null, tijd text, aantal numeric not null default 0,
  activiteit_id bigint, kostenplaats_id bigint, dagtaak_id bigint, medewerker_id bigint, locatie_id bigint, sublocatie_id bigint, sortering_id bigint,
  boekjaar text generated always as (public.pno_boekjaar(datum)) stored,
  bjmaand smallint generated always as (public.pno_bjmaand(datum)) stored,
  week text generated always as (public.pno_week(datum)) stored);
create index if not exists ssor_uren_bj on public.ssor_uren (boekjaar, week);
create index if not exists ssor_uren_datum on public.ssor_uren (datum);
create index if not exists ssor_uren_act on public.ssor_uren (activiteit_id);
create index if not exists ssor_uren_mw on public.ssor_uren (medewerker_id);
create index if not exists ssor_eenh_bj on public.ssor_eenheden (boekjaar, week);
create index if not exists ssor_eenh_datum on public.ssor_eenheden (datum);

-- zelf bij te houden (stond in losse Excel-bestanden en in de budgetbladen)
create table if not exists public.pno_medewerkersgroepen (contract text primary key, werknemergroep text, tarief numeric);
create table if not exists public.pno_budget (
  boekjaar text not null, activiteit_nr text not null, bjmaand smallint not null check (bjmaand between 1 and 12), uren numeric not null default 0,
  naam text, groep text, primary key (boekjaar, activiteit_nr, bjmaand));
create table if not exists public.pno_toelichting (
  boekjaar text not null, activiteit_nr text not null, tekst text, budget_eenheden numeric, door text, bijgewerkt timestamptz not null default now(),
  primary key (boekjaar, activiteit_nr));
create table if not exists public.pno_kosten (
  id uuid primary key default gen_random_uuid(), boekjaar text not null, soort text not null check (soort in ('budget', 'werkelijk')),
  regel text not null, volgorde int not null default 0, bedragen numeric[] not null default array_fill(0::numeric, array[12]));
create table if not exists public.pno_tarieven (
  boekjaar text primary key, uurtarief numeric[] not null default array_fill(22.5::numeric, array[12]),
  derden numeric[] not null default array_fill(25.8::numeric, array[12]), analyse_tarief numeric not null default 20);
-- koppeling met SSOR: één geheime sleutel voor het sync-programma
create table if not exists public.ssor_koppeling (id int primary key default 1 check (id = 1), sleutel uuid, laatst timestamptz, info jsonb not null default '{}');

do $$ declare t text; begin
  foreach t in array array['ssor_activiteitgroepen','ssor_activiteiten','ssor_kostenplaatsen','ssor_locaties','ssor_medewerkers','ssor_uren','ssor_eenheden',
                           'pno_medewerkersgroepen','pno_budget','pno_toelichting','pno_kosten','pno_tarieven','ssor_koppeling'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('drop policy if exists "lezen" on public.%I', t);
    execute format('drop policy if exists "beheren" on public.%I', t);
  end loop;
  -- SSOR-gegevens: alleen lezen (schrijven gaat via ssor_sync)
  foreach t in array array['ssor_activiteitgroepen','ssor_activiteiten','ssor_kostenplaatsen','ssor_locaties','ssor_medewerkers','ssor_uren','ssor_eenheden'] loop
    execute format('create policy "lezen" on public.%I for select to authenticated using ((select public.mag_pno()))', t);
  end loop;
  foreach t in array array['pno_medewerkersgroepen','pno_budget','pno_toelichting','pno_kosten','pno_tarieven'] loop
    execute format('create policy "lezen" on public.%I for select to authenticated using ((select public.mag_pno()))', t);
    execute format('create policy "beheren" on public.%I for all to authenticated using ((select public.mag_pno_beheren())) with check ((select public.mag_pno_beheren()))', t);
  end loop;
  create policy "lezen" on public.ssor_koppeling for select to authenticated using ((select public.is_beheerder()));
  create policy "beheren" on public.ssor_koppeling for all to authenticated using ((select public.is_beheerder())) with check ((select public.is_beheerder()));
end $$;

-- ---------- ontvangen vanuit het sync-programma (met de geheime sleutel) ----------
create or replace function public.ssor_sync(p_sleutel uuid, p_tabel text, p_rijen jsonb, p_van date default null, p_tot date default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare n int := 0; ja text[] := array['1', 't', 'true', 'y', 'j'];
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  if jsonb_typeof(p_rijen) <> 'array' then raise exception 'p_rijen moet een lijst zijn'; end if;
  if p_tabel = 'activiteitgroepen' then
    insert into public.ssor_activiteitgroepen (id, nummer, naam) select x.id::bigint, x.nummer, x.naam from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'activiteiten' then
    insert into public.ssor_activiteiten (id, nummer, naam, groep_id, norm) select x.id::bigint, x.nummer, x.naam, nullif(x.groep_id, '')::bigint, nullif(replace(x.norm, ',', '.'), '')::numeric
      from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text, groep_id text, norm text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, groep_id = excluded.groep_id, norm = excluded.norm, bijgewerkt = now();
  elsif p_tabel = 'kostenplaatsen' then
    insert into public.ssor_kostenplaatsen (id, nummer, naam) select x.id::bigint, x.nummer, x.naam from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'locaties' then
    insert into public.ssor_locaties (id, nummer, naam) select x.id::bigint, x.nummer, x.naam from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'medewerkers' then
    insert into public.ssor_medewerkers (id, nummer, naam, actief, contracttype)
      select x.id::bigint, x.nummer, nullif(trim(regexp_replace(x.naam, '\s+', ' ', 'g')), ''), lower(coalesce(x.actief, '')) = any(ja), nullif(trim(x.contracttype), '')
      from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text, actief text, contracttype text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, actief = excluded.actief, contracttype = excluded.contracttype, bijgewerkt = now();
  elsif p_tabel = 'uren' then
    insert into public.ssor_uren (id, datum, uren, activiteit_id, kostenplaats_id, dagtaak_id, medewerker_id, locatie_id, sublocatie_id)
      select x.id::bigint, left(x.datum, 10)::date, coalesce(nullif(replace(x.uren, ',', '.'), '')::numeric, 0), nullif(x.activiteit_id, '')::bigint, nullif(x.kostenplaats_id, '')::bigint,
             nullif(x.dagtaak_id, '')::bigint, nullif(x.medewerker_id, '')::bigint, nullif(x.locatie_id, '')::bigint, nullif(x.sublocatie_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(id text, datum text, uren text, activiteit_id text, kostenplaats_id text, dagtaak_id text, medewerker_id text, locatie_id text, sublocatie_id text)
      where nullif(x.datum, '') is not null
    on conflict (id) do update set datum = excluded.datum, uren = excluded.uren, activiteit_id = excluded.activiteit_id, kostenplaats_id = excluded.kostenplaats_id,
      dagtaak_id = excluded.dagtaak_id, medewerker_id = excluded.medewerker_id, locatie_id = excluded.locatie_id, sublocatie_id = excluded.sublocatie_id;
  elsif p_tabel = 'eenheden' then
    insert into public.ssor_eenheden (id, datum, tijd, aantal, activiteit_id, kostenplaats_id, dagtaak_id, medewerker_id, locatie_id, sublocatie_id, sortering_id)
      select x.id::bigint, left(x.datum, 10)::date, nullif(x.tijd, ''), coalesce(nullif(replace(x.aantal, ',', '.'), '')::numeric, 0), nullif(x.activiteit_id, '')::bigint,
             nullif(x.kostenplaats_id, '')::bigint, nullif(x.dagtaak_id, '')::bigint, nullif(x.medewerker_id, '')::bigint, nullif(x.locatie_id, '')::bigint,
             nullif(x.sublocatie_id, '')::bigint, nullif(x.sortering_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(id text, datum text, tijd text, aantal text, activiteit_id text, kostenplaats_id text, dagtaak_id text, medewerker_id text, locatie_id text, sublocatie_id text, sortering_id text)
      where nullif(x.datum, '') is not null
    on conflict (id) do update set datum = excluded.datum, tijd = excluded.tijd, aantal = excluded.aantal, activiteit_id = excluded.activiteit_id, kostenplaats_id = excluded.kostenplaats_id,
      dagtaak_id = excluded.dagtaak_id, medewerker_id = excluded.medewerker_id, locatie_id = excluded.locatie_id, sublocatie_id = excluded.sublocatie_id, sortering_id = excluded.sortering_id;
  -- opruimen: alles in de periode p_van..p_tot dat niet (meer) in SSOR staat weghalen (p_rijen = lijst met alle id's in die periode)
  elsif p_tabel in ('uren_opruimen', 'eenheden_opruimen') then
    if p_van is null or p_tot is null then raise exception 'Geef p_van en p_tot op'; end if;
    if p_tabel = 'uren_opruimen' then
      delete from public.ssor_uren u where u.datum between p_van and p_tot and not exists (select 1 from jsonb_array_elements_text(p_rijen) e where e::bigint = u.id);
    else
      delete from public.ssor_eenheden u where u.datum between p_van and p_tot and not exists (select 1 from jsonb_array_elements_text(p_rijen) e where e::bigint = u.id);
    end if;
  else raise exception 'Onbekende tabel %', p_tabel; end if;
  get diagnostics n = row_count;
  update public.ssor_koppeling set laatst = now(), info = info || jsonb_build_object(p_tabel, jsonb_build_object('tijd', now(), 'rijen', n)) where id = 1;
  return jsonb_build_object('tabel', p_tabel, 'rijen', n);
end $$;
revoke all on function public.ssor_sync(uuid, text, jsonb, date, date) from public;
grant execute on function public.ssor_sync(uuid, text, jsonb, date, date) to anon, authenticated;

-- beheerder: nieuwe sleutel maken (de oude werkt dan niet meer) en de status bekijken
create or replace function public.ssor_nieuwe_sleutel() returns uuid language plpgsql security definer set search_path = '' as $$
declare s uuid := gen_random_uuid();
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder kan de SSOR-koppeling instellen'; end if;
  insert into public.ssor_koppeling (id, sleutel) values (1, s) on conflict (id) do update set sleutel = excluded.sleutel;
  return s;
end $$;
grant execute on function public.ssor_nieuwe_sleutel() to authenticated;
create or replace function public.ssor_status() returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  if not (public.mag_pno() or public.is_beheerder()) then raise exception 'Geen toegang'; end if;
  return jsonb_build_object(
    'ingesteld', exists (select 1 from public.ssor_koppeling where id = 1 and sleutel is not null),
    'laatst', (select laatst from public.ssor_koppeling where id = 1), 'info', coalesce((select info from public.ssor_koppeling where id = 1), '{}'),
    'uren', (select count(*) from public.ssor_uren), 'uren_van', (select min(datum) from public.ssor_uren), 'uren_tot', (select max(datum) from public.ssor_uren),
    'eenheden', (select count(*) from public.ssor_eenheden), 'eenheden_tot', (select max(datum) from public.ssor_eenheden),
    'activiteiten', (select count(*) from public.ssor_activiteiten), 'medewerkers', (select count(*) from public.ssor_medewerkers),
    'kostenplaatsen', (select count(*) from public.ssor_kostenplaatsen), 'locaties', (select count(*) from public.ssor_locaties),
    'boekjaren', coalesce((select jsonb_agg(b order by b) from (select distinct boekjaar b from public.ssor_uren) x), '[]'));
end $$;
grant execute on function public.ssor_status() to authenticated;

-- ---------- rekenen (in de database, zodat de telefoon geen 100.000-en regels hoeft te laden) ----------
create or replace function public.pno_f_txt(p jsonb, k text) returns text[] language sql immutable as $$
  select case when p ? k and jsonb_typeof(p->k) = 'array' and jsonb_array_length(p->k) > 0 then array(select jsonb_array_elements_text(p->k)) end;
$$;
create or replace function public.pno_f_int(p jsonb, k text) returns bigint[] language sql immutable as $$
  select case when p ? k and jsonb_typeof(p->k) = 'array' and jsonb_array_length(p->k) > 0 then array(select jsonb_array_elements_text(p->k)::bigint) end;
$$;
-- alle filters (net als de slicers in Excel): boekjaar, periode, week, datum van/tot, groep, activiteit, werknemer, kostenplaats, locatie, werknemergroep
create or replace function public.pno_uren_f(p jsonb)
returns table (datum date, boekjaar text, bjmaand smallint, week text, uren numeric, activiteit_id bigint, groep_id bigint, kostenplaats_id bigint, medewerker_id bigint, locatie_id bigint)
language plpgsql stable security definer set search_path = '' as $$
declare
  f_bj text[] := public.pno_f_txt(p, 'boekjaar'); f_per bigint[] := public.pno_f_int(p, 'periode'); f_wk bigint[] := public.pno_f_int(p, 'week');
  f_gr bigint[] := public.pno_f_int(p, 'groep'); f_act bigint[] := public.pno_f_int(p, 'activiteit'); f_mw bigint[] := public.pno_f_int(p, 'medewerker');
  f_kp bigint[] := public.pno_f_int(p, 'kostenplaats'); f_loc bigint[] := public.pno_f_int(p, 'locatie'); f_wg text[] := public.pno_f_txt(p, 'werknemergroep');
  f_van date := nullif(p->>'van', '')::date; f_tot date := nullif(p->>'tot', '')::date;
begin
  if not public.mag_pno() then return; end if;
  return query
  select u.datum, u.boekjaar, u.bjmaand, u.week, u.uren, u.activiteit_id, a.groep_id, u.kostenplaats_id, u.medewerker_id, u.locatie_id
    from public.ssor_uren u
    left join public.ssor_activiteiten a on a.id = u.activiteit_id
    left join public.ssor_medewerkers m on f_wg is not null and m.id = u.medewerker_id
    left join public.pno_medewerkersgroepen g on f_wg is not null and g.contract = m.contracttype
   where (f_bj is null or u.boekjaar = any(f_bj))
     and (f_per is null or u.bjmaand = any(f_per))
     and (f_wk is null or extract(week from u.datum)::bigint = any(f_wk))
     and (f_gr is null or a.groep_id = any(f_gr))
     and (f_act is null or u.activiteit_id = any(f_act))
     and (f_mw is null or u.medewerker_id = any(f_mw))
     and (f_kp is null or u.kostenplaats_id = any(f_kp))
     and (f_loc is null or u.locatie_id = any(f_loc))
     and (f_wg is null or coalesce(g.werknemergroep, '(geen groep)') = any(f_wg))
     and (f_van is null or u.datum >= f_van)
     and (f_tot is null or u.datum <= f_tot);
end $$;
create or replace function public.pno_eenheden_f(p jsonb)
returns table (datum date, boekjaar text, bjmaand smallint, week text, aantal numeric, activiteit_id bigint, groep_id bigint, kostenplaats_id bigint, medewerker_id bigint, locatie_id bigint)
language plpgsql stable security definer set search_path = '' as $$
declare
  f_bj text[] := public.pno_f_txt(p, 'boekjaar'); f_per bigint[] := public.pno_f_int(p, 'periode'); f_wk bigint[] := public.pno_f_int(p, 'week');
  f_gr bigint[] := public.pno_f_int(p, 'groep'); f_act bigint[] := public.pno_f_int(p, 'activiteit'); f_mw bigint[] := public.pno_f_int(p, 'medewerker');
  f_kp bigint[] := public.pno_f_int(p, 'kostenplaats'); f_loc bigint[] := public.pno_f_int(p, 'locatie'); f_wg text[] := public.pno_f_txt(p, 'werknemergroep');
  f_van date := nullif(p->>'van', '')::date; f_tot date := nullif(p->>'tot', '')::date;
begin
  if not public.mag_pno() then return; end if;
  return query
  select u.datum, u.boekjaar, u.bjmaand, u.week, u.aantal, u.activiteit_id, a.groep_id, u.kostenplaats_id, u.medewerker_id, u.locatie_id
    from public.ssor_eenheden u
    left join public.ssor_activiteiten a on a.id = u.activiteit_id
    left join public.ssor_medewerkers m on f_wg is not null and m.id = u.medewerker_id
    left join public.pno_medewerkersgroepen g on f_wg is not null and g.contract = m.contracttype
   where (f_bj is null or u.boekjaar = any(f_bj))
     and (f_per is null or u.bjmaand = any(f_per))
     and (f_wk is null or extract(week from u.datum)::bigint = any(f_wk))
     and (f_gr is null or a.groep_id = any(f_gr))
     and (f_act is null or u.activiteit_id = any(f_act))
     and (f_mw is null or u.medewerker_id = any(f_mw))
     and (f_kp is null or u.kostenplaats_id = any(f_kp))
     and (f_loc is null or u.locatie_id = any(f_loc))
     and (f_wg is null or coalesce(g.werknemergroep, '(geen groep)') = any(f_wg))
     and (f_van is null or u.datum >= f_van)
     and (f_tot is null or u.datum <= f_tot);
end $$;
revoke all on function public.pno_uren_f(jsonb) from public, anon;
revoke all on function public.pno_eenheden_f(jsonb) from public, anon;
grant execute on function public.pno_uren_f(jsonb) to authenticated;
grant execute on function public.pno_eenheden_f(jsonb) to authenticated;

-- Dashboard 1: uren per week/boekjaar, per groep, top 15's, kostenplaats × maand, en dit boekjaar t/m vandaag tegenover vorig jaar
create or replace function public.pno_dashboard(p jsonb) returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb; bj text := public.pno_boekjaar(current_date); start date; p2 jsonb; nu numeric; vorig numeric;
begin
  if not public.mag_pno() then raise exception 'Geen toegang tot de P&O-gegevens'; end if;
  with f as materialized (select * from public.pno_uren_f(coalesce(p, '{}')))
  select jsonb_build_object(
    'totaal', (select coalesce(round(sum(uren), 2), 0) from f),
    'medewerkers', (select count(distinct medewerker_id) from f),
    'dagen', (select count(distinct datum) from f),
    'boekjaar', (select coalesce(jsonb_object_agg(boekjaar, s), '{}') from (select boekjaar, round(sum(uren), 2) s from f group by 1) x),
    'week', (select coalesce(jsonb_agg(jsonb_build_array(boekjaar, week, s) order by boekjaar, week), '[]') from (select boekjaar, week, round(sum(uren), 2) s from f group by 1, 2) x),
    'groep', (select coalesce(jsonb_agg(jsonb_build_array(groep_id, s) order by s desc), '[]') from (select groep_id, round(sum(uren), 2) s from f group by 1) x),
    'activiteit', (select coalesce(jsonb_agg(jsonb_build_array(activiteit_id, s) order by s desc), '[]') from (select activiteit_id, round(sum(uren), 2) s from f group by 1 order by 2 desc limit 15) x),
    'medewerker', (select coalesce(jsonb_agg(jsonb_build_array(medewerker_id, s) order by s desc), '[]') from (select medewerker_id, round(sum(uren), 2) s from f group by 1 order by 2 desc limit 15) x),
    'kostenplaats', (select coalesce(jsonb_agg(jsonb_build_array(kostenplaats_id, s) order by s desc), '[]') from (select kostenplaats_id, round(sum(uren), 2) s from f group by 1 order by 2 desc limit 15) x),
    'locatie', (select coalesce(jsonb_agg(jsonb_build_array(locatie_id, s) order by s desc), '[]') from (select locatie_id, round(sum(uren), 2) s from f group by 1 order by 2 desc limit 15) x),
    'kp_maand', (select coalesce(jsonb_agg(jsonb_build_array(kostenplaats_id, bjmaand, s)), '[]') from (select kostenplaats_id, bjmaand, round(sum(uren), 2) s from f group by 1, 2) x)
  ) into r;
  -- dit boekjaar t/m vandaag tegenover dezelfde periode vorig boekjaar (zelfde filters, behalve de datumfilters)
  start := make_date(case when extract(month from current_date) >= 10 then extract(year from current_date)::int else extract(year from current_date)::int - 1 end, 10, 1);
  p2 := coalesce(p, '{}') - 'boekjaar' - 'periode' - 'week' - 'van' - 'tot';
  select coalesce(sum(uren), 0) into nu from public.pno_uren_f(p2 || jsonb_build_object('van', start, 'tot', current_date));
  select coalesce(sum(uren), 0) into vorig from public.pno_uren_f(p2 || jsonb_build_object('van', (start - interval '1 year')::date, 'tot', (current_date - interval '1 year')::date));
  return r || jsonb_build_object('fytd', jsonb_build_object('boekjaar', bj, 'tot', current_date, 'nu', round(nu, 2), 'vorig', round(vorig, 2)));
end $$;
grant execute on function public.pno_dashboard(jsonb) to authenticated;

-- Dashboard 2: eenheden en uren per week (en per activiteit) voor eenheden per uur
create or replace function public.pno_productie(p jsonb) returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.mag_pno() then raise exception 'Geen toegang tot de P&O-gegevens'; end if;
  return jsonb_build_object(
    'eenheden', (select coalesce(jsonb_agg(jsonb_build_array(boekjaar, week, s) order by boekjaar, week), '[]') from (select boekjaar, week, sum(aantal) s from public.pno_eenheden_f(coalesce(p, '{}')) group by 1, 2) x),
    'uren', (select coalesce(jsonb_agg(jsonb_build_array(boekjaar, week, s) order by boekjaar, week), '[]') from (select boekjaar, week, round(sum(uren), 2) s from public.pno_uren_f(coalesce(p, '{}')) group by 1, 2) x),
    'activiteit', (select coalesce(jsonb_agg(jsonb_build_array(activiteit_id, e, u)), '[]') from (
        select coalesce(e.activiteit_id, u.activiteit_id) activiteit_id, coalesce(e.s, 0) e, coalesce(u.s, 0) u
          from (select activiteit_id, sum(aantal) s from public.pno_eenheden_f(coalesce(p, '{}')) group by 1) e
          full join (select activiteit_id, round(sum(uren), 2) s from public.pno_uren_f(coalesce(p, '{}')) group by 1) u on u.activiteit_id = e.activiteit_id
         where coalesce(e.s, 0) > 0) x));
end $$;
grant execute on function public.pno_productie(jsonb) to authenticated;

-- Dashboard 5 / budget: uren per groep › activiteit (› werknemer) per kolom (maand, kostenplaats, boekjaar of week)
create or replace function public.pno_tabel(p jsonb, p_kolom text default 'maand', p_medewerker boolean default true) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.mag_pno() then raise exception 'Geen toegang tot de P&O-gegevens'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_array(groep_id, activiteit_id, mw, kol, s)), '[]') from (
    select groep_id, activiteit_id, case when p_medewerker then medewerker_id end mw,
           case p_kolom when 'kostenplaats' then coalesce(kostenplaats_id::text, '') when 'boekjaar' then boekjaar when 'week' then boekjaar || '|' || week
                        when 'locatie' then coalesce(locatie_id::text, '') else boekjaar || '|' || bjmaand end kol,
           round(sum(uren), 2) s
      from public.pno_uren_f(coalesce(p, '{}')) group by 1, 2, 3, 4) x);
end $$;
grant execute on function public.pno_tabel(jsonb, text, boolean) to authenticated;

-- =====================================================================
--  ONDERGROND (bodemkaart + hoogte per perceel) en BEREGENING / WATERBALANS
-- =====================================================================
-- grondsoort en hoogte uit PDOK (BRO Bodemkaart en AHN), per perceel opgeslagen
alter table public.percelen add column if not exists ondergrond jsonb;
create or replace function public.perceel_ondergrond(p_id uuid, p_data jsonb) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then raise exception 'Niet ingelogd'; end if;
  update public.percelen set ondergrond = p_data where id = p_id;
end $$;
revoke all on function public.perceel_ondergrond(uuid, jsonb) from public, anon;
grant execute on function public.perceel_ondergrond(uuid, jsonb) to authenticated;

-- beregening: wat er gegeven is (mm) en hoeveel water er onttrokken is (m³, voor het waterschap)
create table if not exists public.beregening (
  id          uuid primary key default gen_random_uuid(),
  perceel_id  uuid references public.percelen(id) on delete set null,
  perceel_naam text,
  datum       date not null default current_date,
  mm          numeric check (mm is null or mm >= 0),
  m3          numeric check (m3 is null or m3 >= 0),
  uren        numeric check (uren is null or uren >= 0),
  bron        text not null default 'grondwater' check (bron in ('grondwater','oppervlaktewater','leiding','overig')),
  doel        text not null default 'beregenen' check (doel in ('beregenen','vorst','spuiten','overig')),
  notitie     text,
  door        text,
  door_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);
create index if not exists beregening_datum on public.beregening (datum);
create index if not exists beregening_perceel on public.beregening (perceel_id, datum);
alter table public.beregening enable row level security;
grant select, insert, update, delete on public.beregening to authenticated;
drop policy if exists "lezen" on public.beregening;
drop policy if exists "toevoegen" on public.beregening;
drop policy if exists "aanpassen" on public.beregening;
drop policy if exists "verwijderen" on public.beregening;
create policy "lezen"       on public.beregening for select to authenticated using (true);
create policy "toevoegen"   on public.beregening for insert to authenticated with check (public.heeft_recht('beregening_invoeren') or public.heeft_recht('monsters_beheren'));
create policy "aanpassen"   on public.beregening for update to authenticated using (public.heeft_recht('monsters_beheren') or door_id = auth.uid()) with check (true);
create policy "verwijderen" on public.beregening for delete to authenticated using (public.heeft_recht('monsters_beheren') or door_id = auth.uid());
do $$ begin alter publication supabase_realtime add table public.beregening; exception when duplicate_object then null; end $$;
-- standaard mag iedereen beregening invoeren
update public.profielen set rechten = '{"beregening_invoeren":true}'::jsonb || coalesce(rechten, '{}') where not (coalesce(rechten, '{}') ? 'beregening_invoeren');

-- instellingen: ook wanneer er gewaarschuwd wordt voor droogte (neerslagtekort in mm)
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel in ('koelcellen', 'etiket', 'etiket_logo') and public.heeft_recht('voorraad_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen', 'etiket', 'etiket_logo', 'droogte_mm') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  if p_sleutel = 'etiket_logo' and length(coalesce(p_waarde, '')) > 400000 then raise exception 'Het logo is te groot'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;


-- =====================================================================
--  TREKKERS EN BUSSEN: uren rijden / werken / stationair, diesel en km per dag
--  Trekkers: uit de punten van het kastje (toerental, hef, aftakas, l/uur) of de telefoon (alleen rijden/stilstaan).
--  Bussen: FleetGO (motor aan + snelheid); elke verandering wordt gelogd.
-- =====================================================================
alter table public.tractor_posities add column if not exists lh numeric;          -- brandstof l/uur op dat moment
alter table public.tractor_posities add column if not exists motoruren numeric;
create or replace function public.meld_kastje(p_sleutel uuid, p_punten jsonb, p_info jsonb default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare tid uuid; p jsonb; n int := 0; laatst jsonb; wt uuid; bakens text[]; t timestamptz;
begin
  select tractor_id into tid from public.tractor_sleutels where sleutel = p_sleutel;
  if tid is null then raise exception 'Onbekende sleutel'; end if;
  if jsonb_typeof(p_punten) <> 'array' or jsonb_array_length(p_punten) > 500 then raise exception 'Verkeerd pakket'; end if;
  for p in select * from jsonb_array_elements(p_punten) order by coalesce((value->>'t')::bigint, 0) loop
    if (p->>'lat') is null or (p->>'lng') is null or abs((p->>'lat')::float) > 90 or abs((p->>'lng')::float) > 180 then continue; end if;
    t := case when (p->>'t') is not null and (p->>'t')::bigint > 1600000000 then to_timestamp((p->>'t')::bigint) else now() end;
    if t > now() + interval '5 minutes' then t := now(); end if;
    -- werktuig: het eerste baken dat bij een machine hoort
    wt := null;
    if jsonb_typeof(p->'b') = 'array' then
      select array_agg(value) into bakens from jsonb_array_elements_text(p->'b');
      select id into wt from public.machines where baken is not null and lower(baken) = any (select lower(x) from unnest(bakens) x) limit 1;
    end if;
    insert into public.tractor_posities (tractor_id, lat, lng, richting, snelheid, tijd, toeren, aftakas, hef, werktuig_id, lh, motoruren)
    values (tid, (p->>'lat')::float, (p->>'lng')::float, (p->>'r')::numeric, round((p->>'v')::numeric * 3.6, 1), t, (p->>'rpm')::numeric, (p->>'pto')::numeric, (p->>'hef')::numeric, wt, (p->>'lh')::numeric, (p->>'uren')::numeric);
    n := n + 1; laatst := coalesce(laatst, '{}'::jsonb) || jsonb_strip_nulls(p) || jsonb_build_object('_t', t, '_wt', wt);   -- ontbrekende waarden uit eerdere punten
  end loop;
  if laatst is not null then
    update public.tractoren set lat = (laatst->>'lat')::float, lng = (laatst->>'lng')::float, richting = (laatst->>'r')::numeric, snelheid = round((laatst->>'v')::numeric * 3.6, 1),
      nauwkeurigheid = (laatst->>'acc')::numeric, bijgewerkt = greatest(coalesce(bijgewerkt, '-infinity'), (laatst->>'_t')::timestamptz),
      toeren = (laatst->>'rpm')::numeric, aftakas = (laatst->>'pto')::numeric, hef = (laatst->>'hef')::numeric,
      brandstof_lh = coalesce((laatst->>'lh')::numeric, brandstof_lh), brandstof_pct = coalesce((laatst->>'tank')::numeric, brandstof_pct),
      koelvloeistof = coalesce((laatst->>'temp')::numeric, koelvloeistof), motoruren = coalesce((laatst->>'uren')::numeric, motoruren),
      werktuig_id = (laatst->>'_wt')::uuid, kastje_gezien = now(), kastje_info = coalesce(p_info, kastje_info)
    where id = tid;
    -- motoruren ook bij de trekker in Machines (voor het onderhoud)
    if (laatst->>'uren') is not null then
      update public.machines set draaiuren = round((laatst->>'uren')::numeric, 1)
      where tractor_id = tid and (soort ~* 'trekker|tractor|zelfrijdend') and coalesce(draaiuren, 0) <= (laatst->>'uren')::numeric;
    end if;
  else
    update public.tractoren set kastje_gezien = now(), kastje_info = coalesce(p_info, kastje_info) where id = tid;
  end if;
  if random() < 0.01 then delete from public.tractor_posities where tijd < now() - interval '30 days'; end if;
  return jsonb_build_object('ok', n);
end $$;

create table if not exists public.voertuig_log (
  id          bigserial primary key,
  voertuig_id uuid not null references public.voertuigen(id) on delete cascade,
  tijd        timestamptz not null,
  motor_aan   boolean,
  snelheid    double precision,
  km          double precision
);
create index if not exists voertuig_log_tijd on public.voertuig_log (voertuig_id, tijd);
alter table public.voertuig_log enable row level security;   -- alleen via de functie hieronder
revoke all on public.voertuig_log from anon, authenticated;
create or replace function public.voertuig_loggen() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' or (new.gezien, new.motor_aan, new.snelheid) is distinct from (old.gezien, old.motor_aan, old.snelheid) then
    insert into public.voertuig_log (voertuig_id, tijd, motor_aan, snelheid, km) values (new.id, coalesce(new.gezien, now()), new.motor_aan, new.snelheid, new.km);
  end if;
  if random() < 0.002 then delete from public.voertuig_log where tijd < now() - interval '60 days'; end if;
  return new;
end $$;
drop trigger if exists voertuig_loggen on public.voertuigen;
create trigger voertuig_loggen after insert or update on public.voertuigen for each row execute function public.voertuig_loggen();

-- per dag bewaard (de ruwe punten worden na 30/60 dagen opgeruimd)
create table if not exists public.wagen_dagen (
  soort       text not null check (soort in ('trekker','bus')),
  wagen_id    uuid not null,
  datum       date not null,
  rijden      numeric not null default 0,   -- seconden
  werken      numeric not null default 0,
  stationair  numeric not null default 0,
  stil        numeric not null default 0,   -- stilstaan zonder toerental (telefoon)
  diesel_rijden numeric, diesel_werken numeric, diesel_stationair numeric,   -- liters
  km          numeric,
  motoruren   numeric,                       -- stand aan het eind van de dag
  primary key (soort, wagen_id, datum)
);
alter table public.wagen_dagen enable row level security;
revoke all on public.wagen_dagen from anon, authenticated;

-- uitrekenen uit de ruwe punten
create or replace function public.wagen_dagen_reken(p_van date, p_tot date) returns setof public.wagen_dagen
language sql stable security definer set search_path = '' as $$
  with tp as (
    select tractor_id id, tijd, snelheid, toeren, hef, aftakas, lh, motoruren, lat, lng,
           nullif(least(coalesce(extract(epoch from lead(tijd) over w - tijd), 0), 300), 0) dt,
           lead(lat) over w lat2, lead(lng) over w lng2
      from public.tractor_posities
     where tijd >= (p_van::timestamp at time zone 'Europe/Amsterdam') - interval '10 minutes' and tijd < ((p_tot + 1)::timestamp at time zone 'Europe/Amsterdam')
    window w as (partition by tractor_id order by tijd)),
  tk as (
    select *, case when toeren is not null and toeren < 300 then 'uit'
                   when coalesce(snelheid, 0) >= 1.5 and (coalesce(hef, 100) < 40 or coalesce(aftakas, 0) > 100) then 'werken'
                   when coalesce(snelheid, 0) >= 1.5 then 'rijden'
                   when toeren is not null then 'stationair' else 'stil' end st,
           (tijd at time zone 'Europe/Amsterdam')::date dag
      from tp where dt is not null and dt > 0),
  t as (
    select 'trekker'::text soort, id wagen_id, dag datum,
           coalesce(sum(dt) filter (where st = 'rijden'), 0) rijden, coalesce(sum(dt) filter (where st = 'werken'), 0) werken,
           coalesce(sum(dt) filter (where st = 'stationair'), 0) stationair, coalesce(sum(dt) filter (where st = 'stil'), 0) stil,
           round(sum(lh * dt / 3600) filter (where st = 'rijden'), 2) diesel_rijden, round(sum(lh * dt / 3600) filter (where st = 'werken'), 2) diesel_werken,
           round(sum(lh * dt / 3600) filter (where st = 'stationair'), 2) diesel_stationair,
           round((sum(case when lat2 is not null and dt < 300 then 6371 * 2 * asin(sqrt(power(sin(radians(lat2 - lat) / 2), 2) + cos(radians(lat)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng) / 2), 2))) end))::numeric, 1) km,
           max(motoruren) motoruren
      from tk where dag between p_van and p_tot group by id, dag),
  vl as (
    select voertuig_id id, tijd, motor_aan, snelheid, km, nullif(least(coalesce(extract(epoch from lead(tijd) over w - tijd), 0), 600), 0) dt
      from public.voertuig_log
     where tijd >= (p_van::timestamp at time zone 'Europe/Amsterdam') - interval '1 hour' and tijd < ((p_tot + 1)::timestamp at time zone 'Europe/Amsterdam')
    window w as (partition by voertuig_id order by tijd)),
  b as (
    select 'bus'::text, id, (tijd at time zone 'Europe/Amsterdam')::date dag,
           coalesce(sum(dt) filter (where motor_aan and coalesce(snelheid, 0) > 3), 0), 0::numeric,
           coalesce(sum(dt) filter (where motor_aan and coalesce(snelheid, 0) <= 3), 0), 0::numeric,
           null::numeric, null::numeric, null::numeric,
           round((max(km) - min(km))::numeric, 1), null::numeric
      from vl where dt is not null and dt > 0 and (tijd at time zone 'Europe/Amsterdam')::date between p_van and p_tot group by id, dag)
  select * from t union all select * from b;
$$;
revoke all on function public.wagen_dagen_reken(date, date) from public, anon, authenticated;

-- afgelopen dagen vastleggen (draait ook 's nachts als pg_cron aan staat)
create or replace function public.wagen_dagen_bewaren() returns void
language sql security definer set search_path = '' as $$
  insert into public.wagen_dagen select * from public.wagen_dagen_reken(current_date - 29, current_date - 1)
  on conflict (soort, wagen_id, datum) do update set rijden = excluded.rijden, werken = excluded.werken, stationair = excluded.stationair, stil = excluded.stil,
    diesel_rijden = excluded.diesel_rijden, diesel_werken = excluded.diesel_werken, diesel_stationair = excluded.diesel_stationair, km = excluded.km, motoruren = excluded.motoruren;
$$;
revoke all on function public.wagen_dagen_bewaren() from public, anon, authenticated;

-- voor de app: alle dagen in een periode (oude dagen uit de bewaarde tabel, recente vers uitgerekend)
create or replace function public.wagen_uren(p_soort text, p_van date, p_tot date) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare grens date := current_date - 29;
begin
  if p_soort = 'trekker' and not (public.heeft_recht('tractoren_volgen') or public.heeft_recht('tractoren_beheren')) then raise exception 'Je mag de trekkers niet zien'; end if;
  if p_soort = 'bus' and not (public.heeft_recht('voertuigen_zien') or public.heeft_recht('voertuigen_beheren')) then raise exception 'Je mag de bussen niet zien'; end if;
  if p_tot - p_van > 800 then raise exception 'Periode te lang'; end if;
  if p_tot >= grens and not exists (select 1 from public.wagen_dagen where datum = current_date - 1 limit 1) then perform public.wagen_dagen_bewaren(); end if;
  return coalesce((select jsonb_agg(to_jsonb(x) order by x.datum) from (
    select * from public.wagen_dagen where soort = p_soort and datum between p_van and least(p_tot, current_date - 1)
    union all
    select * from public.wagen_dagen_reken(greatest(p_van, current_date), p_tot) where soort = p_soort and p_tot >= current_date
  ) x), '[]'::jsonb);
end $$;
grant execute on function public.wagen_uren(text, date, date) to authenticated;

-- als pg_cron beschikbaar is: elke minuut de bussen ophalen (anders alleen als iemand de app open heeft) en 's nachts de dagen vastleggen
do $$ begin
  create extension if not exists pg_cron;
  perform cron.schedule('fleetgo', '* * * * *', 'select public.fleetgo_sync()');
  perform cron.schedule('wagen_dagen', '20 2 * * *', 'select public.wagen_dagen_bewaren()');
exception when others then raise notice 'pg_cron niet beschikbaar: %', sqlerrm;
end $$;


-- =====================================================================
--  RECHTEN: per scherm aan/uit (scherm_<naam>, ontbreekt = aan) en eigen standaarden (instelling recht_sjablonen)
-- =====================================================================
-- iemand met "team beheren" mag schermen aan- en uitzetten die hij zelf ook ziet
create or replace function public.eigen_rechten_filter(p_nieuw jsonb, p_oud jsonb) returns jsonb language sql stable security definer set search_path = '' as $$
  select case when public.is_beheerder() then p_nieuw
         else coalesce(p_oud, '{}') || coalesce((select jsonb_object_agg(k, v) from jsonb_each(coalesce(p_nieuw, '{}')) x(k, v)
               where public.heeft_recht(k)
                  or (k like 'scherm\_%' and coalesce((select (p.rechten ->> k)::boolean from public.profielen p where p.id = auth.uid()), true))), '{}') end;
$$;
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel in ('koelcellen', 'etiket', 'etiket_logo') and public.heeft_recht('voorraad_beheren'))
     and not (p_sleutel = 'recht_sjablonen' and public.heeft_recht('team_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen', 'etiket', 'etiket_logo', 'droogte_mm', 'recht_sjablonen') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  if p_sleutel = 'etiket_logo' and length(coalesce(p_waarde, '')) > 400000 then raise exception 'Het logo is te groot'; end if;
  if p_sleutel = 'recht_sjablonen' and (length(coalesce(p_waarde, '')) > 200000 or (nullif(trim(p_waarde), '') is not null and jsonb_typeof(p_waarde::jsonb) <> 'object')) then raise exception 'Ongeldige standaarden'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;


create or replace function public.fleetgo_sync(p_forceer boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  k public.fleetgo_koppeling; r extensions.http_response; j jsonb; e jsonb; n int := 0; poging int;
  la double precision; ln double precision;
begin
  if not pg_try_advisory_xact_lock(470501) then return jsonb_build_object('ok', true, 'bericht', 'wordt al opgehaald'); end if;
  select * into k from public.fleetgo_koppeling where id = 1;
  if k.id is null or coalesce(k.client_id, '') = '' or coalesce(k.gebruiker, '') = '' then
    return jsonb_build_object('ok', false, 'bericht', 'De FleetGO-koppeling is nog niet ingesteld');
  end if;
  if not p_forceer and k.laatste_sync > now() - interval '8 seconds' then
    return jsonb_build_object('ok', true, 'bericht', 'net bijgewerkt');
  end if;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '12000');
  for poging in 1..2 loop
    -- inloggen als er geen geldige sleutel (token) is
    if k.token is null or k.token_tot < now() + interval '1 minute' then
      r := extensions.http_post('https://api.fleetgo.com/api/session/login',
             jsonb_build_object('client_id', k.client_id, 'client_secret', k.client_secret, 'username', k.gebruiker, 'password', k.wachtwoord)::text,
             'application/json');
      begin j := r.content::jsonb; exception when others then j := null; end;
      if r.status <> 200 or j ->> 'access_token' is null then
        update public.fleetgo_koppeling set laatste_fout = 'Inloggen bij FleetGO mislukt (' || r.status || '): ' || left(coalesce(r.content, ''), 300), token = null where id = 1;
        return jsonb_build_object('ok', false, 'bericht', 'Inloggen bij FleetGO mislukt (' || r.status || '). Controleer client ID/secret en gebruikersnaam/wachtwoord.');
      end if;
      k.token := j ->> 'access_token';
      k.token_tot := now() + make_interval(secs => coalesce(nullif(j ->> 'expires_in', '')::numeric, 3600));
      update public.fleetgo_koppeling set token = k.token, token_tot = k.token_tot where id = 1;
    end if;
    r := extensions.http(('GET', 'https://api.fleetgo.com/api/equipment/Getfleet?groupId=0&hasDeviceOnly=false',
           array[extensions.http_header('Authorization', 'Bearer ' || k.token)], null, null)::extensions.http_request);
    exit when r.status <> 401;
    k.token := null;   -- sleutel verlopen: één keer opnieuw inloggen
  end loop;
  begin j := r.content::jsonb; exception when others then j := null; end;
  if r.status <> 200 or j is null or jsonb_typeof(j) <> 'array' then
    update public.fleetgo_koppeling set laatste_fout = 'Voertuigen ophalen mislukt (' || r.status || '): ' || left(coalesce(r.content, ''), 300) where id = 1;
    return jsonb_build_object('ok', false, 'bericht', 'Voertuigen ophalen bij FleetGO mislukt (' || r.status || ')');
  end if;
  for e in select * from jsonb_array_elements(j) loop
    la := nullif(coalesce(e #>> '{Location,Latitude}', e ->> 'Latitude'), '')::double precision;
    ln := nullif(coalesce(e #>> '{Location,Longitude}', e ->> 'Longitude'), '')::double precision;
    if la = 0 and ln = 0 then la := null; ln := null; end if;
    insert into public.voertuigen as v (fleetgo_id, kenteken, merk, model, lat, lng, snelheid, motor_aan, km, gezien, bijgewerkt)
    values (coalesce(e ->> 'Id', e #>> '{EquipmentHeader,EquipmentID}'),
            coalesce(e #>> '{EquipmentHeader,SerialNumber}', e ->> 'LicensePlate'),
            e #>> '{EquipmentHeader,Make}', e #>> '{EquipmentHeader,Model}',
            la, ln, nullif(e ->> 'Speed', '')::double precision, (e ->> 'EngineRunning')::boolean,
            nullif(e ->> 'Odometer', '')::double precision, public.fleetgo_tijd(e #>> '{Location,DateTime}'), now())
    on conflict (fleetgo_id) do update set
      kenteken = excluded.kenteken, merk = excluded.merk, model = excluded.model,
      lat = coalesce(excluded.lat, v.lat), lng = coalesce(excluded.lng, v.lng), snelheid = excluded.snelheid,
      motor_aan = excluded.motor_aan, km = excluded.km, gezien = coalesce(excluded.gezien, v.gezien), bijgewerkt = now()
    where (v.lat, v.lng, v.snelheid, v.motor_aan, v.gezien, v.kenteken) is distinct from
          (coalesce(excluded.lat, v.lat), coalesce(excluded.lng, v.lng), excluded.snelheid, excluded.motor_aan, coalesce(excluded.gezien, v.gezien), excluded.kenteken);
    -- wie er nu in zit (als FleetGO dat meestuurt, bijv. via een rijderspas): apart bewaard, niet zichtbaar voor iedereen
    if coalesce(e ->> 'DriverName', e #>> '{Driver,Name}', e #>> '{Driver,FullName}', e #>> '{CurrentDriver,Name}', e #>> '{Employee,Name}') is not null then
      insert into public.voertuig_bestuurder (voertuig_id, naam, sinds)
      select v.id, coalesce(e ->> 'DriverName', e #>> '{Driver,Name}', e #>> '{Driver,FullName}', e #>> '{CurrentDriver,Name}', e #>> '{Employee,Name}'), now()
        from public.voertuigen v where v.fleetgo_id = coalesce(e ->> 'Id', e #>> '{EquipmentHeader,EquipmentID}')
      on conflict (voertuig_id) do update set naam = excluded.naam, sinds = case when public.voertuig_bestuurder.naam is distinct from excluded.naam then now() else public.voertuig_bestuurder.sinds end;
    end if;
    n := n + 1;
  end loop;
  update public.fleetgo_koppeling set laatste_sync = now(), laatste_fout = null, voorbeeld = j -> 0 where id = 1;
  return jsonb_build_object('ok', true, 'bericht', n || ' voertuigen bijgewerkt', 'aantal', n);
exception when others then
  update public.fleetgo_koppeling set laatste_fout = sqlerrm where id = 1;
  return jsonb_build_object('ok', false, 'bericht', 'Fout bij FleetGO: ' || sqlerrm);
end $$;

-- =====================================================================
--  BUSSEN: ritten uit FleetGO (wie reed, van waar naar waar, km) en wie er nu in zit
--  Dit zijn persoonsgegevens: alleen met het recht "ritten_bekijken" en nooit op een gedeeld apparaat.
-- =====================================================================
create table if not exists public.voertuig_bestuurder (
  voertuig_id uuid primary key references public.voertuigen(id) on delete cascade,
  naam text, sinds timestamptz
);
alter table public.voertuig_bestuurder enable row level security;
revoke all on public.voertuig_bestuurder from anon, authenticated;

create table if not exists public.voertuig_ritten (
  id            bigint primary key,            -- rit-id van FleetGO
  voertuig_id   uuid references public.voertuigen(id) on delete cascade,
  equipment_id  text,
  van_tijd      timestamptz, tot_tijd timestamptz,
  van_adres     text, tot_adres text,
  van_lat double precision, van_lng double precision, tot_lat double precision, tot_lng double precision,
  km            numeric,
  bestuurder    text, bestuurder_id text,
  stilstaan_uren numeric, brandstof_l numeric,
  kenteken      text, soort text, doel text, opmerking text,
  track         text,                           -- gecodeerde route (Google-polyline)
  bijgewerkt    timestamptz not null default now()
);
create index if not exists voertuig_ritten_tijd on public.voertuig_ritten (van_tijd desc);
alter table public.voertuig_ritten enable row level security;
revoke all on public.voertuig_ritten from anon, authenticated;
alter table public.fleetgo_koppeling add column if not exists laatste_ritten timestamptz;

-- inloggen bij FleetGO en een geldige sleutel teruggeven
create or replace function public.fleetgo_token() returns text
language plpgsql security definer set search_path = '' as $$
declare k public.fleetgo_koppeling; r extensions.http_response; j jsonb;
begin
  select * into k from public.fleetgo_koppeling where id = 1;
  if k.id is null or coalesce(k.client_id, '') = '' then raise exception 'De FleetGO-koppeling is nog niet ingesteld'; end if;
  if k.token is not null and k.token_tot > now() + interval '1 minute' then return k.token; end if;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '15000');
  r := extensions.http_post('https://api.fleetgo.com/api/session/login',
         jsonb_build_object('client_id', k.client_id, 'client_secret', k.client_secret, 'username', k.gebruiker, 'password', k.wachtwoord)::text, 'application/json');
  begin j := r.content::jsonb; exception when others then j := null; end;
  if r.status <> 200 or j ->> 'access_token' is null then raise exception 'Inloggen bij FleetGO mislukt (%)', r.status; end if;
  update public.fleetgo_koppeling set token = j ->> 'access_token', token_tot = now() + make_interval(secs => coalesce(nullif(j ->> 'expires_in', '')::numeric, 3600)) where id = 1;
  return j ->> 'access_token';
end $$;
revoke all on function public.fleetgo_token() from public, anon, authenticated;

-- ritten ophalen (standaard de laatste 2 dagen)
create or replace function public.fleetgo_ritten_sync(p_van timestamptz default now() - interval '2 days', p_tot timestamptz default now()) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare t text; r extensions.http_response; j jsonb; e jsonb; n int := 0;
begin
  if not pg_try_advisory_xact_lock(470502) then return jsonb_build_object('ok', true, 'bericht', 'wordt al opgehaald'); end if;
  t := public.fleetgo_token();
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '25000');
  r := extensions.http(('GET', 'https://api.fleetgo.com/api/Trips/GetTrips?from=' || to_char(p_van at time zone 'Europe/Amsterdam', 'YYYY-MM-DD"T"HH24:MI:SS')
          || '&to=' || to_char(p_tot at time zone 'Europe/Amsterdam', 'YYYY-MM-DD"T"HH24:MI:SS') || '&extendedInfo=true&accountId=0',
         array[extensions.http_header('Authorization', 'Bearer ' || t)], null, null)::extensions.http_request);
  if r.status = 401 then update public.fleetgo_koppeling set token = null where id = 1; raise exception 'FleetGO-sleutel verlopen, probeer opnieuw'; end if;
  begin j := r.content::jsonb; exception when others then j := null; end;
  if r.status <> 200 or j is null or jsonb_typeof(j) <> 'array' then
    update public.fleetgo_koppeling set laatste_fout = 'Ritten ophalen mislukt (' || r.status || '): ' || left(coalesce(r.content, ''), 300) where id = 1;
    return jsonb_build_object('ok', false, 'bericht', 'Ritten ophalen bij FleetGO mislukt (' || r.status || ')');
  end if;
  for e in select * from jsonb_array_elements(j) loop
    continue when (e ->> 'Id') is null;
    insert into public.voertuig_ritten as x (id, voertuig_id, equipment_id, van_tijd, tot_tijd, van_adres, tot_adres, van_lat, van_lng, tot_lat, tot_lng, km,
        bestuurder, bestuurder_id, stilstaan_uren, brandstof_l, kenteken, soort, doel, opmerking, track, bijgewerkt)
    values ((e ->> 'Id')::bigint, (select id from public.voertuigen where fleetgo_id = e ->> 'EquipmentId'), e ->> 'EquipmentId',
      public.fleetgo_tijd(e #>> '{From,DateTime}'), public.fleetgo_tijd(e #>> '{To,DateTime}'),
      nullif(concat_ws(', ', nullif(e #>> '{From,Address,Address}', ''), nullif(e #>> '{From,Address,City}', ''), nullif(e #>> '{From,PointOfInterest,Name}', ''), nullif(e #>> '{From,Description}', '')), ''),
      nullif(concat_ws(', ', nullif(e #>> '{To,Address,Address}', ''), nullif(e #>> '{To,Address,City}', ''), nullif(e #>> '{To,PointOfInterest,Name}', ''), nullif(e #>> '{To,Description}', '')), ''),
      nullif(coalesce(e #>> '{From,Location,Latitude}', e #>> '{From,Address,Latitude}'), '')::float, nullif(coalesce(e #>> '{From,Location,Longitude}', e #>> '{From,Address,Longitude}'), '')::float,
      nullif(coalesce(e #>> '{To,Location,Latitude}', e #>> '{To,Address,Latitude}'), '')::float, nullif(coalesce(e #>> '{To,Location,Longitude}', e #>> '{To,Address,Longitude}'), '')::float,
      nullif(e ->> 'Distance', '')::numeric, nullif(e ->> 'DriverName', ''), nullif(e ->> 'DriverId', ''),
      nullif(e ->> 'StationaryTimeInHours', '')::numeric, nullif(e ->> 'FuelUsedInLiters', '')::numeric, e ->> 'LicensePlate',
      coalesce(e #>> '{RideType,Name}', e #>> '{RideType,Description}', e ->> 'TripTypeId'), nullif(e ->> 'Purpose', ''), nullif(concat_ws(' · ', nullif(e ->> 'Remarks', ''), nullif(e ->> 'Reason', '')), ''),
      left(nullif(e ->> 'EncodedTrack', ''), 60000), now())
    on conflict (id) do update set voertuig_id = excluded.voertuig_id, van_tijd = excluded.van_tijd, tot_tijd = excluded.tot_tijd, van_adres = excluded.van_adres, tot_adres = excluded.tot_adres,
      van_lat = excluded.van_lat, van_lng = excluded.van_lng, tot_lat = excluded.tot_lat, tot_lng = excluded.tot_lng, km = excluded.km, bestuurder = excluded.bestuurder, bestuurder_id = excluded.bestuurder_id,
      stilstaan_uren = excluded.stilstaan_uren, brandstof_l = excluded.brandstof_l, kenteken = excluded.kenteken, soort = excluded.soort, doel = excluded.doel, opmerking = excluded.opmerking,
      track = coalesce(excluded.track, x.track), bijgewerkt = now();
    n := n + 1;
  end loop;
  update public.fleetgo_koppeling set laatste_ritten = now() where id = 1;
  -- oude ritten na 2 jaar opruimen
  if random() < 0.02 then delete from public.voertuig_ritten where van_tijd < now() - interval '2 years'; end if;
  return jsonb_build_object('ok', true, 'aantal', n);
exception when others then
  return jsonb_build_object('ok', false, 'bericht', 'Fout bij FleetGO-ritten: ' || sqlerrm);
end $$;
revoke all on function public.fleetgo_ritten_sync(timestamptz, timestamptz) from public, anon, authenticated;

-- voor de app: ritten in een periode (haalt ze eerst vers op als dat langer dan 3 minuten geleden is)
create or replace function public.voertuig_ritten(p_van date, p_tot date, p_vers boolean default true) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare k public.fleetgo_koppeling; s jsonb := null;
begin
  if public.is_apparaat() or not (public.heeft_recht('ritten_bekijken') or public.heeft_recht('voertuigen_beheren')) then raise exception 'Je mag de ritten niet zien'; end if;
  if p_tot - p_van > 400 then raise exception 'Periode te lang'; end if;
  select * into k from public.fleetgo_koppeling where id = 1;
  if p_vers and k.id is not null and coalesce(k.laatste_ritten, '-infinity') < now() - interval '3 minutes' then
    s := public.fleetgo_ritten_sync(greatest(p_van::timestamp at time zone 'Europe/Amsterdam', coalesce(least(k.laatste_ritten, now()) - interval '2 days', p_van::timestamp at time zone 'Europe/Amsterdam')),
                                    least((p_tot + 1)::timestamp at time zone 'Europe/Amsterdam', now()));
    -- eerste keer of een oudere periode: ook die periode ophalen
    if not exists (select 1 from public.voertuig_ritten where van_tijd < (p_van + 1)::timestamp at time zone 'Europe/Amsterdam' and van_tijd >= p_van::timestamp at time zone 'Europe/Amsterdam')
       and p_van < current_date - 1 then
      s := public.fleetgo_ritten_sync(p_van::timestamp at time zone 'Europe/Amsterdam', least((p_tot + 1)::timestamp at time zone 'Europe/Amsterdam', now()));
    end if;
  end if;
  return jsonb_build_object('sync', s,
    'nu', coalesce((select jsonb_object_agg(voertuig_id, jsonb_build_object('naam', naam, 'sinds', sinds)) from public.voertuig_bestuurder), '{}'),
    'ritten', coalesce((select jsonb_agg(to_jsonb(r) - 'track' || jsonb_build_object('heeft_track', r.track is not null) order by r.van_tijd desc)
      from public.voertuig_ritten r where r.van_tijd >= p_van::timestamp at time zone 'Europe/Amsterdam' and r.van_tijd < (p_tot + 1)::timestamp at time zone 'Europe/Amsterdam'), '[]'));
end $$;
grant execute on function public.voertuig_ritten(date, date, boolean) to authenticated;

-- de route van één rit (voor op de kaart)
create or replace function public.voertuig_rit_route(p_id bigint) returns text
language plpgsql security definer set search_path = '' as $$
begin
  if public.is_apparaat() or not (public.heeft_recht('ritten_bekijken') or public.heeft_recht('voertuigen_beheren')) then raise exception 'Je mag de ritten niet zien'; end if;
  return (select track from public.voertuig_ritten where id = p_id);
end $$;
grant execute on function public.voertuig_rit_route(bigint) to authenticated;

update public.profielen set rechten = '{"ritten_bekijken":false}'::jsonb || coalesce(rechten, '{}') where not (coalesce(rechten, '{}') ? 'ritten_bekijken');

do $$ begin
  perform cron.schedule('fleetgo_ritten', '*/15 * * * *', 'select public.fleetgo_ritten_sync()');
exception when others then raise notice 'pg_cron niet beschikbaar: %', sqlerrm;
end $$;
-- =====================================================================
--  Werkplek "koelcel": account dat alleen de koelcellen, orders en bakken onderweg ziet
--  (los stukje: draai dit in de SQL Editor; het past alleen zet_werkplek aan)
-- =====================================================================
create or replace function public.zet_werkplek(p_id uuid, p_werkplek text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder mag dit instellen'; end if;
  if p_werkplek is not null and p_werkplek not in ('kiep', 'koelcel') then raise exception 'Onbekende werkplek'; end if;
  update public.profielen set
    werkplek = p_werkplek,
    -- kieplijst = gedeelde telefoon (geen persoonsgegevens); koelcel = gewoon account (moet orders kunnen zien)
    apparaat = case when p_werkplek = 'kiep' then true when p_werkplek = 'koelcel' then false else apparaat end,
    rechten = case when p_werkplek = 'koelcel'
                   then coalesce(rechten, '{}'::jsonb) || '{"voorraad_bekijken":true,"voorraad_beheren":true,"etiketten_printen":true}'::jsonb
                   else rechten end
  where id = p_id;
end $$;
revoke all on function public.zet_werkplek(uuid, text) from public, anon;
grant execute on function public.zet_werkplek(uuid, text) to authenticated;
-- Werkplek-accounts (koelcel-/scanner-tablet, heftruck, prikklok-iPad) hoeven niet in te klokken
-- en staan niet in de namenlijst van de kantine-iPad.

create or replace function public.is_werkplek_account(p_uid uuid default auth.uid()) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select p.werkplek is not null or coalesce(p.prikklok, false) or coalesce(p.apparaat, false)
                   from public.profielen p where p.id = p_uid), false);
$$;
revoke all on function public.is_werkplek_account(uuid) from public, anon;
grant execute on function public.is_werkplek_account(uuid) to authenticated;

-- namenlijst kantine-iPad: alleen echte mensen
create or replace function public.klok_namen() returns table (id uuid, naam text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.naam from public.profielen p
  where (public.is_prikklok() or public.is_beheerder())
    and coalesce(p.apparaat, false) = false and coalesce(p.prikklok, false) = false and p.werkplek is null
    and p.naam is not null
  order by p.naam;
$$;

-- taken oppakken/afvinken: een werkplek-account (niet-trekker) hoeft niet ingeklokt te zijn
create or replace function public.klok_taak() returns trigger
language plpgsql security definer set search_path = '' as $$
declare wie text;
begin
  if auth.uid() is null or not public.klokplicht() or public.is_beheerder() then return new; end if;
  if (new.bezig_door is not null and new.bezig_door is distinct from old.bezig_door) or (new.klaar and not old.klaar) then
    wie := case when new.klaar and not old.klaar then new.klaar_door else new.bezig_door end;
    if public.is_apparaat() then
      if not public.ingeklokt_naam(wie) then raise exception 'NIET_INGEKLOKT: % is vandaag nog niet ingeklokt', wie; end if;
    elsif public.is_werkplek_account() then return new;
    elsif not public.ingeklokt(auth.uid()) then raise exception 'NIET_INGEKLOKT: je bent vandaag nog niet ingeklokt'; end if;
  end if;
  return new;
end $$;

-- vlaggen, gebieden en waarnemingen
create or replace function public.klok_maken() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null or not public.klokplicht() or public.is_beheerder() or public.is_werkplek_account() then return new; end if;
  if not public.ingeklokt(auth.uid()) then raise exception 'NIET_INGEKLOKT: je bent vandaag nog niet ingeklokt'; end if;
  return new;
end $$;
-- =====================================================================
-- HEFTRUCK SCANNEN (24 november 2026)
-- Bakken/boxen (B-kaartjes) en pallets (P-kaarten) scannen, daarna een koelcel of de kiep.
--  · nog nergens          → erin
--  · al in die koelcel    → eruit
--  · in een andere koelcel → verplaatst
--  · kiep                 → gekiept (resultaten) en uit de koelcel
-- Pallet scannen en daarna boxen = die boxen staan op die pallet (en gaan mee).
-- De voorraad blijft in partij_mutaties staan (zelfde als de koelcel-plattegrond).
-- =====================================================================
alter table public.etiketten add column if not exists op_pallet  text;          -- P17: deze box staat op pallet 17
alter table public.etiketten add column if not exists gekiept_op timestamptz;   -- box is gekiept

create table if not exists public.scan_log (
  id         uuid primary key default gen_random_uuid(),
  code       text not null,
  actie      text not null,          -- in / uit / verplaatst / gekiept / op_pallet / van_pallet
  van        text,
  naar       text,
  partij_id  uuid references public.partijen(id) on delete set null,
  melding    text,
  door       text,
  user_id    uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists scan_log_tijd on public.scan_log (created_at desc);
alter table public.scan_log enable row level security;
grant select on public.scan_log to authenticated;
drop policy if exists "lezen" on public.scan_log;
create policy "lezen" on public.scan_log for select to authenticated
  using (public.heeft_recht('voorraad_bekijken') or public.heeft_recht('voorraad_beheren'));
do $$ begin alter publication supabase_realtime add table public.scan_log; exception when duplicate_object then null; when undefined_object then null; end $$;

-- netto aantal van een voorraadregel (in en correctie tellen zoals ze zijn, uit en uitval eraf)
create or replace function public.mut_netto(p_soort text, p_aantal numeric) returns numeric
language sql immutable as $$ select case when p_soort in ('in', 'correctie') then p_aantal else -p_aantal end $$;

-- in welke koelcel staat een etiket nu? (null = nergens)
create or replace function public.etiket_cel(p_code text) returns text
language plpgsql stable security definer set search_path = '' as $$
declare e public.etiketten; c text;
begin
  select * into e from public.etiketten where code = upper(trim(p_code));
  if not found then return null; end if;
  if e.soort = 'pallet' then
    select m.koelcel into c from public.partij_mutaties m where m.pallet = e.nr::text and m.koelcel is not null
      group by m.koelcel having sum(public.mut_netto(m.soort, m.aantal)) > 0.001 order by max(m.created_at) desc limit 1;
  else
    select m.koelcel into c from public.partij_mutaties m where m.notitie = 'Box ' || e.nr and m.koelcel is not null
      group by m.koelcel having sum(public.mut_netto(m.soort, m.aantal)) > 0.001 order by max(m.created_at) desc limit 1;
  end if;
  return c;
end $$;
grant execute on function public.etiket_cel(text) to authenticated;

-- één box boeken: naar een koelcel (en evt. pallet), of eruit (p_cel null)
create or replace function public.scan_box_boek(e public.etiketten, p_cel text, p_pallet text, p_door text) returns void
language plpgsql security definer set search_path = '' as $$
declare r record; s uuid; eenh text;
begin
  select m.koelcel, m.pallet, m.partij_id, m.eenheid, max(m.per_eenheid) per, sum(public.mut_netto(m.soort, m.aantal)) netto
    into r from public.partij_mutaties m where m.notitie = 'Box ' || e.nr
    group by m.koelcel, m.pallet, m.partij_id, m.eenheid having sum(public.mut_netto(m.soort, m.aantal)) > 0.001 limit 1;
  if p_cel is null then
    if r.netto is null then return; end if;
    select seizoen_id into s from public.partijen where id = r.partij_id;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door)
      values (r.partij_id, s, 'uit', r.netto, r.eenheid, r.per, r.koelcel, r.pallet, 'Box ' || e.nr, p_door);
    return;
  end if;
  if r.netto is not null then
    if r.koelcel is not distinct from p_cel and r.pallet is not distinct from p_pallet then return; end if;
    select seizoen_id into s from public.partijen where id = r.partij_id;
    eenh := case when p_pallet is not null then 'kistjes' else r.eenheid end;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door) values
      (r.partij_id, s, 'correctie', -r.netto, r.eenheid, r.per, r.koelcel, r.pallet, 'Box ' || e.nr, p_door),
      (r.partij_id, s, 'correctie',  r.netto, eenh,      r.per, p_cel,     p_pallet, 'Box ' || e.nr, p_door);
    return;
  end if;
  if e.partij_id is null then raise exception 'Box % is niet aan een partij gekoppeld', e.nr; end if;
  select seizoen_id into s from public.partijen where id = e.partij_id;
  insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door)
    values (e.partij_id, coalesce(e.seizoen_id, s), 'in', 1, case when p_pallet is not null then 'kistjes' else 'kuubskisten' end,
            nullif(e.data->>'per_kist', '')::numeric, p_cel, p_pallet, 'Box ' || e.nr, p_door);
end $$;
revoke all on function public.scan_box_boek(public.etiketten, text, text, text) from public, anon, authenticated;

-- de eigen regels van een pallet (zonder boxen erop): verplaatsen naar p_cel, of eruit (p_cel null)
create or replace function public.scan_pallet_boek(pe public.etiketten, p_cel text, p_door text) returns integer
language plpgsql security definer set search_path = '' as $$
declare r record; s uuid; n integer := 0; k numeric;
begin
  for r in select m.koelcel, m.partij_id, m.eenheid, max(m.per_eenheid) per, sum(public.mut_netto(m.soort, m.aantal)) netto
             from public.partij_mutaties m where m.pallet = pe.nr::text and coalesce(m.notitie, '') not like 'Box %'
             group by m.koelcel, m.partij_id, m.eenheid having sum(public.mut_netto(m.soort, m.aantal)) > 0.001 loop
    n := n + 1;
    select seizoen_id into s from public.partijen where id = r.partij_id;
    if p_cel is null then
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door)
        values (r.partij_id, s, 'uit', r.netto, r.eenheid, r.per, r.koelcel, pe.nr::text, 'etiket ' || pe.code, p_door);
    elsif r.koelcel is distinct from p_cel then
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door) values
        (r.partij_id, s, 'correctie', -r.netto, r.eenheid, r.per, r.koelcel, pe.nr::text, '↔ van ' || coalesce(r.koelcel, '?') || ' naar ' || p_cel, p_door),
        (r.partij_id, s, 'correctie',  r.netto, r.eenheid, r.per, p_cel,     pe.nr::text, '↔ van ' || coalesce(r.koelcel, '?') || ' naar ' || p_cel, p_door);
    end if;
  end loop;
  -- nieuwe pallet zonder boxen erop: de kistjes van het etiket inslaan
  if n = 0 and p_cel is not null and not exists (select 1 from public.etiketten b where b.op_pallet = pe.code) then
    k := nullif(pe.data->>'kistjes', '')::numeric;
    if pe.partij_id is null or k is null or k <= 0 then
      raise exception 'Pallet %: scan eerst de kistjes/boxen die erop staan (of vul de partij en het aantal kistjes in op het etiket)', pe.nr;
    end if;
    select seizoen_id into s from public.partijen where id = pe.partij_id;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door)
      values (pe.partij_id, coalesce(pe.seizoen_id, s), 'in', k, 'kistjes', nullif(pe.data->>'per_kist', '')::numeric, p_cel, pe.nr::text, 'etiket ' || pe.code, p_door);
    n := 1;
  end if;
  return n;
end $$;
revoke all on function public.scan_pallet_boek(public.etiketten, text, text) from public, anon, authenticated;

-- één gescande code verwerken; geeft de melding terug
create or replace function public.scan_een(p_actie text, p_code text, p_doel text, p_door text) returns text
language plpgsql security definer set search_path = '' as $$
declare e public.etiketten; pe public.etiketten; b public.etiketten; cur text; n integer; msg text; nb integer := 0;
begin
  select * into e from public.etiketten where code = upper(trim(p_code));
  if not found then raise exception '% niet gevonden', p_code; end if;
  cur := public.etiket_cel(e.code);

  if p_actie = 'koelcel' then
    if e.soort = 'box' then
      if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
      if cur is not distinct from p_doel then
        perform public.scan_box_boek(e, null, null, p_door);
        update public.etiketten set op_pallet = null where id = e.id;
        msg := format('⬆️ Box %s uit %s', e.nr, p_doel);
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'uit', cur, null, e.partij_id, msg, p_door);
      else
        perform public.scan_box_boek(e, p_doel, null, p_door);
        update public.etiketten set op_pallet = null where id = e.id;
        msg := case when cur is null then format('⬇️ Box %s in %s', e.nr, p_doel) else format('↔ Box %s: %s → %s', e.nr, cur, p_doel) end;
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, case when cur is null then 'in' else 'verplaatst' end, cur, p_doel, e.partij_id, msg, p_door);
      end if;
    else
      if cur is not distinct from p_doel then
        for b in select * from public.etiketten where op_pallet = e.code loop perform public.scan_box_boek(b, null, null, p_door); nb := nb + 1; end loop;
        perform public.scan_pallet_boek(e, null, p_door);
        msg := format('⬆️ Pallet %s uit %s', e.nr, p_doel);
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'uit', cur, null, e.partij_id, msg, p_door);
      else
        for b in select * from public.etiketten where op_pallet = e.code and gekiept_op is null loop perform public.scan_box_boek(b, p_doel, e.nr::text, p_door); nb := nb + 1; end loop;
        perform public.scan_pallet_boek(e, p_doel, p_door);
        msg := case when cur is null then format('⬇️ Pallet %s in %s', e.nr, p_doel) else format('↔ Pallet %s: %s → %s', e.nr, cur, p_doel) end
               || case when nb > 0 then format(' (%s kistjes/boxen)', nb) else '' end;
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, case when cur is null then 'in' else 'verplaatst' end, cur, p_doel, e.partij_id, msg, p_door);
      end if;
    end if;
    return msg;
  end if;

  if p_actie = 'kiep' then
    if e.soort = 'pallet' then
      for b in select * from public.etiketten where op_pallet = e.code and gekiept_op is null loop
        perform public.scan_een('kiep', b.code, null, p_door); nb := nb + 1;
      end loop;
      if nb = 0 then raise exception 'Op pallet % staan geen gescande bakken; scan de bakken zelf', e.nr; end if;
      return format('🧺 Pallet %s: %s %s gekiept', e.nr, nb, case when nb = 1 then 'bak' else 'bakken' end);
    end if;
    if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
    if e.partij_id is null then raise exception 'Box % is niet aan een partij gekoppeld', e.nr; end if;
    insert into public.res_invoer (soort, partij_id, bakken, bron, door, opmerking) values ('kiepen', e.partij_id, 1, 'scan', p_door, 'Box ' || e.nr);
    perform public.scan_box_boek(e, null, null, p_door);
    update public.etiketten set gekiept_op = now(), op_pallet = null where id = e.id;
    msg := format('🧺 Box %s gekiept', e.nr);
    insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'gekiept', cur, 'kiep', e.partij_id, msg, p_door);
    return msg;
  end if;

  if p_actie in ('pallet_op', 'pallet_af') then
    select * into pe from public.etiketten where code = upper(trim(p_doel)) and soort = 'pallet';
    if not found then raise exception 'Pallet % niet gevonden', p_doel; end if;
    if e.soort <> 'box' then raise exception 'Op een pallet kun je alleen kistjes/boxen zetten'; end if;
    if p_actie = 'pallet_op' then
      if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
      if e.op_pallet = pe.code then return format('✓ Box %s stond al op pallet %s', e.nr, pe.nr); end if;
      update public.etiketten set op_pallet = pe.code where id = e.id;
      -- staat de pallet (of de box) al in een koelcel, dan gaat de box mee naar de pallet
      if coalesce(public.etiket_cel(pe.code), cur) is not null then
        perform public.scan_box_boek(e, coalesce(public.etiket_cel(pe.code), cur), pe.nr::text, p_door);
      end if;
      msg := format('➕ Box %s op pallet %s', e.nr, pe.nr);
      insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'op_pallet', null, pe.code, e.partij_id, msg, p_door);
    else
      if e.op_pallet is distinct from pe.code then raise exception 'Box % staat niet op pallet %', e.nr, pe.nr; end if;
      update public.etiketten set op_pallet = null where id = e.id;
      if cur is not null then perform public.scan_box_boek(e, cur, null, p_door); end if;
      msg := format('➖ Box %s van pallet %s gehaald', e.nr, pe.nr);
      insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'van_pallet', pe.code, null, e.partij_id, msg, p_door);
    end if;
    return msg;
  end if;
  raise exception 'Onbekende actie %', p_actie;
end $$;
revoke all on function public.scan_een(text, text, text, text) from public, anon, authenticated;

-- wat de app aanroept: een rij codes met één actie. Elke code apart: één fout houdt de rest niet tegen.
create or replace function public.scan_boek(p_actie text, p_codes text[], p_doel text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare c text; r jsonb := '[]'::jsonb; m text; wie text;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_actie not in ('koelcel', 'kiep', 'pallet_op', 'pallet_af') then raise exception 'Onbekende actie'; end if;
  if p_actie <> 'kiep' and coalesce(trim(p_doel), '') = '' then raise exception 'Geen koelcel of pallet gekozen'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  foreach c in array coalesce(p_codes, '{}') loop
    begin
      m := public.scan_een(p_actie, c, nullif(trim(p_doel), ''), wie);
      r := r || jsonb_build_object('code', upper(trim(c)), 'ok', true, 'melding', m);
    exception when others then
      r := r || jsonb_build_object('code', upper(trim(c)), 'ok', false, 'melding', regexp_replace(sqlerrm, '^RES: ', ''));
    end;
  end loop;
  return r;
end $$;
revoke all on function public.scan_boek(text, text[], text) from public, anon;
grant execute on function public.scan_boek(text, text[], text) to authenticated;
-- =====================================================================
-- KIEPEN UIT DE KOELCEL (25 november 2026)
-- Op de kieplijst staan ook de kuubskisten die in de koelcellen staan (per batch).
-- Tik → aantal kiezen → "Gekiept": dat telt als gekiept bij de resultaten en gaat uit de koelcel.
-- Gescande boxen (B-kaartjes) van die partij in die koelcel gaan als eerste mee.
-- =====================================================================
create or replace function public.kiep_uit_koelcel(p_partij uuid, p_cel text, p_aantal integer) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare wie text; beschikbaar numeric; k integer := 0; b public.etiketten; s uuid; per numeric; r uuid;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_aantal is null or p_aantal < 1 or p_aantal > 500 then raise exception 'Kies een aantal tussen 1 en 500'; end if;
  if coalesce(trim(p_cel), '') = '' then raise exception 'Geen koelcel gekozen'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  select coalesce(sum(public.mut_netto(m.soort, m.aantal)), 0) into beschikbaar
    from public.partij_mutaties m where m.partij_id = p_partij and m.koelcel = p_cel and m.eenheid = 'kuubskisten';
  if beschikbaar < p_aantal - 0.001 then
    raise exception 'In % staan maar % kuubskisten van deze partij', p_cel, trim(to_char(beschikbaar, 'FM999990.##'));
  end if;
  select seizoen_id into s from public.partijen where id = p_partij;
  insert into public.res_invoer (soort, seizoen_id, partij_id, bakken, bron, door, opmerking)
    values ('kiepen', s, p_partij, p_aantal, 'koelcel', wie, 'uit ' || p_cel) returning id into r;
  -- eerst de gescande boxen van deze partij die los in deze koelcel staan
  for b in select e.* from public.etiketten e
            where e.soort = 'box' and e.partij_id = p_partij and e.gekiept_op is null and e.op_pallet is null
              and public.etiket_cel(e.code) = p_cel order by e.nr limit p_aantal loop
    perform public.scan_box_boek(b, null, null, wie);
    update public.etiketten set gekiept_op = now() where id = b.id;
    insert into public.scan_log (code, actie, van, naar, partij_id, melding, door)
      values (b.code, 'gekiept', p_cel, 'kiep', p_partij, format('🧺 Box %s gekiept (kieplijst)', b.nr), wie);
    k := k + 1;
  end loop;
  -- de rest als gewone kuubskisten uit de koelcel
  if p_aantal - k > 0 then
    select m.per_eenheid into per from public.partij_mutaties m
      where m.partij_id = p_partij and m.koelcel = p_cel and m.eenheid = 'kuubskisten' and m.per_eenheid is not null order by m.created_at desc limit 1;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, notitie, door)
      values (p_partij, s, 'uit', p_aantal - k, 'kuubskisten', per, p_cel, 'gekiept', wie);
  end if;
  return jsonb_build_object('res_id', r, 'gekiept', p_aantal, 'boxen', k);
end $$;
revoke all on function public.kiep_uit_koelcel(uuid, text, integer) from public, anon;
grant execute on function public.kiep_uit_koelcel(uuid, text, integer) to authenticated;

-- "oeps, terug": eigen kiep van het laatste halfuur ongedaan maken (kisten gaan terug in de koelcel)
create or replace function public.kiep_koelcel_terug(p_res uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare r public.res_invoer; cel text;
begin
  select * into r from public.res_invoer where id = p_res and soort = 'kiepen' and bron = 'koelcel';
  if not found then raise exception 'Die kiep is niet (meer) gevonden'; end if;
  if not (public.is_beheerder() or (r.user_id = auth.uid() and r.created_at > now() - interval '30 minutes')) then
    raise exception 'Alleen je eigen kiep van het laatste halfuur kun je terugzetten';
  end if;
  cel := substr(r.opmerking, 5);
  -- boxen die bij deze kiep hoorden weer terug
  update public.etiketten e set gekiept_op = null
    where e.partij_id = r.partij_id and e.code in (select l.code from public.scan_log l where l.actie = 'gekiept' and l.created_at = r.created_at and l.partij_id = r.partij_id);
  delete from public.scan_log l where l.actie = 'gekiept' and l.created_at = r.created_at and l.partij_id = r.partij_id;
  delete from public.partij_mutaties m where m.partij_id = r.partij_id and m.soort = 'uit' and m.koelcel = cel and m.created_at = r.created_at;
  delete from public.res_invoer where id = r.id;
end $$;
revoke all on function public.kiep_koelcel_terug(uuid) from public, anon;
grant execute on function public.kiep_koelcel_terug(uuid) to authenticated;
-- =====================================================================
-- OFFLINE OP DE TABLET (25 november 2026)
-- Scannen en kiepen zonder bereik worden op de tablet bewaard en later verstuurd.
-- Elke opdracht krijgt een eigen sleutel: komt hij twee keer binnen (antwoord ging verloren), dan wordt hij maar één keer geboekt.
-- Draai eerst heftruck-scannen.sql en kiep-uit-koelcel.sql (als dat nog niet gebeurd is).
-- =====================================================================
create table if not exists public.verwerkt (
  sleutel    text primary key,
  resultaat  jsonb,
  created_at timestamptz not null default now()
);
alter table public.verwerkt enable row level security;   -- alleen via de functies hieronder
revoke all on public.verwerkt from anon, authenticated;
do $$ begin
  perform cron.schedule('verwerkt_opruimen', '17 3 * * *', $c$delete from public.verwerkt where created_at < now() - interval '30 days'$c$);
exception when others then null; end $$;

drop function if exists public.scan_boek(text, text[], text);
drop function if exists public.kiep_uit_koelcel(uuid, text, integer);

create or replace function public.scan_boek(p_actie text, p_codes text[], p_doel text default null, p_sleutel text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare c text; r jsonb := '[]'::jsonb; m text; wie text; oud jsonb;
begin
  -- dezelfde opdracht nog een keer (verstuurd zonder bereik, antwoord kwam niet aan): niet opnieuw boeken
  if p_sleutel is not null then select resultaat into oud from public.verwerkt where sleutel = p_sleutel; if found then return oud; end if; end if;
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_actie not in ('koelcel', 'kiep', 'pallet_op', 'pallet_af') then raise exception 'Onbekende actie'; end if;
  if p_actie <> 'kiep' and coalesce(trim(p_doel), '') = '' then raise exception 'Geen koelcel of pallet gekozen'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  foreach c in array coalesce(p_codes, '{}') loop
    begin
      m := public.scan_een(p_actie, c, nullif(trim(p_doel), ''), wie);
      r := r || jsonb_build_object('code', upper(trim(c)), 'ok', true, 'melding', m);
    exception when others then
      r := r || jsonb_build_object('code', upper(trim(c)), 'ok', false, 'melding', regexp_replace(sqlerrm, '^RES: ', ''));
    end;
  end loop;
  if p_sleutel is not null then insert into public.verwerkt (sleutel, resultaat) values (p_sleutel, r) on conflict do nothing; end if;
  return r;
end $$;
revoke all on function public.scan_boek(text, text[], text, text) from public, anon;
grant execute on function public.scan_boek(text, text[], text, text) to authenticated;

create or replace function public.kiep_uit_koelcel(p_partij uuid, p_cel text, p_aantal integer, p_sleutel text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare wie text; beschikbaar numeric; k integer := 0; b public.etiketten; s uuid; per numeric; r uuid; oud jsonb; uitk jsonb;
begin
  if p_sleutel is not null then select resultaat into oud from public.verwerkt where sleutel = p_sleutel; if found then return oud; end if; end if;
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_aantal is null or p_aantal < 1 or p_aantal > 500 then raise exception 'Kies een aantal tussen 1 en 500'; end if;
  if coalesce(trim(p_cel), '') = '' then raise exception 'Geen koelcel gekozen'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  select coalesce(sum(public.mut_netto(m.soort, m.aantal)), 0) into beschikbaar
    from public.partij_mutaties m where m.partij_id = p_partij and m.koelcel = p_cel and m.eenheid = 'kuubskisten';
  if beschikbaar < p_aantal - 0.001 then
    raise exception 'In % staan maar % kuubskisten van deze partij', p_cel, trim(to_char(beschikbaar, 'FM999990.##'));
  end if;
  select seizoen_id into s from public.partijen where id = p_partij;
  insert into public.res_invoer (soort, seizoen_id, partij_id, bakken, bron, door, opmerking)
    values ('kiepen', s, p_partij, p_aantal, 'koelcel', wie, 'uit ' || p_cel) returning id into r;
  -- eerst de gescande boxen van deze partij die los in deze koelcel staan
  for b in select e.* from public.etiketten e
            where e.soort = 'box' and e.partij_id = p_partij and e.gekiept_op is null and e.op_pallet is null
              and public.etiket_cel(e.code) = p_cel order by e.nr limit p_aantal loop
    perform public.scan_box_boek(b, null, null, wie);
    update public.etiketten set gekiept_op = now() where id = b.id;
    insert into public.scan_log (code, actie, van, naar, partij_id, melding, door)
      values (b.code, 'gekiept', p_cel, 'kiep', p_partij, format('🧺 Box %s gekiept (kieplijst)', b.nr), wie);
    k := k + 1;
  end loop;
  -- de rest als gewone kuubskisten uit de koelcel
  if p_aantal - k > 0 then
    select m.per_eenheid into per from public.partij_mutaties m
      where m.partij_id = p_partij and m.koelcel = p_cel and m.eenheid = 'kuubskisten' and m.per_eenheid is not null order by m.created_at desc limit 1;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, notitie, door)
      values (p_partij, s, 'uit', p_aantal - k, 'kuubskisten', per, p_cel, 'gekiept', wie);
  end if;
  uitk := jsonb_build_object('res_id', r, 'gekiept', p_aantal, 'boxen', k);
  if p_sleutel is not null then insert into public.verwerkt (sleutel, resultaat) values (p_sleutel, uitk) on conflict do nothing; end if;
  return uitk;
end $$;
revoke all on function public.kiep_uit_koelcel(uuid, text, integer, text) from public, anon;
grant execute on function public.kiep_uit_koelcel(uuid, text, integer, text) to authenticated;
-- =====================================================================
-- KISTKAARTEN / PLANTENPASPOORT (25 november 2026)
-- In de app zet je kistkaarten klaar (partij, sortering, categorie, aantal per kist, aantal kaartjes).
-- Het printprogramma op app01 (kistkaart-print.ps1) haalt ze op, schrijft ze naar een bestandje voor BarTender
-- en meldt terug wanneer ze geprint zijn. De barcode is per batch + sortering: K260018-A2+
-- =====================================================================
create table if not exists public.kistkaart_opdrachten (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  door        text,
  user_id     uuid default auth.uid(),
  sjabloon    text not null default 'standaard' check (sjabloon in ('standaard', 'cac', 'vgs')),
  partij_id   uuid references public.partijen(id) on delete set null,
  ras         text not null,
  sortering   text,
  partij_nr   text not null,
  plantjaar   integer,
  registratie text,
  certificaat text,
  categorie   text,
  afgifte     text,               -- week en jaar van printen, bijv. '48 2026'
  per_kist    integer,
  aantal      integer not null check (aantal between 1 and 2000),   -- aantal kaartjes
  barcode     text not null,
  status      text not null default 'klaar' check (status in ('klaar', 'klaargezet', 'geprint', 'fout', 'weg')),
  melding     text,
  geprint_op  timestamptz
);
create index if not exists kistkaart_status on public.kistkaart_opdrachten (status, created_at);
alter table public.kistkaart_opdrachten enable row level security;
grant select, insert, update on public.kistkaart_opdrachten to authenticated;
drop policy if exists "lezen" on public.kistkaart_opdrachten;
create policy "lezen" on public.kistkaart_opdrachten for select to authenticated
  using (public.heeft_recht('etiketten_printen') or public.is_beheerder());
drop policy if exists "maken" on public.kistkaart_opdrachten;
create policy "maken" on public.kistkaart_opdrachten for insert to authenticated
  with check (public.heeft_recht('etiketten_printen') or public.is_beheerder());
drop policy if exists "bijwerken" on public.kistkaart_opdrachten;
create policy "bijwerken" on public.kistkaart_opdrachten for update to authenticated
  using (public.heeft_recht('etiketten_printen') or public.is_beheerder())
  with check (public.heeft_recht('etiketten_printen') or public.is_beheerder());
do $$ begin alter publication supabase_realtime add table public.kistkaart_opdrachten; exception when duplicate_object then null; when undefined_object then null; end $$;

-- geheime sleutel voor het printprogramma
create table if not exists public.kistkaart_koppeling (
  id integer primary key default 1 check (id = 1),
  sleutel uuid not null default gen_random_uuid(),
  laatst_gezien timestamptz,
  info text
);
alter table public.kistkaart_koppeling enable row level security;
revoke all on public.kistkaart_koppeling from anon, authenticated;
insert into public.kistkaart_koppeling (id) values (1) on conflict do nothing;

-- de beheerder haalt de sleutel op (voor het downloaden van het printprogramma) en ziet wanneer het voor het laatst draaide
create or replace function public.kistkaart_sleutel() returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder'; end if;
  return (select jsonb_build_object('sleutel', sleutel, 'laatst_gezien', laatst_gezien, 'info', info) from public.kistkaart_koppeling where id = 1);
end $$;
revoke all on function public.kistkaart_sleutel() from public, anon;
grant execute on function public.kistkaart_sleutel() to authenticated;

-- iedereen met het recht ziet of het printprogramma draait
create or replace function public.kistkaart_status() returns timestamptz
language sql stable security definer set search_path = '' as $$
  select laatst_gezien from public.kistkaart_koppeling where id = 1 and (public.heeft_recht('etiketten_printen') or public.is_beheerder());
$$;
revoke all on function public.kistkaart_status() from public, anon;
grant execute on function public.kistkaart_status() to authenticated;

-- het printprogramma: openstaande opdrachten ophalen
create or replace function public.kistkaart_ophalen(p_sleutel uuid, p_info text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.kistkaart_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  update public.kistkaart_koppeling set laatst_gezien = now(), info = coalesce(p_info, info) where id = 1;
  return coalesce((select jsonb_agg(to_jsonb(k) order by k.created_at) from public.kistkaart_opdrachten k where k.status in ('klaar', 'klaargezet')), '[]'::jsonb);
end $$;
revoke all on function public.kistkaart_ophalen(uuid, text) from public;
grant execute on function public.kistkaart_ophalen(uuid, text) to anon, authenticated;

-- het printprogramma: status terugmelden (klaargezet = in het bestandje voor BarTender, geprint, fout)
create or replace function public.kistkaart_melden(p_sleutel uuid, p_ids uuid[], p_status text, p_melding text default null) returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.kistkaart_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  if p_status not in ('klaargezet', 'geprint', 'fout') then raise exception 'Onbekende status'; end if;
  update public.kistkaart_opdrachten set status = p_status, melding = p_melding,
         geprint_op = case when p_status = 'geprint' then now() else geprint_op end
   where id = any(p_ids) and status in ('klaar', 'klaargezet', 'fout');
  get diagnostics n = row_count; return n;
end $$;
revoke all on function public.kistkaart_melden(uuid, uuid[], text, text) from public;
grant execute on function public.kistkaart_melden(uuid, uuid[], text, text) to anon, authenticated;
-- =====================================================================
-- NAAR HET VELD (25 november 2026)
-- Uit de koelcel kan nu ook "naar het veld" (bijv. om te poten), naast levering en uitval.
-- =====================================================================
alter table public.partij_mutaties drop constraint if exists partij_mutaties_soort_check;
alter table public.partij_mutaties add constraint partij_mutaties_soort_check check (soort in ('in', 'uit', 'uitval', 'correctie', 'veld'));
alter table public.partij_mutaties add column if not exists perceel_id uuid references public.percelen(id) on delete set null;   -- naar welk perceel
-- =====================================================================
-- ORDERS OP DE HEFTRUCK + KIEPPLANNING (25 november 2026)
--  · orders: ook "naar het veld" (met perceel), per regel klaarzetten en (deels) uitleveren op de heftruck-tablet
--  · kiepplanning: op de computer invullen wat er gekiept/gesorteerd moet worden; de heftruck ziet het op de kieplijst
-- =====================================================================
alter table public.voorraad_bestemmingen add column if not exists perceel_id uuid references public.percelen(id) on delete set null;
alter table public.voorraad_reserveringen add column if not exists klaargezet boolean not null default false;
alter table public.voorraad_reserveringen add column if not exists geleverd numeric not null default 0;   -- planten die al (deels) uitgeleverd zijn
alter table public.partij_mutaties add column if not exists bestemming_id uuid references public.voorraad_bestemmingen(id) on delete set null;

create table if not exists public.kiep_planning (
  id          uuid primary key default gen_random_uuid(),
  datum       date not null default current_date,
  volgorde    integer not null default 0,
  partij_id   uuid not null references public.partijen(id) on delete cascade,
  aantal      numeric,                 -- hoeveel bakken / kisten
  koelcel     text,                    -- waar ze staan (leeg = van het veld)
  notitie     text,
  klaar       boolean not null default false,
  door        text,
  created_at  timestamptz not null default now()
);
create index if not exists kiep_planning_datum on public.kiep_planning (datum, volgorde);
alter table public.kiep_planning enable row level security;
grant select, insert, update, delete on public.kiep_planning to authenticated;
drop policy if exists "lezen" on public.kiep_planning;
create policy "lezen" on public.kiep_planning for select to authenticated using (true);
drop policy if exists "schrijven" on public.kiep_planning;
create policy "schrijven" on public.kiep_planning for all to authenticated
  using (public.heeft_recht('resultaten_beheren') or public.heeft_recht('voorraad_beheren') or public.is_beheerder())
  with check (public.heeft_recht('resultaten_beheren') or public.heeft_recht('voorraad_beheren') or public.is_beheerder());
do $$ begin alter publication supabase_realtime add table public.kiep_planning; exception when duplicate_object then null; when undefined_object then null; end $$;

-- Kiepen van bakken die in de koelcel stonden (gescand of vanaf de kieplijst), terwijl het rooien niet (volledig)
-- geregistreerd was: dan het ontbrekende rooien automatisch bijboeken in plaats van te weigeren.
-- Bij met de hand tikken op de bakken van het veld blijft de controle gewoon staan.
create or replace function public.res_controle() returns trigger
language plpgsql security definer set search_path = '' as $$
declare gerooid numeric; gekiept numeric;
begin
  if new.seizoen_id is null then select seizoen_id into new.seizoen_id from public.partijen where id = new.partij_id; end if;
  if new.door is null then new.door := coalesce((select naam from public.profielen where id = auth.uid()), 'onbekend'); end if;
  if new.correctie_van is not null and coalesce(trim(new.reden), '') = '' then raise exception 'RES: bij een correctie hoort een reden'; end if;
  if new.soort = 'kiepen' then
    select coalesce(sum(bakken), 0) into gerooid from public.res_invoer where partij_id = new.partij_id and soort = 'rooien';
    select coalesce(sum(bakken), 0) into gekiept from public.res_invoer where partij_id = new.partij_id and soort = 'kiepen';
    if gekiept + coalesce(new.bakken, 0) > gerooid then
      if new.bron in ('scan', 'koelcel') then
        insert into public.res_invoer (soort, seizoen_id, partij_id, bakken, bron, door, opmerking)
          values ('rooien', new.seizoen_id, new.partij_id, gekiept + coalesce(new.bakken, 0) - gerooid, 'koelcel', new.door,
                  'Automatisch: deze bakken stonden in de koelcel, maar het rooien was niet geregistreerd');
      else
        raise exception 'RES: er kunnen niet meer bakken gekiept worden dan er gerooid zijn (gerooid %, al gekiept %)', gerooid, gekiept;
      end if;
    end if;
  end if;
  return new;
end $$;
-- =====================================================================
-- KIEP TERUGDRAAIEN (25 november 2026)
-- "↶ Oeps" na een scan-kiep zet de box nu helemaal terug: weer in de koelcel (en op de pallet), niet meer gekiept,
-- en het automatisch bijgeboekte rooien gaat ook weg. Boxen die met de oude versie al waren teruggedraaid,
-- kun je gewoon weer in een koelcel scannen.
-- =====================================================================
create or replace function public.scan_een(p_actie text, p_code text, p_doel text, p_door text) returns text
language plpgsql security definer set search_path = '' as $$
declare e public.etiketten; pe public.etiketten; b public.etiketten; cur text; n integer; msg text; nb integer := 0;
begin
  select * into e from public.etiketten where code = upper(trim(p_code));
  if not found then raise exception '% niet gevonden', p_code; end if;
  cur := public.etiket_cel(e.code);

  if p_actie = 'koelcel' then
    if e.soort = 'box' then
      -- gekiept, maar die kiep is later teruggedraaid (oude versie zette hem niet terug): weer vrijgeven
      if e.gekiept_op is not null and not exists (select 1 from public.res_invoer ri where ri.soort = 'kiepen' and ri.partij_id = e.partij_id and ri.opmerking = 'Box ' || e.nr) then
        update public.etiketten set gekiept_op = null where id = e.id; e.gekiept_op := null;
      end if;
      if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
      if cur is not distinct from p_doel then
        perform public.scan_box_boek(e, null, null, p_door);
        update public.etiketten set op_pallet = null where id = e.id;
        msg := format('⬆️ Box %s uit %s', e.nr, p_doel);
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'uit', cur, null, e.partij_id, msg, p_door);
      else
        perform public.scan_box_boek(e, p_doel, null, p_door);
        update public.etiketten set op_pallet = null where id = e.id;
        msg := case when cur is null then format('⬇️ Box %s in %s', e.nr, p_doel) else format('↔ Box %s: %s → %s', e.nr, cur, p_doel) end;
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, case when cur is null then 'in' else 'verplaatst' end, cur, p_doel, e.partij_id, msg, p_door);
      end if;
    else
      if cur is not distinct from p_doel then
        for b in select * from public.etiketten where op_pallet = e.code loop perform public.scan_box_boek(b, null, null, p_door); nb := nb + 1; end loop;
        perform public.scan_pallet_boek(e, null, p_door);
        msg := format('⬆️ Pallet %s uit %s', e.nr, p_doel);
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'uit', cur, null, e.partij_id, msg, p_door);
      else
        for b in select * from public.etiketten where op_pallet = e.code and gekiept_op is null loop perform public.scan_box_boek(b, p_doel, e.nr::text, p_door); nb := nb + 1; end loop;
        perform public.scan_pallet_boek(e, p_doel, p_door);
        msg := case when cur is null then format('⬇️ Pallet %s in %s', e.nr, p_doel) else format('↔ Pallet %s: %s → %s', e.nr, cur, p_doel) end
               || case when nb > 0 then format(' (%s kistjes/boxen)', nb) else '' end;
        insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, case when cur is null then 'in' else 'verplaatst' end, cur, p_doel, e.partij_id, msg, p_door);
      end if;
    end if;
    return msg;
  end if;

  if p_actie = 'kiep' then
    if e.soort = 'pallet' then
      for b in select * from public.etiketten where op_pallet = e.code and gekiept_op is null loop
        perform public.scan_een('kiep', b.code, null, p_door); nb := nb + 1;
      end loop;
      if nb = 0 then raise exception 'Op pallet % staan geen gescande bakken; scan de bakken zelf', e.nr; end if;
      return format('🧺 Pallet %s: %s %s gekiept', e.nr, nb, case when nb = 1 then 'bak' else 'bakken' end);
    end if;
    if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
    if e.partij_id is null then raise exception 'Box % is niet aan een partij gekoppeld', e.nr; end if;
    insert into public.res_invoer (soort, partij_id, bakken, bron, door, opmerking) values ('kiepen', e.partij_id, 1, 'scan', p_door, 'Box ' || e.nr);
    perform public.scan_box_boek(e, null, null, p_door);
    update public.etiketten set gekiept_op = now(), op_pallet = null where id = e.id;
    msg := format('🧺 Box %s gekiept', e.nr);
    insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'gekiept', cur, 'kiep', e.partij_id, msg, p_door);
    return msg;
  end if;

  if p_actie in ('pallet_op', 'pallet_af') then
    select * into pe from public.etiketten where code = upper(trim(p_doel)) and soort = 'pallet';
    if not found then raise exception 'Pallet % niet gevonden', p_doel; end if;
    if e.soort <> 'box' then raise exception 'Op een pallet kun je alleen kistjes/boxen zetten'; end if;
    if p_actie = 'pallet_op' then
      if e.gekiept_op is not null then raise exception 'Box % is al gekiept', e.nr; end if;
      if e.op_pallet = pe.code then return format('✓ Box %s stond al op pallet %s', e.nr, pe.nr); end if;
      update public.etiketten set op_pallet = pe.code where id = e.id;
      -- staat de pallet (of de box) al in een koelcel, dan gaat de box mee naar de pallet
      if coalesce(public.etiket_cel(pe.code), cur) is not null then
        perform public.scan_box_boek(e, coalesce(public.etiket_cel(pe.code), cur), pe.nr::text, p_door);
      end if;
      msg := format('➕ Box %s op pallet %s', e.nr, pe.nr);
      insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'op_pallet', null, pe.code, e.partij_id, msg, p_door);
    else
      if e.op_pallet is distinct from pe.code then raise exception 'Box % staat niet op pallet %', e.nr, pe.nr; end if;
      update public.etiketten set op_pallet = null where id = e.id;
      if cur is not null then perform public.scan_box_boek(e, cur, null, p_door); end if;
      msg := format('➖ Box %s van pallet %s gehaald', e.nr, pe.nr);
      insert into public.scan_log (code, actie, van, naar, partij_id, melding, door) values (e.code, 'van_pallet', pe.code, null, e.partij_id, msg, p_door);
    end if;
    return msg;
  end if;
  raise exception 'Onbekende actie %', p_actie;
end $$;
revoke all on function public.scan_een(text, text, text, text) from public, anon, authenticated;

create or replace function public.kiep_koelcel_terug(p_res uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare r public.res_invoer; cel text; m record; boxnr text;
begin
  select * into r from public.res_invoer where id = p_res and soort = 'kiepen' and bron in ('koelcel', 'scan');
  if not found then raise exception 'Die kiep is niet (meer) gevonden'; end if;
  if not (public.is_beheerder() or (r.user_id = auth.uid() and r.created_at > now() - interval '30 minutes')) then
    raise exception 'Alleen je eigen kiep van het laatste halfuur kun je terugzetten';
  end if;
  if r.bron = 'scan' then
    -- één box: zijn uit-boeking van dat moment terugdraaien, en weer op de pallet als hij erop stond
    boxnr := substr(r.opmerking, 5);
    for m in select * from public.partij_mutaties where partij_id = r.partij_id and soort = 'uit' and notitie = r.opmerking and created_at = r.created_at loop
      update public.etiketten set op_pallet = case when m.pallet is not null then 'P' || m.pallet else op_pallet end where soort = 'box' and etiketten.nr::text = boxnr;
    end loop;
    delete from public.partij_mutaties where partij_id = r.partij_id and soort = 'uit' and notitie = r.opmerking and created_at = r.created_at;
    update public.etiketten set gekiept_op = null where soort = 'box' and etiketten.nr::text = boxnr;
    delete from public.scan_log where actie = 'gekiept' and code = 'B' || boxnr and created_at = r.created_at;
  else
    cel := substr(r.opmerking, 5);
    update public.etiketten e set gekiept_op = null
      where e.partij_id = r.partij_id and e.code in (select l.code from public.scan_log l where l.actie = 'gekiept' and l.created_at = r.created_at and l.partij_id = r.partij_id);
    delete from public.scan_log l where l.actie = 'gekiept' and l.created_at = r.created_at and l.partij_id = r.partij_id;
    delete from public.partij_mutaties m2 where m2.partij_id = r.partij_id and m2.soort = 'uit' and m2.koelcel = cel and m2.created_at = r.created_at;
  end if;
  -- het rooien dat er bij deze kiep automatisch bij geboekt werd, ook weer weg
  delete from public.res_invoer where partij_id = r.partij_id and soort = 'rooien' and bron = 'koelcel' and created_at = r.created_at;
  delete from public.res_invoer where id = r.id;
end $$;
revoke all on function public.kiep_koelcel_terug(uuid) from public, anon;
grant execute on function public.kiep_koelcel_terug(uuid) to authenticated;

-- =====================================================================
-- VOORRAAD ERUIT HALEN: gescande boxen gaan mee (25 november 2026)
-- Levering, uitval of naar het veld van kuubskisten/kistjes uit een koelcel: eerst de gescande boxen (B-kaartjes)
-- van die partij in die koelcel, de rest als gewone kisten. Zo zegt een box nooit meer dat hij in een koelcel
-- staat terwijl hij al weg is. Draai eerst naar-het-veld.sql en orders-kiepplanning.sql.
-- Onderaan: eenmalige reparatie van boxen die nu nog ten onrechte in een koelcel staan.
-- =====================================================================
create or replace function public.voorraad_eruit(
  p_partij uuid, p_cel text, p_eenheid text, p_pallet text, p_soort text, p_aantal numeric, p_per numeric default null,
  p_datum date default null, p_klant text default null, p_pakbon text default null, p_prijs numeric default null, p_notitie text default null,
  p_perceel uuid default null, p_bestemming uuid default null, p_sleutel text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare wie text; s uuid; b public.etiketten; k integer := 0; rest numeric; oud jsonb; uitk jsonb; beschikbaar numeric;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_sleutel is not null then select resultaat into oud from public.verwerkt where sleutel = p_sleutel; if found then return oud; end if; end if;
  if p_soort not in ('uit', 'uitval', 'veld') then raise exception 'Onbekende soort'; end if;
  if p_aantal is null or p_aantal <= 0 then raise exception 'Vul het aantal in'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  select seizoen_id into s from public.partijen where id = p_partij;
  -- p_pallet = '*': maakt niet uit van welke pallet (orders op de heftruck)
  select coalesce(sum(public.mut_netto(m.soort, m.aantal)), 0) into beschikbaar from public.partij_mutaties m
   where m.partij_id = p_partij and m.koelcel is not distinct from p_cel and m.eenheid = p_eenheid and (p_pallet = '*' or m.pallet is not distinct from p_pallet);
  if p_pallet is distinct from '*' and beschikbaar < p_aantal - 0.001 then raise exception 'Er staan maar % % van deze partij', trim(to_char(beschikbaar, 'FM999990.##')), p_eenheid; end if;
  -- hele kisten: eerst de gescande boxen
  if p_eenheid in ('kuubskisten', 'kistjes') and p_cel is not null then
    for b in select e.* from public.etiketten e
              where e.soort = 'box' and e.partij_id = p_partij and e.gekiept_op is null
                and public.etiket_cel(e.code) = p_cel
                and exists (select 1 from public.partij_mutaties m where m.notitie = 'Box ' || e.nr and m.eenheid = p_eenheid and (p_pallet = '*' or m.pallet is not distinct from p_pallet))
              order by e.nr limit floor(p_aantal) loop
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, datum, aantal, eenheid, per_eenheid, koelcel, pallet, klant, pakbon, prijs, notitie, door, perceel_id, bestemming_id)
        values (p_partij, s, p_soort, coalesce(p_datum, current_date), 1, p_eenheid, p_per, p_cel,
                case when p_pallet = '*' then (select m.pallet from public.partij_mutaties m where m.notitie = 'Box ' || b.nr order by m.created_at desc limit 1) else p_pallet end,
                p_klant, p_pakbon, p_prijs, 'Box ' || b.nr, wie, p_perceel, p_bestemming);
      update public.etiketten set op_pallet = null where id = b.id;
      insert into public.scan_log (code, actie, van, naar, partij_id, melding, door)
        values (b.code, 'uit', p_cel, p_soort, p_partij, format('⬆️ Box %s %s', b.nr, case p_soort when 'uitval' then 'uitval' when 'veld' then 'naar het veld' else 'geleverd' end), wie);
      k := k + 1;
    end loop;
  end if;
  rest := p_aantal - k;
  if rest > 0.00001 then
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, datum, aantal, eenheid, per_eenheid, koelcel, pallet, klant, pakbon, prijs, notitie, door, perceel_id, bestemming_id)
      values (p_partij, s, p_soort, coalesce(p_datum, current_date), rest, p_eenheid, p_per, p_cel, nullif(p_pallet, '*'), p_klant, p_pakbon, p_prijs, p_notitie, wie, p_perceel, p_bestemming);
  end if;
  uitk := jsonb_build_object('boxen', k, 'aantal', p_aantal);
  if p_sleutel is not null then insert into public.verwerkt (sleutel, resultaat) values (p_sleutel, uitk) on conflict do nothing; end if;
  return uitk;
end $$;
revoke all on function public.voorraad_eruit(uuid, text, text, text, text, numeric, numeric, date, text, text, numeric, text, uuid, uuid, text) from public, anon;
grant execute on function public.voorraad_eruit(uuid, text, text, text, text, numeric, numeric, date, text, text, numeric, text, uuid, uuid, text) to authenticated;

-- eenmalige reparatie: staan er van een partij in een koelcel meer gescande boxen dan er in totaal nog kisten zijn,
-- dan de overtollige boxen uit de koelcel halen (het totaal blijft gelijk)
do $$
declare r record; b public.etiketten; teveel integer;
begin
  for r in select m.partij_id, m.koelcel, m.eenheid,
                  sum(public.mut_netto(m.soort, m.aantal)) as tot,
                  sum(public.mut_netto(m.soort, m.aantal)) filter (where m.notitie like 'Box %') as boxen
             from public.partij_mutaties m where m.koelcel is not null and m.eenheid in ('kuubskisten', 'kistjes')
            group by m.partij_id, m.koelcel, m.eenheid
           having coalesce(sum(public.mut_netto(m.soort, m.aantal)) filter (where m.notitie like 'Box %'), 0) > greatest(sum(public.mut_netto(m.soort, m.aantal)), 0) + 0.001 loop
    teveel := ceil(r.boxen - greatest(r.tot, 0));
    for b in select e.* from public.etiketten e where e.soort = 'box' and e.partij_id = r.partij_id and public.etiket_cel(e.code) = r.koelcel order by e.nr desc limit teveel loop
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, koelcel, pallet, notitie, door)
        select r.partij_id, p.seizoen_id, 'correctie', -1, r.eenheid, r.koelcel, (select m2.pallet from public.partij_mutaties m2 where m2.notitie = 'Box ' || b.nr order by m2.created_at desc limit 1), 'Box ' || b.nr, 'reparatie' from public.partijen p where p.id = r.partij_id;
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, koelcel, notitie, door)
        select r.partij_id, p.seizoen_id, 'correctie', 1, r.eenheid, r.koelcel, 'reparatie: box ' || b.nr || ' was al weg', 'reparatie' from public.partijen p where p.id = r.partij_id;
      update public.etiketten set op_pallet = null where id = b.id;
    end loop;
  end loop;
end $$;

-- =====================================================================
-- KIEP: EEN GEKIEPTE BOX TERUGZETTEN + BAK VAN DE KIEPLIJST HALEN (25 november 2026)
--  · kiep_box_terug('B12'): een box die (per ongeluk) als gekiept staat weer terugzetten, ook later en vanaf elke tablet.
--    Hij komt terug waar hij stond (koelcel / pallet); de kiep telt één bak minder.
--  · kiep_bak_weg(partij): een bak die ten onrechte "van het veld" op de kieplijst staat weghalen.
-- Draai eerst kiep-terug.sql.
-- =====================================================================
create or replace function public.kiep_box_terug(p_code text) returns text
language plpgsql security definer set search_path = '' as $$
declare e public.etiketten; l public.scan_log; r public.res_invoer; m record; cel text; t timestamptz;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.heeft_recht('resultaten_invoeren') or public.heeft_recht('resultaten_beheren') or public.is_beheerder()) then
    raise exception 'Je mag geen kiep terugzetten'; end if;
  select * into e from public.etiketten where code = upper(trim(p_code)) and soort = 'box';
  if not found then raise exception 'Box % niet gevonden', p_code; end if;
  if e.gekiept_op is null then return format('Box %s stond niet als gekiept', e.nr); end if;
  select * into l from public.scan_log where code = e.code and actie = 'gekiept' order by created_at desc limit 1;
  t := coalesce(l.created_at, e.gekiept_op);
  -- de uit-boeking van de box bij het kiepen terugdraaien (en weer op de pallet als hij erop stond)
  for m in select * from public.partij_mutaties where notitie = 'Box ' || e.nr and soort = 'uit' and created_at = t loop
    cel := m.koelcel;
    if m.pallet is not null then update public.etiketten set op_pallet = 'P' || m.pallet where id = e.id; end if;
  end loop;
  delete from public.partij_mutaties where notitie = 'Box ' || e.nr and soort = 'uit' and created_at = t;
  update public.etiketten set gekiept_op = null where id = e.id;
  delete from public.scan_log where code = e.code and actie = 'gekiept' and created_at = t;
  -- de kiep zelf: één bak minder (of helemaal weg), en het automatisch bijgeboekte rooien ook
  select * into r from public.res_invoer where soort = 'kiepen' and partij_id = e.partij_id and created_at = t and bron in ('scan', 'koelcel')
    order by (opmerking = 'Box ' || e.nr) desc limit 1;
  if found then
    if coalesce(r.bakken, 0) > 1 then update public.res_invoer set bakken = bakken - 1 where id = r.id; else delete from public.res_invoer where id = r.id; end if;
    select * into r from public.res_invoer where soort = 'rooien' and bron = 'koelcel' and partij_id = e.partij_id and created_at = t limit 1;
    if found then
      if coalesce(r.bakken, 0) > 1 then update public.res_invoer set bakken = bakken - 1 where id = r.id; else delete from public.res_invoer where id = r.id; end if;
    end if;
  end if;
  insert into public.scan_log (code, actie, van, naar, partij_id, melding, door)
    values (e.code, 'terug', 'kiep', cel, e.partij_id, format('↶ Box %s teruggezet%s', e.nr, coalesce(' in ' || cel, '')),
            coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck'));
  return format('↶ Box %s teruggezet%s', e.nr, coalesce(' in ' || cel, ' (scan nu de koelcel waar hij staat)'));
end $$;
revoke all on function public.kiep_box_terug(text) from public, anon;
grant execute on function public.kiep_box_terug(text) to authenticated;

create or replace function public.kiep_bak_weg(p_partij uuid, p_aantal integer default 1) returns integer
language plpgsql security definer set search_path = '' as $$
declare ger numeric; kiep numeric; r public.res_invoer; n integer := 0; s uuid; wie text;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.heeft_recht('resultaten_invoeren') or public.heeft_recht('resultaten_beheren') or public.is_beheerder()) then
    raise exception 'Je mag de kieplijst niet aanpassen'; end if;
  select coalesce(sum(bakken) filter (where soort = 'rooien'), 0), coalesce(sum(bakken) filter (where soort = 'kiepen'), 0) into ger, kiep
    from public.res_invoer where partij_id = p_partij;
  if ger - kiep < 1 then raise exception 'Er staan van deze partij geen bakken meer op de kieplijst'; end if;
  p_aantal := least(coalesce(p_aantal, 1), floor(ger - kiep)::integer);
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  -- eerst automatisch bijgeboekt rooien opruimen
  while n < p_aantal loop
    select * into r from public.res_invoer where partij_id = p_partij and soort = 'rooien' and bron = 'koelcel' and bakken > 0 order by created_at desc limit 1;
    exit when not found;
    if r.bakken > 1 then update public.res_invoer set bakken = bakken - 1 where id = r.id; else delete from public.res_invoer where id = r.id; end if;
    n := n + 1;
  end loop;
  -- de rest als correctie op het rooien (blijft zichtbaar in het overzicht)
  if n < p_aantal then
    select * into r from public.res_invoer where partij_id = p_partij and soort = 'rooien' and bakken > 0 order by created_at desc limit 1;
    select seizoen_id into s from public.partijen where id = p_partij;
    insert into public.res_invoer (soort, seizoen_id, partij_id, bakken, bron, correctie_van, reden, door)
      values ('rooien', s, p_partij, -(p_aantal - n), 'kiep', r.id, 'Van de kieplijst gehaald: stond er ten onrechte', wie);
    n := p_aantal;
  end if;
  return n;
end $$;
revoke all on function public.kiep_bak_weg(uuid, integer) from public, anon;
grant execute on function public.kiep_bak_weg(uuid, integer) to authenticated;

-- =====================================================================
-- KISTKAARTEN: KLEUR VOLGENS DE KLASSE (25 november 2026)
--   wit   = BM1 t/m BM5 (basismateriaal)           -> sjabloon 'wit'
--   blauw = CM (gecertificeerd), het standaardkaartje -> sjabloon 'standaard'
--   geel  = VGS (ook VGS BM1 t/m BM5) of CAC         -> sjabloon 'vgs' / 'cac'
-- Draai na kistkaarten.sql.
-- =====================================================================
alter table public.kistkaart_opdrachten drop constraint if exists kistkaart_opdrachten_sjabloon_check;
alter table public.kistkaart_opdrachten add constraint kistkaart_opdrachten_sjabloon_check check (sjabloon in ('wit', 'standaard', 'cac', 'vgs'));

-- =====================================================================
-- WIE DEED WAT: SORTEREN PER MEDEWERKER UIT SSOR (25 november 2026)
-- Per medewerker de gesorteerde planten (scans van activiteitengroep 100) en de uren op die activiteiten.
-- Persoonlijke prestaties: alleen met het recht P&O bekijken of resultaten beheren, nooit op een gedeeld apparaat.
-- =====================================================================
create or replace function public.sorteren_mensen(p_van date, p_tot date) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if public.is_apparaat() or not (public.mag_pno() or public.heeft_recht('resultaten_beheren') or public.is_beheerder()) then
    return jsonb_build_object('mag', false);
  end if;
  return jsonb_build_object('mag', true, 'regels', coalesce((
    with acts as (select a.id from public.ssor_activiteiten a join public.ssor_activiteitgroepen g on g.id = a.groep_id where g.nummer = '100'),
    sc as (select e.medewerker_id mw, sum(e.aantal) planten, count(*) scans from public.ssor_eenheden e
            where e.datum between p_van and p_tot and e.activiteit_id in (select id from acts) group by e.medewerker_id),
    ur as (select u.medewerker_id mw, sum(u.uren) uren from public.ssor_uren u
            where u.datum between p_van and p_tot and u.activiteit_id in (select id from acts) group by u.medewerker_id)
    select jsonb_agg(jsonb_build_object('naam', coalesce(m.naam, 'Medewerker ' || coalesce(sc.mw, ur.mw)), 'planten', coalesce(sc.planten, 0),
                                        'scans', coalesce(sc.scans, 0), 'uren', round(coalesce(ur.uren, 0)::numeric, 2)) order by m.naam)
      from sc full join ur on ur.mw = sc.mw left join public.ssor_medewerkers m on m.id = coalesce(sc.mw, ur.mw)), '[]'::jsonb),
    'laatst', (select laatst from public.ssor_koppeling where id = 1));
end $$;
revoke all on function public.sorteren_mensen(date, date) from public, anon;
grant execute on function public.sorteren_mensen(date, date) to authenticated;

-- =====================================================================
-- KISTKAARTEN SCANNEN OP DE HEFTRUCK (25 november 2026)
-- De QR-code op een kistkaart (bijv. K260046-FR-A-400) hoort bij een batch + sortering.
-- De heftruck-tablet zoekt hiermee de partij, sortering en het aantal per kist op.
-- Draai na kistkaarten.sql.
-- =====================================================================
create or replace function public.kistkaart_code(p_barcode text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select to_jsonb(x) from (
    select k.partij_id, k.ras, k.partij_nr, k.sortering, k.per_kist, k.barcode from public.kistkaart_opdrachten k
     where upper(k.barcode) = upper(trim(p_barcode))
       and (public.heeft_recht('voorraad_beheren') or public.heeft_recht('voorraad_bekijken') or public.heeft_recht('etiketten_printen') or public.is_beheerder())
     order by k.created_at desc limit 1) x;
$$;
revoke all on function public.kistkaart_code(text) from public, anon;
grant execute on function public.kistkaart_code(text) to authenticated;

-- =====================================================================
-- PALLET / BOX LEEGMAKEN VANAF DE HEFTRUCK (25 november 2026)
-- etiket_leegmaken('P17') of ('B230'): alles wat er nog op/in staat gaat uit de voorraad (correctie),
-- boxen gaan van de pallet af. Scan je het etiket daarna opnieuw, dan is het leeg en kun je het opnieuw gebruiken.
-- Werkt ook voor een pallet zonder etiket (met de hand ingeslagen): etiket_leegmaken('P17').
-- Draai na heftruck-scannen.sql.
-- =====================================================================
create or replace function public.etiket_leegmaken(p_code text) returns text
language plpgsql security definer set search_path = '' as $$
declare e public.etiketten; r record; s uuid; wie text; n integer := 0; b public.etiketten; v_soort text; v_nr text;
begin
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  select * into e from public.etiketten where code = upper(trim(p_code));
  if found then v_soort := e.soort; v_nr := e.nr::text;
  elsif upper(trim(p_code)) ~ '^P\d+$' then v_soort := 'pallet'; v_nr := substr(upper(trim(p_code)), 2);   -- pallet zonder etiket (met de hand ingeslagen)
  else raise exception 'Etiket % niet gevonden', p_code; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  for r in select m.partij_id, m.koelcel, m.pallet, m.eenheid, case when m.notitie like 'Box %' then m.notitie end notitie, max(m.per_eenheid) per, sum(public.mut_netto(m.soort, m.aantal)) netto
             from public.partij_mutaties m
            where (v_soort = 'pallet' and m.pallet = v_nr) or (v_soort = 'box' and m.notitie = 'Box ' || v_nr)
            group by m.partij_id, m.koelcel, m.pallet, m.eenheid, case when m.notitie like 'Box %' then m.notitie end
           having sum(public.mut_netto(m.soort, m.aantal)) > 0.001 loop
    select seizoen_id into s from public.partijen where id = r.partij_id;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, per_eenheid, koelcel, pallet, notitie, door)
      values (r.partij_id, s, 'correctie', -r.netto, r.eenheid, r.per, r.koelcel, r.pallet,
              case when r.notitie like 'Box %' then r.notitie else '🗑️ ' || case v_soort when 'pallet' then 'P' else 'B' end || v_nr || ' leeggemaakt' end, wie);
    n := n + 1;
  end loop;
  if v_soort = 'pallet' then
    update public.etiketten set op_pallet = null where op_pallet = 'P' || v_nr;
    if e.id is not null then update public.etiketten set data = coalesce(data, '{}'::jsonb) - 'kistjes' where id = e.id; end if;   -- niet opnieuw vanzelf inslaan
  else
    update public.etiketten set op_pallet = null where id = e.id;
  end if;
  insert into public.scan_log (code, actie, van, naar, partij_id, melding, door)
    values (case v_soort when 'pallet' then 'P' else 'B' end || v_nr, 'leeg', null, null, e.partij_id, format('🗑️ %s %s leeggemaakt', case v_soort when 'pallet' then 'Pallet' else 'Box' end, v_nr), wie);
  return format('🗑️ %s %s is leeg%s', case v_soort when 'pallet' then 'Pallet' else 'Box' end, v_nr, case when n = 0 then ' (er stond niets op)' else '' end);
end $$;
revoke all on function public.etiket_leegmaken(text) from public, anon;
grant execute on function public.etiket_leegmaken(text) to authenticated;

-- =====================================================================
-- BOXEN HERSTELLEN (25 november 2026) – mag je vaker draaien
-- Een gescande box (kuubskist) die volgens de scans nog in een koelcel staat, terwijl die koelcel van die partij
-- (bijna) niets meer heeft, wordt uit die koelcel gehaald. Het totaal van de voorraad blijft gelijk.
-- Daarna zegt een box nooit meer "staat in Koelcel 4" als hij daar niet te zien is.
-- =====================================================================
-- eenmalige reparatie: staan er van een partij in een koelcel meer gescande boxen dan er in totaal nog kisten zijn,
-- dan de overtollige boxen uit de koelcel halen (het totaal blijft gelijk)
do $$
declare r record; b public.etiketten; teveel integer;
begin
  for r in select m.partij_id, m.koelcel, m.eenheid,
                  sum(public.mut_netto(m.soort, m.aantal)) as tot,
                  sum(public.mut_netto(m.soort, m.aantal)) filter (where m.notitie like 'Box %') as boxen
             from public.partij_mutaties m where m.koelcel is not null and m.eenheid in ('kuubskisten', 'kistjes')
            group by m.partij_id, m.koelcel, m.eenheid
           having coalesce(sum(public.mut_netto(m.soort, m.aantal)) filter (where m.notitie like 'Box %'), 0) > greatest(sum(public.mut_netto(m.soort, m.aantal)), 0) + 0.001 loop
    teveel := ceil(r.boxen - greatest(r.tot, 0));
    for b in select e.* from public.etiketten e where e.soort = 'box' and e.partij_id = r.partij_id and public.etiket_cel(e.code) = r.koelcel order by e.nr desc limit teveel loop
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, koelcel, pallet, notitie, door)
        select r.partij_id, p.seizoen_id, 'correctie', -1, r.eenheid, r.koelcel, (select m2.pallet from public.partij_mutaties m2 where m2.notitie = 'Box ' || b.nr order by m2.created_at desc limit 1), 'Box ' || b.nr, 'reparatie' from public.partijen p where p.id = r.partij_id;
      insert into public.partij_mutaties (partij_id, seizoen_id, soort, aantal, eenheid, koelcel, notitie, door)
        select r.partij_id, p.seizoen_id, 'correctie', 1, r.eenheid, r.koelcel, 'reparatie: box ' || b.nr || ' was al weg', 'reparatie' from public.partijen p where p.id = r.partij_id;
      update public.etiketten set op_pallet = null where id = b.id;
    end loop;
  end loop;
end $$;

-- =====================================================================
-- EXACT ONLINE KOPPELING (26 november 2026)
-- Alles uit Exact Online wordt (alleen lezen) in de app gezet: relaties, artikelen, verkooporders, facturen, leveringen,
-- inkoop, voorraad, grootboek en boekingen, projecten ... De Edge Function "exact" haalt het op (elke 15 minuten wat er
-- veranderd is) en zet het in exact_data. Wat er opgehaald wordt staat in exact_onderdelen (aan/uit te zetten).
-- Zien: alleen beheerders en mensen met het recht "Exact Online bekijken", nooit op een gedeeld apparaat.
-- Salarissen en personeelsgegevens (Payroll/HRM) worden NIET opgehaald.
-- =====================================================================
create table if not exists public.exact_koppeling (
  id           integer primary key default 1 check (id = 1),
  access_token text,
  refresh_token text,
  verloopt_op  timestamptz,
  division     integer,
  divisie_naam text,
  staat        text,                      -- tijdelijk, tijdens het inloggen bij Exact
  sync_sleutel uuid not null default gen_random_uuid(),
  bezig_tot    timestamptz,
  laatst       timestamptz,
  aanroepen_dag date,
  aanroepen    integer not null default 0,
  fout         text,
  gekoppeld_door text,
  gekoppeld_op timestamptz
);
insert into public.exact_koppeling (id) values (1) on conflict do nothing;
alter table public.exact_koppeling enable row level security;
revoke all on public.exact_koppeling from anon, authenticated;   -- alleen de Edge Function (service role) komt hierbij

create table if not exists public.exact_onderdelen (
  soort      text primary key,           -- bijv. 'relaties'
  naam       text not null,              -- wat je in de app ziet
  sync_pad   text,                       -- bijv. 'sync/CRM/Accounts' (snel: 1000 per keer, alleen wat veranderd is)
  pad        text,                       -- gewone endpoint als terugval, bijv. 'crm/Accounts'
  kolommen   text,                       -- $select voor de sync (leeg = de app zoekt ze zelf uit)
  aan        boolean not null default true,
  volgorde   integer not null default 0,
  ts         bigint not null default 0,  -- laatste Timestamp van de sync
  gewijzigd  timestamptz,                -- laatste Modified (terugval)
  aantal     integer not null default 0,
  laatst     timestamptz,
  klaar      boolean not null default false,   -- eerste keer helemaal opgehaald
  fout       text
);
alter table public.exact_onderdelen enable row level security;
grant select, update on public.exact_onderdelen to authenticated;
drop policy if exists "lezen" on public.exact_onderdelen;
create policy "lezen" on public.exact_onderdelen for select to authenticated using (not public.is_apparaat() and (public.is_beheerder() or public.heeft_recht('exact_bekijken')));
drop policy if exists "beheren" on public.exact_onderdelen;
create policy "beheren" on public.exact_onderdelen for update to authenticated using (public.is_beheerder()) with check (public.is_beheerder());

insert into public.exact_onderdelen (soort, naam, sync_pad, pad, volgorde) values
  ('relaties',          'Relaties (klanten en leveranciers)', 'sync/CRM/Accounts',              'crm/Accounts',                 1),
  ('contactpersonen',   'Contactpersonen',                    'sync/CRM/Contacts',              'crm/Contacts',                 2),
  ('adressen',          'Adressen',                           'sync/CRM/Addresses',             'crm/Addresses',                3),
  ('artikelen',         'Artikelen',                          'sync/Logistics/Items',           'logistics/Items',              4),
  ('verkoopprijzen',    'Verkoopprijzen',                     'sync/Logistics/SalesItemPrices', 'logistics/SalesItemPrices',    5),
  ('verkooporders',     'Verkooporders',                      'sync/SalesOrder/SalesOrderHeaders', 'salesorder/SalesOrders',    6),
  ('verkooporderregels','Verkooporderregels',                 'sync/SalesOrder/SalesOrderLines', 'salesorder/SalesOrderLines',  7),
  ('leveringen',        'Leveringen',                         'sync/SalesOrder/GoodsDeliveries', 'salesorder/GoodsDeliveries',  8),
  ('leveringregels',    'Leveringregels',                     'sync/SalesOrder/GoodsDeliveryLines', 'salesorder/GoodsDeliveryLines', 9),
  ('verkoopfacturen',   'Verkoopfacturen',                    'sync/SalesInvoice/SalesInvoices', 'salesinvoice/SalesInvoices',  10),
  ('factuurregels',     'Factuurregels',                      'sync/SalesInvoice/SalesInvoiceLines', 'salesinvoice/SalesInvoiceLines', 11),
  ('offertes',          'Offertes',                           'sync/Quotation/Quotations',      'crm/Quotations',               12),
  ('offerteregels',     'Offerteregels',                      'sync/Quotation/QuotationLines',  'crm/QuotationLines',           13),
  ('inkooporders',      'Inkooporders',                       'sync/PurchaseOrder/PurchaseOrders', 'purchaseorder/PurchaseOrders', 14),
  ('inkooporderregels', 'Inkooporderregels',                  'sync/PurchaseOrder/PurchaseOrderLines', 'purchaseorder/PurchaseOrderLines', 15),
  ('voorraad',          'Voorraadposities',                   'sync/Inventory/StockPositions',  'inventory/StockPositions',     16),
  ('artikelmagazijnen', 'Voorraad per magazijn',              'sync/Inventory/ItemWarehouses',  'inventory/ItemWarehouses',     17),
  ('grootboek',         'Grootboekrekeningen',                'sync/Financial/GLAccounts',      'financial/GLAccounts',         18),
  ('boekingen',         'Boekingsregels (financieel)',        'sync/Financial/TransactionLines','financialtransaction/TransactionLines', 19),
  ('betaalcondities',   'Betalingscondities',                 'sync/Cashflow/PaymentTerms',     'cashflow/PaymentConditions',   20),
  ('projecten',         'Projecten',                          'sync/Project/Projects',          'project/Projects',             21)
on conflict (soort) do nothing;

create table if not exists public.exact_data (
  soort     text not null,
  id        text not null,
  data      jsonb not null,
  gewijzigd timestamptz not null default now(),
  primary key (soort, id)
);
create index if not exists exact_data_zoek on public.exact_data using gin (data jsonb_path_ops);
alter table public.exact_data enable row level security;
grant select on public.exact_data to authenticated;
drop policy if exists "lezen" on public.exact_data;
create policy "lezen" on public.exact_data for select to authenticated using (not public.is_apparaat() and (public.is_beheerder() or public.heeft_recht('exact_bekijken')));

-- status voor de app (zonder tokens)
create or replace function public.exact_status() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if public.is_apparaat() or not (public.is_beheerder() or public.heeft_recht('exact_bekijken')) then return jsonb_build_object('mag', false); end if;
  return (select jsonb_build_object('mag', true, 'gekoppeld', refresh_token is not null, 'division', division, 'divisie', divisie_naam, 'laatst', laatst,
            'fout', fout, 'aanroepen', case when aanroepen_dag = current_date then aanroepen else 0 end, 'door', gekoppeld_door, 'op', gekoppeld_op,
            'cron', exists (select 1 from cron.job where jobname = 'exact-sync'))
          from public.exact_koppeling where id = 1);
exception when undefined_table then
  return (select jsonb_build_object('mag', true, 'gekoppeld', refresh_token is not null, 'division', division, 'divisie', divisie_naam, 'laatst', laatst, 'fout', fout, 'cron', false)
          from public.exact_koppeling where id = 1);
end $$;
revoke all on function public.exact_status() from public, anon;
grant execute on function public.exact_status() to authenticated;

-- elke 15 minuten bijwerken (de beheerder zet dit aan vanuit de app; het adres van de functie geeft de app mee)
do $$ begin create extension if not exists pg_cron; exception when others then null; end $$;
do $$ begin create extension if not exists pg_net; exception when others then null; end $$;
create or replace function public.exact_cron(p_url text, p_aan boolean default true) returns text
language plpgsql security definer set search_path = '' as $$
declare k uuid;
begin
  if not public.is_beheerder() then raise exception 'Alleen een beheerder'; end if;
  begin perform cron.unschedule('exact-sync'); exception when others then null; end;
  if not p_aan then return 'uit'; end if;
  select sync_sleutel into k from public.exact_koppeling where id = 1;
  perform cron.schedule('exact-sync', '*/15 * * * *', format(
    $c$select net.http_post(url := %L, headers := jsonb_build_object('Content-Type', 'application/json', 'x-sync-sleutel', %L), body := '{"actie":"sync"}'::jsonb, timeout_milliseconds := 60000)$c$,
    rtrim(p_url, '/') || '/functions/v1/exact', k::text));
  return 'aan';
end $$;
revoke all on function public.exact_cron(text, boolean) from public, anon;
grant execute on function public.exact_cron(text, boolean) to authenticated;
-- =====================================================================
-- BOXKAARTEN AUTOMATISCH PRINTEN (27 november 2026)
-- Als de rooier een wagen terugstuurt, print de printstation-computer (Etiketten → Actueel → 🖨️ Printstation)
-- meteen één boxkaart per bak. Per wagen wordt vastgelegd dat hij geprint is, zodat het nooit dubbel gebeurt
-- (ook niet als er twee computers als printstation aan staan, of na herladen).
-- =====================================================================
alter table public.wagens_weg add column if not exists boxkaarten_op   timestamptz;
alter table public.wagens_weg add column if not exists boxkaarten_door text;

-- de printstation claimt een wagen: true = jij print hem nu, false = al geprint of de wagen bestaat niet (meer)
create or replace function public.wagen_boxkaarten_claim(p_wagen uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  if not (public.heeft_recht('etiketten_printen') or public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then
    raise exception 'Je mag geen etiketten afdrukken';
  end if;
  update public.wagens_weg
     set boxkaarten_op = now(),
         boxkaarten_door = coalesce((select naam from public.profielen where id = auth.uid()), 'printstation')
   where id = p_wagen and boxkaarten_op is null and status in ('onderweg', 'legen');
  get diagnostics n = row_count;
  return n > 0;
end $$;
revoke all on function public.wagen_boxkaarten_claim(uuid) from public, anon;
grant execute on function public.wagen_boxkaarten_claim(uuid) to authenticated;

-- mislukt voordat er iets gemaakt is: de wagen weer vrijgeven, dan probeert de printstation het straks opnieuw
create or replace function public.wagen_boxkaarten_vrij(p_wagen uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not (public.heeft_recht('etiketten_printen') or public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then
    raise exception 'Je mag geen etiketten afdrukken';
  end if;
  update public.wagens_weg set boxkaarten_op = null, boxkaarten_door = null where id = p_wagen;
end $$;
revoke all on function public.wagen_boxkaarten_vrij(uuid) from public, anon;
grant execute on function public.wagen_boxkaarten_vrij(uuid) to authenticated;
-- =====================================================================
-- WAGEN BINNEN: GELOST OF IN EEN KOELCEL (27 november 2026)
-- Bij een wagen die onderweg is kies je:
--   🚚 Gelost      → de bakken komen op de plek Laden & lossen te staan (daar blijven ze soms even)
--   ❄️ In koelcel  → je kiest in welke koelcel; de bakken komen daar te staan
-- De bakken worden meteen ingeslagen (zonder scannen). Scan je later toch een box van die wagen,
-- dan telt hij niet dubbel (de app haalt dan één "wagen zonder scannen"-bak weg).
-- =====================================================================
alter table public.wagens_weg add column if not exists plek text;   -- waar de bakken zijn neergezet

create or replace function public.wagen_inslaan(p_wagen uuid, p_cel text, p_inhoud jsonb default null, p_door text default null) returns integer
language plpgsql security definer set search_path = '' as $$
declare
  w public.wagens_weg; x jsonb; n integer := 0; b numeric; v_door text; v_pid uuid;
begin
  select * into w from public.wagens_weg where id = p_wagen for update;
  if not found then raise exception 'Deze wagen bestaat niet (meer)'; end if;
  if not (w.bijrijder_id = auth.uid() or public.is_apparaat() or public.heeft_recht('taken_afvinken')
          or public.heeft_recht('resultaten_beheren') or public.heeft_recht('voorraad_beheren')) then
    raise exception 'Je mag deze wagen niet binnen melden';
  end if;
  if w.status not in ('onderweg', 'legen') then raise exception 'Deze wagen is al binnen gemeld'; end if;
  if coalesce(trim(p_cel), '') = '' then raise exception 'Kies waar de bakken staan'; end if;
  v_door := coalesce(nullif(trim(p_door), ''), (select naam from public.profielen where id = auth.uid()), 'app');
  for x in select * from jsonb_array_elements(coalesce(p_inhoud, w.inhoud, '[]'::jsonb)) loop
    b := round(coalesce(nullif(x->>'bakken', '')::numeric, 0));
    v_pid := nullif(x->>'partij_id', '')::uuid;
    if v_pid is null or b <= 0 then continue; end if;
    if not exists (select 1 from public.partijen where id = v_pid) then continue; end if;
    insert into public.partij_mutaties (partij_id, seizoen_id, soort, datum, aantal, eenheid, koelcel, notitie, door)
    values (v_pid, coalesce((select seizoen_id from public.partijen where id = v_pid), w.seizoen_id), 'in', current_date, b, 'kuubskisten', trim(p_cel),
            '🚛 wagen zonder scannen · ' || coalesce(w.wagen, 'wagen') || ' van ' || to_char(w.gemeld_op at time zone 'Europe/Amsterdam', 'HH24:MI'), v_door);
    n := n + b;
  end loop;
  update public.wagens_weg set status = 'koelcel', plek = trim(p_cel), koelcel_op = now(), koelcel_door = v_door where id = p_wagen;
  return n;
end $$;
revoke all on function public.wagen_inslaan(uuid, text, jsonb, text) from public, anon;
grant execute on function public.wagen_inslaan(uuid, text, jsonb, text) to authenticated;
-- =====================================================================
-- SCANNEN: GEEN PALLETS MEER PER ONGELUK UITBOEKEN (27 november 2026)
-- Een pallet (of box) scannen en dan de koelcel waar hij al in staat = eruit halen. Bij meerdere pallets tegelijk,
-- of als de scanner de koelcel twee keer las, ging een deel van de pallets daardoor weer de koelcel uit (leeg).
-- Nu: bij meerdere codes tegelijk wordt nooit iets uitgeboekt, en een code die net (binnen 20 s) in deze koelcel
-- is gezet, wordt ook niet meteen weer uitgeboekt. Dubbele codes in één opdracht tellen één keer.
-- =====================================================================
create or replace function public.scan_boek(p_actie text, p_codes text[], p_doel text default null, p_sleutel text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare c text; r jsonb := '[]'::jsonb; m text; wie text; oud jsonb; codes text[]; meer boolean; cur text; e public.etiketten;
begin
  -- dezelfde opdracht nog een keer (verstuurd zonder bereik, antwoord kwam niet aan): niet opnieuw boeken
  if p_sleutel is not null then select resultaat into oud from public.verwerkt where sleutel = p_sleutel; if found then return oud; end if; end if;
  if not (public.heeft_recht('voorraad_beheren') or public.is_beheerder()) then raise exception 'Je mag geen voorraad boeken'; end if;
  if p_actie not in ('koelcel', 'kiep', 'pallet_op', 'pallet_af') then raise exception 'Onbekende actie'; end if;
  if p_actie <> 'kiep' and coalesce(trim(p_doel), '') = '' then raise exception 'Geen koelcel of pallet gekozen'; end if;
  wie := coalesce((select naam from public.profielen where id = auth.uid()), 'heftruck');
  -- dubbele codes eruit (volgorde blijft)
  select coalesce(array_agg(x order by i), '{}') into codes
    from (select distinct on (upper(trim(t))) upper(trim(t)) x, ord i from unnest(coalesce(p_codes, '{}')) with ordinality as u(t, ord) where coalesce(trim(t), '') <> '' order by upper(trim(t)), ord) q;
  meer := coalesce(array_length(codes, 1), 0) > 1;
  foreach c in array codes loop
    begin
      if p_actie = 'koelcel' then
        cur := public.etiket_cel(c);
        if cur is not distinct from nullif(trim(p_doel), '') and cur is not null and (meer or exists (
             select 1 from public.scan_log l where l.code = c and l.naar = cur and l.created_at > now() - interval '20 seconds')) then
          select * into e from public.etiketten where code = c;
          r := r || jsonb_build_object('code', c, 'ok', true, 'melding', format('✓ %s %s stond al in %s', case when e.soort = 'pallet' then 'Pallet' else 'Box' end, e.nr, cur));
          continue;
        end if;
      end if;
      m := public.scan_een(p_actie, c, nullif(trim(p_doel), ''), wie);
      r := r || jsonb_build_object('code', c, 'ok', true, 'melding', m);
    exception when others then
      r := r || jsonb_build_object('code', c, 'ok', false, 'melding', regexp_replace(sqlerrm, '^RES: ', ''));
    end;
  end loop;
  if p_sleutel is not null then insert into public.verwerkt (sleutel, resultaat) values (p_sleutel, r) on conflict do nothing; end if;
  return r;
end $$;
revoke all on function public.scan_boek(text, text[], text, text) from public, anon;
grant execute on function public.scan_boek(text, text[], text, text) to authenticated;
-- =====================================================================
-- SORTEERLIJNEN BIJ HET KIEPEN (27 november 2026)
-- De beheerder geeft de sorteerlijnen op (instelling 'sorteerlijnen'). Op de kieplijst kies je op welke lijn je kiept;
-- elke gekiepte bak (tikken, scannen, uit de koelcel) krijgt die lijn mee.
-- =====================================================================
alter table public.res_invoer add column if not exists lijn text;
alter table public.profielen  add column if not exists kiep_lijn text;

-- de lijn die dit apparaat/account nu gebruikt, automatisch op elke kiep-regel
create or replace function public.kiep_lijn_invullen() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.soort = 'kiepen' and new.lijn is null then new.lijn := (select kiep_lijn from public.profielen where id = auth.uid()); end if;
  return new;
end $$;
drop trigger if exists kiep_lijn_invullen on public.res_invoer;
create trigger kiep_lijn_invullen before insert on public.res_invoer for each row execute function public.kiep_lijn_invullen();

create or replace function public.zet_kiep_lijn(p_lijn text) returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.profielen set kiep_lijn = nullif(trim(p_lijn), '') where id = auth.uid();
end $$;
revoke all on function public.zet_kiep_lijn(text) from public, anon;
grant execute on function public.zet_kiep_lijn(text) to authenticated;

create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel in ('koelcellen', 'etiket', 'etiket_logo', 'sorteerlijnen') and public.heeft_recht('voorraad_beheren'))
     and not (p_sleutel = 'recht_sjablonen' and public.heeft_recht('team_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen', 'etiket', 'etiket_logo', 'droogte_mm', 'recht_sjablonen', 'sorteerlijnen') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  if p_sleutel = 'etiket_logo' and length(coalesce(p_waarde, '')) > 400000 then raise exception 'Het logo is te groot'; end if;
  if p_sleutel = 'recht_sjablonen' and (length(coalesce(p_waarde, '')) > 200000 or (nullif(trim(p_waarde), '') is not null and jsonb_typeof(p_waarde::jsonb) <> 'object')) then raise exception 'Ongeldige standaarden'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;


-- =====================================================================
-- WAT LIGT ER OP DE SORTEERLIJN (27 november 2026)
-- Elke gekiepte bak met een lijn zet die partij "op de lijn". Kiep je een andere soort op dezelfde lijn,
-- dan vraagt de app eerst of de lijn leeg is. Met lijn_leeg maak je een lijn vrij voor een nieuwe soort.
-- Draai NA sorteerlijnen.sql.
-- =====================================================================
create table if not exists public.sorteerlijn_stand (
  lijn       text primary key,
  partij_id  uuid references public.partijen(id) on delete set null,
  ras        text,                 -- soort/ras op het moment van kiepen (blijft ook als de partij later weg is)
  sinds      timestamptz,          -- sinds wanneer deze partij erop ligt
  laatst     timestamptz,          -- laatste gekiepte bak
  leeg_op    timestamptz,
  leeg_door  text
);
alter table public.sorteerlijn_stand enable row level security;
drop policy if exists "lezen" on public.sorteerlijn_stand;
create policy "lezen" on public.sorteerlijn_stand for select to authenticated using (true);
-- schrijven alleen via de trigger en lijn_leeg hieronder

create or replace function public.lijn_stand_bij_kiep() returns trigger language plpgsql security definer set search_path = '' as $$
declare r text;
begin
  if new.soort <> 'kiepen' or new.lijn is null or new.partij_id is null then return new; end if;
  select coalesce(ra.naam, p.ras_tekst) into r from public.partijen p left join public.rassen ra on ra.id = p.ras_id where p.id = new.partij_id;
  insert into public.sorteerlijn_stand as s (lijn, partij_id, ras, sinds, laatst)
    values (new.lijn, new.partij_id, r, now(), now())
  on conflict (lijn) do update set
    sinds   = case when s.partij_id is not distinct from excluded.partij_id then coalesce(s.sinds, now()) else now() end,
    partij_id = excluded.partij_id, ras = excluded.ras, laatst = now();
  return new;
end $$;
drop trigger if exists lijn_stand_bij_kiep on public.res_invoer;
create trigger lijn_stand_bij_kiep after insert on public.res_invoer for each row execute function public.lijn_stand_bij_kiep();

create or replace function public.lijn_leeg(p_lijn text) returns void language plpgsql security definer set search_path = '' as $$
declare n text;
begin
  if auth.uid() is null then raise exception 'Niet ingelogd'; end if;
  select naam into n from public.profielen where id = auth.uid();
  insert into public.sorteerlijn_stand as s (lijn, partij_id, ras, sinds, laatst, leeg_op, leeg_door)
    values (trim(p_lijn), null, null, null, null, now(), n)
  on conflict (lijn) do update set partij_id = null, ras = null, sinds = null, leeg_op = now(), leeg_door = n;
end $$;
revoke all on function public.lijn_leeg(text) from public, anon;
grant execute on function public.lijn_leeg(text) to authenticated;

-- =====================================================================
-- SSOR-LIJNEN INSTELLEN VANUIT DE APP (27 november 2026)
-- Zie docs/ssor-lijnen-koppelgegevens: SSOR bewaart een lijn in PRODUCTIONLINE, wat erop ligt in
-- PRODUCTIONLINESETTING en kleur kistkaart -> soort kistje in PRODUCTIONLINESORTING. De Control Tower
-- leest dat alleen bij het opstarten, dus de app schrijft NIET in SSOR: hij zet een opdracht in de
-- wachtrij ssor_opdrachten, en de uitvoerder op de pc van de Control Tower (ct-lijn-zetten.ps1) voert
-- hem uit en meldt KLAAR of FOUT terug.
-- Draai NA sorteerlijnen.sql en lijn-stand.sql. Raakt ssor_sync niet aan: de lijnen komen binnen via
-- een eigen rpc ssor_sync_lijnen (met dezelfde geheime sleutel).
-- =====================================================================

-- ---------- kopie van de SSOR-lijntabellen (gevuld door ssor-sync.ps1) ----------
create table if not exists public.ssor_lijnen (id bigint primary key, naam text, nr text, scanner boolean, hoofdlijn_id bigint, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_lijn_stand (lijn_id bigint primary key, dagtaak_id bigint, locatie_id bigint, sublocatie_id bigint, bijgewerkt timestamptz not null default now());
create table if not exists public.ssor_lijn_kleuren (lijn_id bigint not null, kleur int not null, sortering_id bigint, primary key (lijn_id, kleur));
-- soorten kistjes met het aantal per kist en de standaardkleur (SORTING); eigen tabel, los van wat ssor_sync al doet
create table if not exists public.ssor_kistsoorten (id bigint primary key, naam text, aantal numeric, kleur int, bijgewerkt timestamptz not null default now());
-- perceel + partij-namen (LOCATION), alleen wat nodig is om de stand te tonen en een partij te vinden; geen persoonsgegevens
create table if not exists public.ssor_plekken (id bigint primary key, naam text, nak text, ouder_id bigint, actief boolean, bijgewerkt timestamptz not null default now());

do $$ declare t text; begin
  foreach t in array array['ssor_lijnen', 'ssor_lijn_stand', 'ssor_lijn_kleuren', 'ssor_kistsoorten', 'ssor_plekken'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('drop policy if exists "lezen" on public.%I', t);
    -- geen persoonsgegevens: iedereen die is ingelogd mag lezen (ook de kieptelefoon)
    execute format('create policy "lezen" on public.%I for select to authenticated using (true)', t);
  end loop;
end $$;

create or replace function public.ssor_sync_lijnen(p_sleutel uuid, p_tabel text, p_rijen jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare n int := 0; ja text[] := array['1', 't', 'true', 'y', 'j'];
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  if jsonb_typeof(p_rijen) <> 'array' then raise exception 'p_rijen moet een lijst zijn'; end if;
  -- kleine tabellen: elke keer helemaal vervangen (dan verdwijnt ook wat in SSOR is weggehaald)
  if p_tabel = 'lijnen' then
    delete from public.ssor_lijnen where true;
    insert into public.ssor_lijnen (id, naam, nr, scanner, hoofdlijn_id)
      select x.id::bigint, nullif(trim(x.naam), ''), nullif(trim(x.nr), ''), lower(coalesce(x.scanner, '')) = any(ja), nullif(x.hoofdlijn_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(id text, naam text, nr text, scanner text, hoofdlijn_id text);
  elsif p_tabel = 'lijn_stand' then
    delete from public.ssor_lijn_stand where true;
    insert into public.ssor_lijn_stand (lijn_id, dagtaak_id, locatie_id, sublocatie_id)
      select distinct on (x.lijn_id::bigint) x.lijn_id::bigint, nullif(x.dagtaak_id, '')::bigint, nullif(x.locatie_id, '')::bigint, nullif(x.sublocatie_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(lijn_id text, dagtaak_id text, locatie_id text, sublocatie_id text) where nullif(x.lijn_id, '') is not null;
  elsif p_tabel = 'lijn_kleuren' then
    delete from public.ssor_lijn_kleuren where true;
    insert into public.ssor_lijn_kleuren (lijn_id, kleur, sortering_id)
      select distinct on (x.lijn_id::bigint, x.kleur::int) x.lijn_id::bigint, x.kleur::int, nullif(x.sortering_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(lijn_id text, kleur text, sortering_id text) where nullif(x.lijn_id, '') is not null and nullif(x.kleur, '') is not null;
  elsif p_tabel = 'kistsoorten' then
    insert into public.ssor_kistsoorten (id, naam, aantal, kleur)
      select x.id::bigint, nullif(trim(x.naam), ''), nullif(replace(x.aantal, ',', '.'), '')::numeric, nullif(x.kleur, '')::int
      from jsonb_to_recordset(p_rijen) x(id text, naam text, aantal text, kleur text)
    on conflict (id) do update set naam = excluded.naam, aantal = excluded.aantal, kleur = excluded.kleur, bijgewerkt = now();
  elsif p_tabel = 'plekken' then
    insert into public.ssor_plekken (id, naam, nak, ouder_id, actief)
      select x.id::bigint, nullif(trim(x.naam), ''), nullif(trim(x.nak), ''), nullif(x.ouder_id, '')::bigint, lower(coalesce(x.actief, '')) = any(ja)
      from jsonb_to_recordset(p_rijen) x(id text, naam text, nak text, ouder_id text, actief text)
    on conflict (id) do update set naam = excluded.naam, nak = excluded.nak, ouder_id = excluded.ouder_id, actief = excluded.actief, bijgewerkt = now();
  else raise exception 'Onbekende tabel %', p_tabel; end if;
  get diagnostics n = row_count;
  update public.ssor_koppeling set laatst = now(), info = info || jsonb_build_object('lijnen_' || p_tabel, jsonb_build_object('tijd', now(), 'rijen', n)) where id = 1;
  return jsonb_build_object('tabel', p_tabel, 'rijen', n);
end $$;
revoke all on function public.ssor_sync_lijnen(uuid, text, jsonb) from public;
grant execute on function public.ssor_sync_lijnen(uuid, text, jsonb) to anon, authenticated;

-- ---------- wie mag lijnen instellen: recht lijnen_instellen, of de kieptelefoon ----------
create or replace function public.mag_lijnen() returns boolean language sql stable security definer set search_path = '' as $$
  select public.heeft_recht('lijnen_instellen') or exists (select 1 from public.profielen where id = auth.uid() and werkplek = 'kiep');
$$;
grant execute on function public.mag_lijnen() to authenticated;

-- ---------- wachtrij ----------
create table if not exists public.ssor_opdrachten (
  id           bigint generated always as identity primary key,
  soort        text not null default 'lijn_instellen' check (soort in ('lijn_instellen')),
  ssor_lijn    text not null,               -- PRODUCTIONLINE.NAME = tabblad in de Control Tower, bijv. 'Lijn 1a'
  app_lijn     text,                        -- de lijn zoals in de app (sorteerlijnen), alleen ter info
  partij       text not null,               -- naam van de SSOR-sublocatie = NAK, bijv. '260531'
  perceel      text,                        -- naam van het perceel; alleen nodig als de NAK vaker voorkomt
  kleuren      jsonb not null default '[]', -- [{"kleur": 3, "sortering_id": 307}, ...]; niet genoemd = (Geen)
  partij_id    uuid,                        -- partij in de app, alleen ter info
  status       text not null default 'wacht' check (status in ('wacht', 'bezig', 'klaar', 'fout')),
  fout         text,
  gemaakt_door uuid default auth.uid(),
  door_naam    text,
  gemaakt_op   timestamptz not null default now(),
  gestart_op   timestamptz,
  klaar_op     timestamptz
);
create index if not exists ssor_opdrachten_status on public.ssor_opdrachten (status, gemaakt_op);
alter table public.ssor_opdrachten enable row level security;
revoke all on public.ssor_opdrachten from anon;
grant select on public.ssor_opdrachten to authenticated;
drop policy if exists "lezen" on public.ssor_opdrachten;
create policy "lezen" on public.ssor_opdrachten for select to authenticated using ((select public.mag_lijnen()) or (select public.is_beheerder()));
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'ssor_opdrachten') then
    execute 'alter publication supabase_realtime add table public.ssor_opdrachten';
  end if;
exception when others then null;
end $$;

-- de app (tablet) zet een opdracht klaar
create or replace function public.ssor_lijn_opdracht(p_ssor_lijn text, p_partij text, p_perceel text, p_kleuren jsonb, p_partij_id uuid default null, p_app_lijn text default null)
returns bigint language plpgsql security definer set search_path = '' as $$
declare i bigint; k jsonb;
begin
  if not public.mag_lijnen() then raise exception 'Je mag geen sorteerlijnen instellen (recht "Sorteerlijnen in SSOR instellen")'; end if;
  if nullif(trim(p_ssor_lijn), '') is null then raise exception 'Deze lijn is nog niet aan een SSOR-lijn gekoppeld'; end if;
  if nullif(trim(p_partij), '') is null then raise exception 'Kies eerst de partij (scan de box)'; end if;
  if jsonb_typeof(coalesce(p_kleuren, '[]')) <> 'array' then raise exception 'Kleuren moeten een lijst zijn'; end if;
  for k in select * from jsonb_array_elements(coalesce(p_kleuren, '[]')) loop
    if (k->>'kleur') !~ '^\d+$' or (k->>'sortering_id') !~ '^\d+$' then raise exception 'Ongeldige kleur of soort kistje: %', k; end if;
  end loop;
  -- een oudere, nog wachtende opdracht voor dezelfde lijn is achterhaald
  update public.ssor_opdrachten set status = 'fout', fout = 'Vervangen door een nieuwere opdracht', klaar_op = now()
   where ssor_lijn = trim(p_ssor_lijn) and status = 'wacht';
  insert into public.ssor_opdrachten (ssor_lijn, app_lijn, partij, perceel, kleuren, partij_id, door_naam)
    values (trim(p_ssor_lijn), nullif(trim(p_app_lijn), ''), trim(p_partij), nullif(trim(p_perceel), ''), coalesce(p_kleuren, '[]'), p_partij_id,
            (select naam from public.profielen where id = auth.uid()))
    returning id into i;
  return i;
end $$;
revoke all on function public.ssor_lijn_opdracht(text, text, text, jsonb, uuid, text) from public, anon;
grant execute on function public.ssor_lijn_opdracht(text, text, text, jsonb, uuid, text) to authenticated;

-- de uitvoerder op de pc van de Control Tower: wachtende opdrachten ophalen (oudste eerst) en op bezig zetten
create or replace function public.ssor_opdrachten_ophalen(p_sleutel uuid)
returns setof public.ssor_opdrachten language plpgsql security definer set search_path = '' as $$
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  -- blijft iets langer dan 15 minuten op bezig hangen (uitvoerder vastgelopen), dan als fout melden
  update public.ssor_opdrachten set status = 'fout', fout = 'De uitvoerder reageerde niet (meer dan 15 minuten bezig). Kijk of de lijn loopt.', klaar_op = now()
   where status = 'bezig' and gestart_op < now() - interval '15 minutes';
  return query
    update public.ssor_opdrachten o set status = 'bezig', gestart_op = now()
     where o.id in (select id from public.ssor_opdrachten where status = 'wacht' order by gemaakt_op for update skip locked)
    returning o.*;
end $$;
revoke all on function public.ssor_opdrachten_ophalen(uuid) from public;
grant execute on function public.ssor_opdrachten_ophalen(uuid) to anon, authenticated;

create or replace function public.ssor_opdracht_klaar(p_sleutel uuid, p_id bigint, p_status text, p_fout text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  if p_status not in ('klaar', 'fout') then raise exception 'Status moet klaar of fout zijn'; end if;
  update public.ssor_opdrachten set status = p_status, fout = left(nullif(trim(p_fout), ''), 1000), klaar_op = now() where id = p_id;
  if not found then raise exception 'Opdracht % niet gevonden', p_id; end if;
end $$;
revoke all on function public.ssor_opdracht_klaar(uuid, bigint, text, text) from public;
grant execute on function public.ssor_opdracht_klaar(uuid, bigint, text, text) to anon, authenticated;

-- partij (NAK) zoeken in SSOR: actieve partij-plekken met die NAK, met het perceel erbij
create or replace function public.ssor_partij_zoek(p_nak text)
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', s.id, 'partij', s.naam, 'nak', s.nak, 'perceel', o.naam, 'perceel_id', o.id) order by o.naam), '[]'::jsonb)
    from public.ssor_plekken s left join public.ssor_plekken o on o.id = s.ouder_id
   where s.ouder_id is not null and s.actief and (s.nak = trim(p_nak) or s.naam = trim(p_nak));
$$;
revoke all on function public.ssor_partij_zoek(text) from public, anon;
grant execute on function public.ssor_partij_zoek(text) to authenticated;

-- ---------- instellingen: koppeling app-lijn -> SSOR-lijn en kleurnummers ----------
create or replace function public.zet_instelling(p_sleutel text, p_waarde text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.mag_instellingen()
     and not ((p_sleutel like 'res_%' or p_sleutel = 'wagens') and public.heeft_recht('resultaten_beheren'))
     and not (p_sleutel = 'spoor_opbouw' and (public.heeft_recht('spuitsporen_bewerken') or public.heeft_recht('percelen_bewerken')))
     and not (p_sleutel = 'teeltjaar_start' and public.heeft_recht('seizoen_starten'))
     and not (p_sleutel in ('koelcellen', 'etiket', 'etiket_logo', 'sorteerlijnen', 'ssor_lijn_koppeling', 'ssor_kleuren') and public.heeft_recht('voorraad_beheren'))
     and not (p_sleutel = 'recht_sjablonen' and public.heeft_recht('team_beheren')) then
    raise exception 'Je mag de instellingen niet aanpassen';
  end if;
  if p_sleutel not in ('uurtarief', 'vorst_grens', 'spuit_wind_max', 'klokplicht', 'klok_start', 'res_grens', 'wagens', 'regenvrij_uur', 'spoor_opbouw', 'teeltjaar_start', 'koelcellen', 'etiket', 'etiket_logo', 'droogte_mm', 'recht_sjablonen', 'sorteerlijnen', 'ssor_lijn_koppeling', 'ssor_kleuren') then raise exception 'Onbekende instelling'; end if;
  if p_sleutel = 'teeltjaar_start' and nullif(trim(p_waarde), '') is not null and trim(p_waarde) !~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$' then raise exception 'Datum als MM-DD, bijv. 11-01'; end if;
  if p_sleutel = 'etiket_logo' and length(coalesce(p_waarde, '')) > 400000 then raise exception 'Het logo is te groot'; end if;
  if p_sleutel = 'recht_sjablonen' and (length(coalesce(p_waarde, '')) > 200000 or (nullif(trim(p_waarde), '') is not null and jsonb_typeof(p_waarde::jsonb) <> 'object')) then raise exception 'Ongeldige standaarden'; end if;
  if p_sleutel in ('ssor_lijn_koppeling', 'ssor_kleuren') and nullif(trim(p_waarde), '') is not null and jsonb_typeof(p_waarde::jsonb) <> 'object' then raise exception 'Ongeldige waarde'; end if;
  insert into public.instellingen values (p_sleutel, nullif(trim(p_waarde), ''))
  on conflict (sleutel) do update set waarde = excluded.waarde;
  perform public.gebeurtenis('instelling', 'Instelling ' || p_sleutel || ' aangepast');
end $$;

-- kleurnummers zoals in de Control Tower (bewezen 27-11); later aan te passen zonder nieuwe versie
insert into public.instellingen (sleutel, waarde)
values ('ssor_kleuren', '{"Blauw": 4, "Geel": 12, "Groen": 6, "Rood": 5, "Wit": 3, "Mint": 1, "Rose": 2}')
on conflict (sleutel) do nothing;

-- =====================================================================
-- SSOR-KOPPELING HERSTELLEN (27 november 2026)
-- Het koppelprogramma stuurt ook dagtaken, sorteringen, rassen, locaties met NAK en waarschuwingen,
-- maar de functie ssor_sync in de database kende die niet (meer): "Onbekende tabel".
-- Dit zet ssor_sync terug met ALLE tabellen die ssor-sync.ps1 stuurt. Bestaande tabellen en kolommen
-- blijven staan; ontbrekende worden aangemaakt. ssor_moet en ssor_verzoek worden alleen aangemaakt
-- als ze nog niet bestaan (een bestaande versie blijft dus ongemoeid).
-- =====================================================================
create table if not exists public.ssor_dagtaken (id bigint primary key);
alter table public.ssor_dagtaken add column if not exists nr text;
alter table public.ssor_dagtaken add column if not exists naam text;
alter table public.ssor_dagtaken add column if not exists datum date;
alter table public.ssor_dagtaken add column if not exists activiteit_id bigint;
alter table public.ssor_dagtaken add column if not exists locatie_id bigint;
alter table public.ssor_dagtaken add column if not exists sublocatie_id bigint;
alter table public.ssor_dagtaken add column if not exists norm numeric;
alter table public.ssor_dagtaken add column if not exists bijgewerkt timestamptz not null default now();
create table if not exists public.ssor_sorteringen (id bigint primary key);
alter table public.ssor_sorteringen add column if not exists naam text;
alter table public.ssor_sorteringen add column if not exists bijgewerkt timestamptz not null default now();
create table if not exists public.ssor_rassen (id bigint primary key);
alter table public.ssor_rassen add column if not exists naam text;
alter table public.ssor_rassen add column if not exists bijgewerkt timestamptz not null default now();
alter table public.ssor_locaties add column if not exists nak text;
alter table public.ssor_locaties add column if not exists ras_id bigint;
alter table public.ssor_locaties add column if not exists ouder_id bigint;
alter table public.ssor_locaties add column if not exists actief boolean;

do $$ declare t text; begin
  foreach t in array array['ssor_dagtaken', 'ssor_sorteringen', 'ssor_rassen'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('grant select on public.%I to authenticated', t);
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = t and policyname = 'lezen') then
      execute format('create policy "lezen" on public.%I for select to authenticated using ((select public.mag_pno()) or (select public.is_beheerder()))', t);
    end if;
  end loop;
end $$;

create or replace function public.ssor_sync(p_sleutel uuid, p_tabel text, p_rijen jsonb, p_van date default null, p_tot date default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare n int := 0; ja text[] := array['1', 't', 'true', 'y', 'j'];
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  if jsonb_typeof(p_rijen) <> 'array' then raise exception 'p_rijen moet een lijst zijn'; end if;
  if p_tabel = 'activiteitgroepen' then
    insert into public.ssor_activiteitgroepen (id, nummer, naam) select x.id::bigint, x.nummer, x.naam from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'activiteiten' then
    insert into public.ssor_activiteiten (id, nummer, naam, groep_id, norm) select x.id::bigint, x.nummer, x.naam, nullif(x.groep_id, '')::bigint, nullif(replace(x.norm, ',', '.'), '')::numeric
      from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text, groep_id text, norm text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, groep_id = excluded.groep_id, norm = excluded.norm, bijgewerkt = now();
  elsif p_tabel = 'kostenplaatsen' then
    insert into public.ssor_kostenplaatsen (id, nummer, naam) select x.id::bigint, x.nummer, x.naam from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'locaties' then
    -- ook de sublocaties (partijen) met NAK, ras en het perceel erboven
    insert into public.ssor_locaties (id, nummer, naam, nak, ras_id, ouder_id, actief)
      select x.id::bigint, x.nummer, x.naam, nullif(trim(x.nak), ''), nullif(x.ras_id, '')::bigint, nullif(x.ouder_id, '')::bigint,
             case when nullif(x.actief, '') is null then null else lower(x.actief) = any(ja) end
      from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text, nak text, ras_id text, ouder_id text, actief text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, nak = excluded.nak, ras_id = excluded.ras_id, ouder_id = excluded.ouder_id,
      actief = excluded.actief, bijgewerkt = now();
  elsif p_tabel = 'medewerkers' then
    insert into public.ssor_medewerkers (id, nummer, naam, actief, contracttype)
      select x.id::bigint, x.nummer, nullif(trim(regexp_replace(x.naam, '\s+', ' ', 'g')), ''), lower(coalesce(x.actief, '')) = any(ja), nullif(trim(x.contracttype), '')
      from jsonb_to_recordset(p_rijen) x(id text, nummer text, naam text, actief text, contracttype text)
    on conflict (id) do update set nummer = excluded.nummer, naam = excluded.naam, actief = excluded.actief, contracttype = excluded.contracttype, bijgewerkt = now();
  elsif p_tabel = 'sorteringen' then
    insert into public.ssor_sorteringen (id, naam) select x.id::bigint, nullif(trim(x.naam), '') from jsonb_to_recordset(p_rijen) x(id text, naam text)
    on conflict (id) do update set naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'rassen' then
    insert into public.ssor_rassen (id, naam) select x.id::bigint, nullif(trim(x.naam), '') from jsonb_to_recordset(p_rijen) x(id text, naam text)
    on conflict (id) do update set naam = excluded.naam, bijgewerkt = now();
  elsif p_tabel = 'uren' then
    insert into public.ssor_uren (id, datum, uren, activiteit_id, kostenplaats_id, dagtaak_id, medewerker_id, locatie_id, sublocatie_id)
      select x.id::bigint, left(x.datum, 10)::date, coalesce(nullif(replace(x.uren, ',', '.'), '')::numeric, 0), nullif(x.activiteit_id, '')::bigint, nullif(x.kostenplaats_id, '')::bigint,
             nullif(x.dagtaak_id, '')::bigint, nullif(x.medewerker_id, '')::bigint, nullif(x.locatie_id, '')::bigint, nullif(x.sublocatie_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(id text, datum text, uren text, activiteit_id text, kostenplaats_id text, dagtaak_id text, medewerker_id text, locatie_id text, sublocatie_id text)
      where nullif(x.datum, '') is not null
    on conflict (id) do update set datum = excluded.datum, uren = excluded.uren, activiteit_id = excluded.activiteit_id, kostenplaats_id = excluded.kostenplaats_id,
      dagtaak_id = excluded.dagtaak_id, medewerker_id = excluded.medewerker_id, locatie_id = excluded.locatie_id, sublocatie_id = excluded.sublocatie_id;
  elsif p_tabel = 'eenheden' then
    insert into public.ssor_eenheden (id, datum, tijd, aantal, activiteit_id, kostenplaats_id, dagtaak_id, medewerker_id, locatie_id, sublocatie_id, sortering_id)
      select x.id::bigint, left(x.datum, 10)::date, nullif(x.tijd, ''), coalesce(nullif(replace(x.aantal, ',', '.'), '')::numeric, 0), nullif(x.activiteit_id, '')::bigint,
             nullif(x.kostenplaats_id, '')::bigint, nullif(x.dagtaak_id, '')::bigint, nullif(x.medewerker_id, '')::bigint, nullif(x.locatie_id, '')::bigint,
             nullif(x.sublocatie_id, '')::bigint, nullif(x.sortering_id, '')::bigint
      from jsonb_to_recordset(p_rijen) x(id text, datum text, tijd text, aantal text, activiteit_id text, kostenplaats_id text, dagtaak_id text, medewerker_id text, locatie_id text, sublocatie_id text, sortering_id text)
      where nullif(x.datum, '') is not null
    on conflict (id) do update set datum = excluded.datum, tijd = excluded.tijd, aantal = excluded.aantal, activiteit_id = excluded.activiteit_id, kostenplaats_id = excluded.kostenplaats_id,
      dagtaak_id = excluded.dagtaak_id, medewerker_id = excluded.medewerker_id, locatie_id = excluded.locatie_id, sublocatie_id = excluded.sublocatie_id, sortering_id = excluded.sortering_id;
  elsif p_tabel = 'dagtaken' then
    insert into public.ssor_dagtaken (id, nr, naam, datum, activiteit_id, locatie_id, sublocatie_id, norm)
      select x.id::bigint, nullif(trim(x.nr), ''), nullif(trim(x.naam), ''), left(x.datum, 10)::date, nullif(x.activiteit_id, '')::bigint, nullif(x.locatie_id, '')::bigint,
             nullif(x.sublocatie_id, '')::bigint, nullif(replace(x.norm, ',', '.'), '')::numeric
      from jsonb_to_recordset(p_rijen) x(id text, nr text, naam text, datum text, activiteit_id text, locatie_id text, sublocatie_id text, norm text)
      where nullif(x.datum, '') is not null
    on conflict (id) do update set nr = excluded.nr, naam = excluded.naam, datum = excluded.datum, activiteit_id = excluded.activiteit_id, locatie_id = excluded.locatie_id,
      sublocatie_id = excluded.sublocatie_id, norm = excluded.norm, bijgewerkt = now();
  -- opruimen: alles in de periode p_van..p_tot dat niet (meer) in SSOR staat weghalen (p_rijen = lijst met alle id's in die periode)
  elsif p_tabel in ('uren_opruimen', 'eenheden_opruimen', 'dagtaken_opruimen') then
    if p_van is null or p_tot is null then raise exception 'Geef p_van en p_tot op'; end if;
    if p_tabel = 'uren_opruimen' then
      delete from public.ssor_uren u where u.datum between p_van and p_tot and not exists (select 1 from jsonb_array_elements_text(p_rijen) e where e::bigint = u.id);
    elsif p_tabel = 'eenheden_opruimen' then
      delete from public.ssor_eenheden u where u.datum between p_van and p_tot and not exists (select 1 from jsonb_array_elements_text(p_rijen) e where e::bigint = u.id);
    else
      delete from public.ssor_dagtaken u where u.datum between p_van and p_tot and not exists (select 1 from jsonb_array_elements_text(p_rijen) e where e::bigint = u.id);
    end if;
  -- waarschuwingen van de laatste ronde (leeg = alles gelukt)
  elsif p_tabel = 'waarschuwing' then
    update public.ssor_koppeling set info = info || jsonb_build_object('waarschuwing',
      case when jsonb_array_length(p_rijen) = 0 then null else (select jsonb_agg(e->>'tekst') from jsonb_array_elements(p_rijen) e) end,
      'waarschuwing_tijd', now()) where id = 1;
    return jsonb_build_object('tabel', p_tabel, 'rijen', jsonb_array_length(p_rijen));
  else raise exception 'Onbekende tabel %', p_tabel; end if;
  get diagnostics n = row_count;
  update public.ssor_koppeling set laatst = now(), info = info || jsonb_build_object(p_tabel, jsonb_build_object('tijd', now(), 'rijen', n)) where id = 1;
  return jsonb_build_object('tabel', p_tabel, 'rijen', n);
end $$;
revoke all on function public.ssor_sync(uuid, text, jsonb, date, date) from public;
grant execute on function public.ssor_sync(uuid, text, jsonb, date, date) to anon, authenticated;

-- "Nu bijwerken" in de app en "moet ik bijwerken?" voor het koppelprogramma: alleen aanmaken als ze er nog niet zijn
do $$ begin
  if not exists (select 1 from pg_proc p join pg_namespace s on s.oid = p.pronamespace where s.nspname = 'public' and p.proname = 'ssor_verzoek') then
    execute $f$
      create function public.ssor_verzoek() returns void language plpgsql security definer set search_path = '' as $b$
      begin
        if public.is_apparaat() or not (public.mag_pno() or public.is_beheerder() or public.heeft_recht('resultaten_bekijken') or public.heeft_recht('resultaten_beheren')) then
          raise exception 'Je mag de SSOR-koppeling niet laten bijwerken'; end if;
        update public.ssor_koppeling set info = info || jsonb_build_object('verzoek', now()) where id = 1;
      end $b$;
      revoke all on function public.ssor_verzoek() from public, anon;
      grant execute on function public.ssor_verzoek() to authenticated;
    $f$;
  end if;
  if not exists (select 1 from pg_proc p join pg_namespace s on s.oid = p.pronamespace where s.nspname = 'public' and p.proname = 'ssor_moet') then
    execute $f$
      create function public.ssor_moet(p_sleutel uuid) returns jsonb language plpgsql security definer set search_path = '' as $b$
      declare k public.ssor_koppeling; v timestamptz; g timestamptz;
      begin
        select * into k from public.ssor_koppeling where id = 1;
        if p_sleutel is null or p_sleutel is distinct from k.sleutel then raise exception 'Onbekende sleutel'; end if;
        v := nullif(k.info->>'verzoek', '')::timestamptz; g := nullif(k.info->>'moet_gestart', '')::timestamptz;
        if v is not null and (g is null or v > g) then
          update public.ssor_koppeling set info = info || jsonb_build_object('moet_gestart', now()) where id = 1;
          return jsonb_build_object('moet', true, 'reden', 'Nu bijwerken aangevraagd in de app');
        end if;
        if k.laatst is null or k.laatst < now() - interval '30 minutes' then
          update public.ssor_koppeling set info = info || jsonb_build_object('moet_gestart', now()) where id = 1;
          return jsonb_build_object('moet', true, 'reden', 'Laatste keer meer dan een half uur geleden');
        end if;
        return jsonb_build_object('moet', false, 'reden', null);
      end $b$;
      revoke all on function public.ssor_moet(uuid) from public;
      grant execute on function public.ssor_moet(uuid) to anon, authenticated;
    $f$;
  end if;
end $$;

-- =====================================================================
-- LIJNEN OOK OP DE TABLET (27 november 2026)
-- Sorteerlijnen in SSOR instellen mag nu ook wie voorraad mag boeken (koelcel-tablet), naast het recht
-- lijnen_instellen en de kieptelefoon.
-- =====================================================================
create or replace function public.mag_lijnen() returns boolean language sql stable security definer set search_path = '' as $$
  select public.heeft_recht('lijnen_instellen') or public.heeft_recht('voorraad_beheren')
      or exists (select 1 from public.profielen where id = auth.uid() and werkplek in ('kiep', 'koelcel'));
$$;
grant execute on function public.mag_lijnen() to authenticated;

-- =====================================================================
-- SSOR-LIJNEN: DAGTAAK KIEZEN EN LIJN STOPPEN (28 november 2026)
-- Hoort bij "SSOR-lijnen: wat de app nog moet doen" (28-11). Draai NA ssor-lijnen.sql en ssor-sync-herstel.sql.
-- - ssor_opdrachten krijgt dagtaak_id (DAYJOB.ID) en de soort 'lijn_leeg' (lijn stoppen in de Control Tower)
-- - ssor_dagtaken_vandaag: de dagtaken van vandaag voor de keuzelijst op de tablet
-- - ssor_moet: het grote bijwerken blijft elk half uur, ook nu het koppelprogramma elke 2 minuten
--   de dagtaken van vandaag en de lijnstand meestuurt (die kleine ronde telt niet als "bijgewerkt")
-- - ssor_verzoek (Ververs / Nu bijwerken) mag ook vanaf de tablet die lijnen instelt
-- =====================================================================
alter table public.ssor_opdrachten add column if not exists dagtaak_id bigint;   -- DAYJOB.ID; leeg = dagtaak in de Control Tower laten staan
alter table public.ssor_opdrachten alter column partij drop not null;            -- leeg bij lijn_leeg
do $$ declare c text; begin
  for c in select con.conname from pg_constraint con join pg_class t on t.oid = con.conrelid join pg_namespace n on n.oid = t.relnamespace
            where n.nspname = 'public' and t.relname = 'ssor_opdrachten' and con.contype = 'c' and pg_get_constraintdef(con.oid) ilike '%soort%' loop
    execute format('alter table public.ssor_opdrachten drop constraint %I', c);
  end loop;
end $$;
alter table public.ssor_opdrachten add constraint ssor_opdrachten_soort_check check (soort in ('lijn_instellen', 'lijn_leeg'));

-- de tablet zet een opdracht klaar: lijn instellen (partij, kleuren, dagtaak) of lijn stoppen
drop function if exists public.ssor_lijn_opdracht(text, text, text, jsonb, uuid, text);
create or replace function public.ssor_lijn_opdracht(p_ssor_lijn text, p_partij text default null, p_perceel text default null, p_kleuren jsonb default '[]',
  p_partij_id uuid default null, p_app_lijn text default null, p_dagtaak_id bigint default null, p_soort text default 'lijn_instellen')
returns bigint language plpgsql security definer set search_path = '' as $$
declare i bigint; k jsonb; bezet text;
begin
  if not public.mag_lijnen() then raise exception 'Je mag geen sorteerlijnen instellen (recht "Sorteerlijnen in SSOR instellen")'; end if;
  if nullif(trim(p_ssor_lijn), '') is null then raise exception 'Deze lijn is nog niet aan een SSOR-lijn gekoppeld'; end if;
  if p_soort not in ('lijn_instellen', 'lijn_leeg') then raise exception 'Onbekende opdracht %', p_soort; end if;
  if p_soort = 'lijn_instellen' then
    if nullif(trim(p_partij), '') is null then raise exception 'Kies eerst de partij (scan de box)'; end if;
    if jsonb_typeof(coalesce(p_kleuren, '[]')) <> 'array' then raise exception 'Kleuren moeten een lijst zijn'; end if;
    for k in select * from jsonb_array_elements(coalesce(p_kleuren, '[]')) loop
      if (k->>'kleur') !~ '^\d+$' or (k->>'sortering_id') !~ '^\d+$' then raise exception 'Ongeldige kleur of soort kistje: %', k; end if;
    end loop;
    -- een dagtaak die al op een ándere lijn hangt, neemt de Control Tower niet over
    if p_dagtaak_id is not null then
      select l.naam into bezet from public.ssor_lijn_stand s join public.ssor_lijnen l on l.id = s.lijn_id
       where s.dagtaak_id = p_dagtaak_id and l.naam is distinct from trim(p_ssor_lijn) limit 1;
      if bezet is not null then raise exception 'Deze dagtaak hangt al aan %. Kies een andere dagtaak.', bezet; end if;
    end if;
  end if;
  -- een oudere, nog wachtende opdracht voor dezelfde lijn is achterhaald
  update public.ssor_opdrachten set status = 'fout', fout = 'Vervangen door een nieuwere opdracht', klaar_op = now()
   where ssor_lijn = trim(p_ssor_lijn) and status = 'wacht';
  insert into public.ssor_opdrachten (soort, ssor_lijn, app_lijn, partij, perceel, kleuren, partij_id, dagtaak_id, door_naam)
    values (p_soort, trim(p_ssor_lijn), nullif(trim(p_app_lijn), ''),
            case when p_soort = 'lijn_instellen' then trim(p_partij) end, case when p_soort = 'lijn_instellen' then nullif(trim(p_perceel), '') end,
            case when p_soort = 'lijn_instellen' then coalesce(p_kleuren, '[]') else '[]' end,
            p_partij_id, case when p_soort = 'lijn_instellen' then p_dagtaak_id end, (select naam from public.profielen where id = auth.uid()))
    returning id into i;
  return i;
end $$;
revoke all on function public.ssor_lijn_opdracht(text, text, text, jsonb, uuid, text, bigint, text) from public, anon;
grant execute on function public.ssor_lijn_opdracht(text, text, text, jsonb, uuid, text, bigint, text) to authenticated;

-- opnieuw aanmaken: de rij heeft nu ook dagtaak_id (en soort lijn_leeg)
drop function if exists public.ssor_opdrachten_ophalen(uuid);
create function public.ssor_opdrachten_ophalen(p_sleutel uuid)
returns setof public.ssor_opdrachten language plpgsql security definer set search_path = '' as $$
begin
  if p_sleutel is null or p_sleutel is distinct from (select sleutel from public.ssor_koppeling where id = 1) then raise exception 'Onbekende sleutel'; end if;
  update public.ssor_opdrachten set status = 'fout', fout = 'De uitvoerder reageerde niet (meer dan 15 minuten bezig). Kijk of de lijn loopt.', klaar_op = now()
   where status = 'bezig' and gestart_op < now() - interval '15 minutes';
  return query
    update public.ssor_opdrachten o set status = 'bezig', gestart_op = now()
     where o.id in (select id from public.ssor_opdrachten where status = 'wacht' order by gemaakt_op for update skip locked)
    returning o.*;
end $$;
revoke all on function public.ssor_opdrachten_ophalen(uuid) from public;
grant execute on function public.ssor_opdrachten_ophalen(uuid) to anon, authenticated;

-- de dagtaken van vandaag voor de keuzelijst, met de SSOR-lijn waar ze al aan hangen
create or replace function public.ssor_dagtaken_vandaag()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare d date := (now() at time zone 'Europe/Amsterdam')::date;
begin
  if not (public.mag_lijnen() or public.is_beheerder()) then raise exception 'Je mag geen sorteerlijnen instellen'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'nr', t.nr, 'naam', t.naam, 'datum', t.datum,
      'op_lijn', (select l.naam from public.ssor_lijn_stand s join public.ssor_lijnen l on l.id = s.lijn_id where s.dagtaak_id = t.id limit 1))
      order by nullif(regexp_replace(coalesce(t.nr, ''), '\D', '', 'g'), '')::numeric nulls last, t.naam)
    from public.ssor_dagtaken t where t.datum = d), '[]'::jsonb);
end $$;
revoke all on function public.ssor_dagtaken_vandaag() from public, anon;
grant execute on function public.ssor_dagtaken_vandaag() to authenticated;

-- Ververs / Nu bijwerken: ook vanaf de tablet die lijnen instelt
create or replace function public.ssor_verzoek() returns void language plpgsql security definer set search_path = '' as $$
begin
  if not (public.mag_lijnen() or public.is_beheerder()
          or (not public.is_apparaat() and (public.mag_pno() or public.heeft_recht('resultaten_bekijken') or public.heeft_recht('resultaten_beheren')))) then
    raise exception 'Je mag de SSOR-koppeling niet laten bijwerken';
  end if;
  update public.ssor_koppeling set info = info || jsonb_build_object('verzoek', now()) where id = 1;
end $$;
revoke all on function public.ssor_verzoek() from public, anon;
grant execute on function public.ssor_verzoek() to authenticated;

-- moet het koppelprogramma groot bijwerken? Na een verzoek, of als de laatste grote ronde (die eindigt altijd met
-- 'waarschuwing') meer dan een half uur geleden is. De kleine ronde van elke 2 minuten telt daarvoor niet mee.
create or replace function public.ssor_moet(p_sleutel uuid) returns jsonb language plpgsql security definer set search_path = '' as $$
declare k public.ssor_koppeling; v timestamptz; g timestamptz; vol timestamptz;
begin
  select * into k from public.ssor_koppeling where id = 1;
  if p_sleutel is null or p_sleutel is distinct from k.sleutel then raise exception 'Onbekende sleutel'; end if;
  v := nullif(k.info->>'verzoek', '')::timestamptz; g := nullif(k.info->>'moet_gestart', '')::timestamptz;
  vol := nullif(k.info->>'waarschuwing_tijd', '')::timestamptz;
  if v is not null and (g is null or v > g) then
    update public.ssor_koppeling set info = info || jsonb_build_object('moet_gestart', now()) where id = 1;
    return jsonb_build_object('moet', true, 'reden', 'Nu bijwerken aangevraagd in de app');
  end if;
  -- niet elke 2 minuten opnieuw starten als een grote ronde nog loopt (die duurt soms een paar minuten)
  if (vol is null or vol < now() - interval '30 minutes') and (g is null or g < now() - interval '10 minutes') then
    update public.ssor_koppeling set info = info || jsonb_build_object('moet_gestart', now()) where id = 1;
    return jsonb_build_object('moet', true, 'reden', 'Laatste grote ronde meer dan een half uur geleden');
  end if;
  return jsonb_build_object('moet', false, 'reden', null);
end $$;
revoke all on function public.ssor_moet(uuid) from public;
grant execute on function public.ssor_moet(uuid) to anon, authenticated;
