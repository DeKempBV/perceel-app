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
  select '{"percelen_tekenen":true,"percelen_bewerken":true,"percelen_verwijderen":false,
           "soorten_indelen":true,"soorten_beheren":false,
           "taken_toevoegen":true,"taken_afvinken":true,"taken_verwijderen":false,
           "markeringen_maken":true,"tractor_rijden":true}'::jsonb;
$$;
alter table public.profielen alter column rechten set default public.standaard_rechten();
-- nieuwe rechten aanvullen, bestaande keuzes blijven staan
update public.profielen set rechten = public.standaard_rechten() || rechten;

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
  using (public.heeft_recht('percelen_bewerken') or public.heeft_recht('soorten_indelen')) with check (true);
create policy "verwijderen" on public.percelen for delete to authenticated using (public.heeft_recht('percelen_verwijderen'));

-- Soort perceel: veld, trayveld, kas of bedrijfspand
alter table public.percelen add column if not exists type text not null default 'veld';
alter table public.percelen drop constraint if exists percelen_type_check;
alter table public.percelen add constraint percelen_type_check check (type in ('veld','tray','kas','pand'));

-- Vakken: deelgebieden met een eigen rijrichting
alter table public.percelen add column if not exists vakken jsonb not null default '[]';
-- Spuitsporen: {elke, start, extra: [nrs], uit: [nrs]}
alter table public.percelen add column if not exists spuit jsonb;

create or replace function public.controleer_perceel() returns trigger language plpgsql as $$
declare
  nv jsonb := (select coalesce(jsonb_agg(v - 'banen'), '[]') from jsonb_array_elements(coalesce(new.vakken, '[]')) v);
  ov jsonb := (select coalesce(jsonb_agg(v - 'banen'), '[]') from jsonb_array_elements(coalesce(old.vakken, '[]')) v);
  nb jsonb := (select coalesce(jsonb_agg(v -> 'banen'), '[]') from jsonb_array_elements(coalesce(new.vakken, '[]')) v);
  ob jsonb := (select coalesce(jsonb_agg(v -> 'banen'), '[]') from jsonb_array_elements(coalesce(old.vakken, '[]')) v);
begin
  if auth.uid() is null then return new; end if;   -- SQL Editor / systeem
  if (new.banen is distinct from old.banen or nb is distinct from ob) and not public.heeft_recht('soorten_indelen') then
    raise exception 'Je mag geen soorten op banen indelen';
  end if;
  if ((new.naam, new.geo, new.richting, new.breedte, new.aantal, new.verschuiving, new.banen_aan, new.type, new.spuit)
     is distinct from (old.naam, old.geo, old.richting, old.breedte, old.aantal, old.verschuiving, old.banen_aan, old.type, old.spuit)
     or nv is distinct from ov)
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
create policy "toevoegen"   on public.taken for insert to authenticated with check (public.heeft_recht('taken_toevoegen'));
create policy "wijzigen"    on public.taken for update to authenticated
  using (public.heeft_recht('taken_afvinken') or public.heeft_recht('taken_toevoegen')) with check (true);
create policy "verwijderen" on public.taken for delete to authenticated using (public.heeft_recht('taken_verwijderen'));

-- Uitgebreide taken: werkzaamheden, wie, welk stuk van het veld
alter table public.taken add column if not exists omschrijving   text;
alter table public.taken add column if not exists toegewezen_aan uuid references public.profielen(id) on delete set null;
alter table public.taken add column if not exists gebied         jsonb;     -- zelf getekend stuk van het veld
alter table public.taken add column if not exists spoor_van      integer;   -- of: sporen van … t/m …
alter table public.taken add column if not exists spoor_tot      integer;

create or replace function public.controleer_taak() returns trigger language plpgsql as $$
begin
  if auth.uid() is null then return new; end if;
  if (new.klaar, new.klaar_door, new.klaar_op) is distinct from (old.klaar, old.klaar_door, old.klaar_op)
     and not public.heeft_recht('taken_afvinken') then
    raise exception 'Je mag taken niet afvinken';
  end if;
  if (new.tekst, new.deadline, new.perceel_id, new.omschrijving, new.toegewezen_aan, new.gebied, new.spoor_van, new.spoor_tot)
     is distinct from (old.tekst, old.deadline, old.perceel_id, old.omschrijving, old.toegewezen_aan, old.gebied, old.spoor_van, old.spoor_tot)
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
create policy "beheer" on public.tractoren for all to authenticated using (public.is_beheerder()) with check (public.is_beheerder());

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
create policy "beheerder" on public.tractor_sleutels for select to authenticated using (public.is_beheerder());
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
