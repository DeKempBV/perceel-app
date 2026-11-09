-- ============================================================
--  Perceel App – database
--  Plak dit hele bestand in Supabase → SQL Editor → Run
-- ============================================================

create table if not exists public.soorten (
  id          uuid primary key default gen_random_uuid(),
  naam        text not null,
  kleur       text not null default '#9e9e9e',
  created_at  timestamptz not null default now()
);

create table if not exists public.percelen (
  id              uuid primary key default gen_random_uuid(),
  naam            text not null,
  geo             jsonb not null,                 -- vorm van het perceel (GeoJSON)
  richting        numeric not null default 0,     -- GPS-richting AB-lijn in graden
  breedte         numeric not null default 3,     -- baanbreedte in meters
  aantal          integer not null default 0,     -- 0 = hele perceel vullen
  verschuiving    numeric not null default 0,     -- banen opzij schuiven (m)
  banen_aan       boolean not null default false,
  banen           jsonb not null default '[]',    -- soort-id per baan
  aangemaakt_door text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create table if not exists public.taken (
  id              uuid primary key default gen_random_uuid(),
  perceel_id      uuid not null references public.percelen(id) on delete cascade,
  tekst           text not null,
  deadline        date,
  klaar           boolean not null default false,
  klaar_door      text,
  klaar_op        timestamptz,
  aangemaakt_door text,
  created_at      timestamptz not null default now()
);

-- Voor later: GPS-kastjes op de tractoren schrijven hier hun positie in
create table if not exists public.tractoren (
  id          uuid primary key default gen_random_uuid(),
  naam        text not null,
  lat         double precision,
  lng         double precision,
  richting    numeric,
  snelheid    numeric,
  bijgewerkt  timestamptz not null default now()
);

-- Alleen ingelogde teamleden mogen lezen en schrijven
alter table public.soorten   enable row level security;
alter table public.percelen  enable row level security;
alter table public.taken     enable row level security;
alter table public.tractoren enable row level security;

drop policy if exists "team" on public.soorten;
drop policy if exists "team" on public.percelen;
drop policy if exists "team" on public.taken;
drop policy if exists "team" on public.tractoren;
create policy "team" on public.soorten   for all to authenticated using (true) with check (true);
create policy "team" on public.percelen  for all to authenticated using (true) with check (true);
create policy "team" on public.taken     for all to authenticated using (true) with check (true);
create policy "team" on public.tractoren for all to authenticated using (true) with check (true);

-- Live bijwerken: iedereen ziet wijzigingen meteen
alter publication supabase_realtime add table public.soorten, public.percelen, public.taken, public.tractoren;

-- Startlijst met soorten (kun je in de app aanpassen)
insert into public.soorten (naam, kleur) values
  ('Aardappel',  '#c9a227'),
  ('Tarwe',      '#e8cf7a'),
  ('Maïs',       '#7cb342'),
  ('Ui',         '#ab47bc'),
  ('Suikerbiet', '#ef6c00'),
  ('Gras',       '#2e7d32'),
  ('Braak',      '#8d6e63');
