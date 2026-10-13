-- Run this whole file in Supabase > SQL Editor
create table if not exists log_sources(
  id text primary key, path text, last_line bigint default 0, last_offset bigint default 0,
  last_chain text, updated_at timestamptz default now());

create table if not exists log_events(
  id bigserial primary key, source_id text not null, line_no bigint not null, byte_offset bigint,
  ts timestamptz, category text, event_type text, host text, src_ip text, src_port int,
  dest_ip text, dest_port int, proto text, summary text,
  line_sha256 text not null, chain_hash text not null, status text default 'ok',
  raw jsonb, ingested_at timestamptz default now(), unique(source_id, line_no));
create index if not exists idx_ev_line on log_events(source_id, line_no desc);
create index if not exists idx_ev_cat on log_events(category);

create table if not exists verifications(
  id bigserial primary key, source_id text, status text, started_at timestamptz default now(),
  finished_at timestamptz, lines_checked bigint, events_checked bigint, issues int default 0,
  head_chain text, actor text);

create table if not exists tamper_alerts(
  id bigserial primary key, source_id text, verification_id bigint, kind text, severity text,
  line_no bigint, detail text, detected_at timestamptz default now());

create table if not exists custody_log(
  id bigserial primary key, actor text, action text, detail text, at timestamptz default now());

-- Append-only evidence trail (cannot be edited or deleted)
create or replace function no_mutate() returns trigger as $$
begin raise exception 'append-only table'; end $$ language plpgsql;
drop trigger if exists custody_ro on custody_log;
create trigger custody_ro before update or delete on custody_log for each row execute function no_mutate();
drop trigger if exists alerts_ro on tamper_alerts;
create trigger alerts_ro before update or delete on tamper_alerts for each row execute function no_mutate();

-- Allow the anon key (demo setup). Tighten for production.
do $$ declare t text; begin
  foreach t in array array['log_sources','log_events','verifications','tamper_alerts','custody_log'] loop
    execute format('alter table %I enable row level security', t);
    execute format('drop policy if exists "anon all" on %I', t);
    execute format('create policy "anon all" on %I for all to anon using (true) with check (true)', t);
  end loop; end $$;
