
-- Proxy Gateway Manager - Postgres schema v1.1

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  password_hash text not null,
  role text not null check (role in ('admin','viewer')),
  created_at timestamptz not null default now()
);

create table if not exists proxies (
  id uuid primary key default gen_random_uuid(),
  label text,
  type text not null check (type in ('http','socks5')),
  host text not null,
  port int not null check (port > 0 and port <= 65535),
  username text,
  password text,
  enabled boolean not null default true,
  status text not null default 'DOWN' check (status in ('OK','DEGRADED','DOWN')),
  latency_ms int,
  exit_ip inet,
  last_checked_at timestamptz
);
create index if not exists idx_proxies_status on proxies(status);

create table if not exists clients (
  id uuid primary key default gen_random_uuid(),
  ip_cidr cidr not null unique,
  note text,
  enabled boolean not null default true
);

create table if not exists mappings (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references clients(id) on delete cascade,
  proxy_id uuid not null references proxies(id) on delete restrict,
  protocol text not null check (protocol in ('http','socks5')),
  local_redirect_port int not null,
  state text not null default 'PENDING' check (state in ('APPLIED','PENDING','FAILED')),
  last_applied_at timestamptz
);
create unique index if not exists idx_mappings_client_unique on mappings(client_id);

create table if not exists audit_log (
  id bigserial primary key,
  actor uuid,
  action text not null,
  entity text not null,
  entity_id uuid,
  payload jsonb,
  created_at timestamptz not null default now()
);

-- Helper view for UI
create or replace view mapping_view as
select m.id,
       m.local_redirect_port,
       m.state,
       c.id as client_id,
       c.ip_cidr,
       p.id as proxy_id,
       p.type as proxy_type,
       (p.host || ':' || p.port) as proxy_addr,
       p.username,
       p.status,
       p.latency_ms,
       p.exit_ip
from mappings m
join clients c on c.id = m.client_id
join proxies p on p.id = m.proxy_id;
