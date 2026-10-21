-- 고정비 가계부 Supabase 스키마
-- Supabase 대시보드 → SQL Editor에서 실행합니다.
-- 테이블은 RLS로 직접 접근을 막고, 비밀번호를 확인하는 함수로만 읽고 씁니다.

create table if not exists public.ledger_docs (
  key        text primary key,          -- 'settings' 또는 'm-2026-10'
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.ledger_docs enable row level security;

-- 비밀번호 확인 (평문 대신 SHA-256 해시를 비교)
create or replace function public.ledger_check(p_pass text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if encode(sha256(convert_to(coalesce(p_pass,''),'UTF8')),'hex')
     <> 'c27ca1e58418a8cc8169f2f36c38969cdfcac0d3ab0eab7659ca74c99518fb09' then
    raise exception 'invalid password' using errcode = '28P01';
  end if;
end $$;

-- 전체 읽기
create or replace function public.ledger_get(p_pass text)
returns table(key text, data jsonb, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  perform public.ledger_check(p_pass);
  return query select d.key, d.data, d.updated_at from public.ledger_docs d;
end $$;

-- 한 문서 저장
create or replace function public.ledger_put(p_pass text, p_key text, p_data jsonb)
returns timestamptz
language plpgsql security definer set search_path = public as $$
declare t timestamptz;
begin
  perform public.ledger_check(p_pass);
  if p_key !~ '^(settings|m-\d{4}-\d{2})$' then raise exception 'invalid key'; end if;
  insert into public.ledger_docs(key, data, updated_at) values (p_key, p_data, now())
  on conflict (key) do update set data = excluded.data, updated_at = now()
  returning updated_at into t;
  return t;
end $$;

revoke all on function public.ledger_check(text) from public, anon, authenticated;
grant execute on function public.ledger_get(text) to anon;
grant execute on function public.ledger_put(text, text, jsonb) to anon;
