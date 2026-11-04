-- COOKIE COSMOS — Supabase schema, RLS and secure save function
-- Run the whole script in Supabase Dashboard > SQL Editor > New query.
-- Google OAuth must also be enabled in Authentication > Providers > Google.
-- Never place a Google Client Secret or Supabase service-role key in index.html.

create table if not exists public.cookie_game_saves (
  user_id uuid primary key references auth.users(id) on delete cascade,
  save_data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.cookie_leaderboard (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  total_cookies numeric(30,0) not null default 0 check (total_cookies >= 0),
  updated_at timestamptz not null default now(),
  constraint cookie_username_length check (char_length(username) between 3 and 20),
  constraint cookie_username_chars check (username ~ '^[A-Za-z0-9_ ]+$')
);

create index if not exists cookie_leaderboard_rank_idx
  on public.cookie_leaderboard (total_cookies desc, updated_at asc);

alter table public.cookie_game_saves enable row level security;
alter table public.cookie_leaderboard enable row level security;

drop policy if exists "Players read own cookie save" on public.cookie_game_saves;
create policy "Players read own cookie save"
  on public.cookie_game_saves for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "Anyone can read cookie leaderboard" on public.cookie_leaderboard;
create policy "Anyone can read cookie leaderboard"
  on public.cookie_leaderboard for select to anon, authenticated
  using (true);

revoke all on public.cookie_game_saves from anon, authenticated;
revoke all on public.cookie_leaderboard from anon, authenticated;
grant select on public.cookie_game_saves to authenticated;
grant select on public.cookie_leaderboard to anon, authenticated;

-- This SECURITY DEFINER function executes with its owner's privileges.
-- Run this script in the Supabase SQL Editor as the project postgres owner.
-- auth.uid() ensures the caller can only save their own row.
create or replace function public.save_cookie_game(
  p_username text,
  p_save_data jsonb,
  p_total_cookies numeric
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_username text := btrim(coalesce(p_username, ''));
  v_total numeric := greatest(coalesce(p_total_cookies, 0), 0);
begin
  if v_uid is null then
    raise exception 'You must be signed in to save online';
  end if;

  if v_username !~ '^[A-Za-z0-9_ ]{3,20}$' then
    raise exception 'Username must be 3-20 characters (letters, numbers, spaces or underscores)';
  end if;

  if p_save_data is null or jsonb_typeof(p_save_data) <> 'object' then
    raise exception 'Save data must be a JSON object';
  end if;

  if pg_column_size(p_save_data) > 50000 then
    raise exception 'Save data is too large';
  end if;

  if v_total > 999999999999999999999999999999 then
    raise exception 'Cookie score is out of range';
  end if;

  insert into public.cookie_game_saves(user_id, save_data, updated_at)
  values (v_uid, p_save_data, now())
  on conflict (user_id) do update
    set save_data = excluded.save_data,
        updated_at = now();

  insert into public.cookie_leaderboard(user_id, username, total_cookies, updated_at)
  values (v_uid, v_username, v_total, now())
  on conflict (user_id) do update
    set username = excluded.username,
        total_cookies = greatest(public.cookie_leaderboard.total_cookies, excluded.total_cookies),
        updated_at = now();
end;
$$;

revoke all on function public.save_cookie_game(text, jsonb, numeric) from public;
grant execute on function public.save_cookie_game(text, jsonb, numeric) to authenticated;
