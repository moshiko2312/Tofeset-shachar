-- ============================================================
--  Tofeset Shachar - Supabase setup
--  Run once in Supabase: SQL Editor -> New query -> paste all -> Run
--  Safe to run again later: functions are replaced, data is kept.
-- ============================================================

create extension if not exists pgcrypto with schema extensions;
create schema if not exists tag_private;
revoke all on schema tag_private from public;

-- ---------------------------------------------------------- tables
create table if not exists public.tag_game (
  id                 int primary key default 1 check (id = 1),
  status             text not null default 'registration'
                     check (status in ('registration', 'active', 'finished')),
  title              text not null default 'משחק התופסת',
  join_code          text,
  admin_hash         text not null,
  admin_failed       int not null default 0,
  admin_locked_until timestamptz,
  started_at         timestamptz,
  finished_at        timestamptz,
  winner_id          bigint
);

create table if not exists public.tag_players (
  id            bigint generated always as identity primary key,
  name          text not null,
  pin_hash      text not null,
  position      int not null,
  alive         boolean not null default true,
  caught_by     bigint references public.tag_players(id) on delete set null,
  caught_at     timestamptz,
  failed_logins int not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now()
);
create unique index if not exists tag_players_name_uq on public.tag_players (lower(btrim(name)));

create table if not exists public.tag_catches (
  id          bigint generated always as identity primary key,
  catcher_id  bigint not null references public.tag_players(id) on delete cascade,
  target_id   bigint not null references public.tag_players(id) on delete cascade,
  photo       text,
  status      text not null default 'pending'
              check (status in ('pending', 'confirmed', 'rejected', 'cancelled')),
  reject_reason text,          -- 'tie' = was wearing the scout tie, 'no' = was not caught
  resolved_by text,
  created_at  timestamptz not null default now(),
  resolved_at timestamptz
);
alter table public.tag_catches add column if not exists reject_reason text;
create unique index if not exists tag_catches_one_pending
  on public.tag_catches (catcher_id) where status = 'pending';

-- >>> COUNSELOR (ADMIN) CODE: change 'shachar2026' below before running <<<
-- (used only on the first run; later you can change it from the admin screen)
insert into public.tag_game (id, admin_hash)
values (1, extensions.crypt('shachar2026', extensions.gen_salt('bf')))
on conflict (id) do nothing;

-- Nobody reads or writes the tables directly. Everything goes through the functions below.
alter table public.tag_game    enable row level security;
alter table public.tag_players enable row level security;
alter table public.tag_catches enable row level security;
revoke all on public.tag_game, public.tag_players, public.tag_catches from public;
do $$ begin
  execute 'revoke all on public.tag_game, public.tag_players, public.tag_catches from anon, authenticated';
exception when undefined_object then null; end $$;

-- ---------------------------------------------------------- private helpers
create or replace function tag_private.err(p_msg text) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('error', p_msg);
$$;

-- Who does this player chase? The next living player in registration order (circular).
create or replace function tag_private.target_of(p_id bigint) returns bigint
language sql stable set search_path = '' as $$
  select coalesce(
    (select p.id from public.tag_players p
       where p.alive and p.id <> p_id
         and p.position > (select position from public.tag_players where id = p_id)
       order by p.position limit 1),
    (select p.id from public.tag_players p
       where p.alive and p.id <> p_id
       order by p.position limit 1));
$$;

-- Returns null when the code is right, otherwise an error message. Locks after 8 wrong tries.
create or replace function tag_private.check_pin(p_id bigint, p_pin text) returns text
language plpgsql set search_path = '' as $$
declare v public.tag_players;
begin
  select * into v from public.tag_players where id = p_id for update;
  if not found then return 'השחקן לא נמצא'; end if;
  if v.locked_until is not null and v.locked_until > now() then
    return 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות';
  end if;
  if extensions.crypt(coalesce(p_pin, ''), v.pin_hash) = v.pin_hash then
    if v.failed_logins > 0 then
      update public.tag_players set failed_logins = 0, locked_until = null where id = p_id;
    end if;
    return null;
  end if;
  update public.tag_players
     set failed_logins = case when failed_logins >= 7 then 0 else failed_logins + 1 end,
         locked_until  = case when failed_logins >= 7 then now() + interval '5 minutes' else locked_until end
   where id = p_id;
  return 'קוד שגוי';
end $$;

create or replace function tag_private.check_admin(p_code text) returns text
language plpgsql set search_path = '' as $$
declare g public.tag_game;
begin
  select * into g from public.tag_game where id = 1 for update;
  if g.admin_locked_until is not null and g.admin_locked_until > now() then
    return 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות';
  end if;
  if extensions.crypt(coalesce(p_code, ''), g.admin_hash) = g.admin_hash then
    if g.admin_failed > 0 then
      update public.tag_game set admin_failed = 0, admin_locked_until = null where id = 1;
    end if;
    return null;
  end if;
  update public.tag_game
     set admin_failed       = case when admin_failed >= 7 then 0 else admin_failed + 1 end,
         admin_locked_until = case when admin_failed >= 7 then now() + interval '5 minutes' else admin_locked_until end
   where id = 1;
  return 'קוד מדריך שגוי';
end $$;

-- Ends the game when one player is left, reopens it if more than one is alive again.
create or replace function tag_private.check_finish() returns void
language plpgsql set search_path = '' as $$
declare v_alive int; v_last bigint;
begin
  select count(*), min(id) into v_alive, v_last from public.tag_players where alive;
  if v_alive = 1 then
    update public.tag_game set status = 'finished', finished_at = now(), winner_id = v_last
     where id = 1 and status = 'active';
  elsif v_alive > 1 then
    update public.tag_game set status = 'active', finished_at = null, winner_id = null
     where id = 1 and status = 'finished';
  end if;
end $$;

create or replace function tag_private.apply_catch(p_catch_id bigint, p_by text) returns jsonb
language plpgsql set search_path = '' as $$
declare c public.tag_catches; v_catcher public.tag_players; v_target public.tag_players;
begin
  select * into c from public.tag_catches where id = p_catch_id for update;
  if not found or c.status <> 'pending' then
    return tag_private.err('הבקשה הזאת כבר טופלה');
  end if;
  select * into v_catcher from public.tag_players where id = c.catcher_id;
  select * into v_target  from public.tag_players where id = c.target_id;
  if not v_catcher.alive or not v_target.alive
     or tag_private.target_of(c.catcher_id) is distinct from c.target_id then
    update public.tag_catches set status = 'cancelled', resolved_by = 'system', resolved_at = now()
     where id = c.id;
    return tag_private.err('השרשרת השתנתה בינתיים, הבקשה בוטלה');
  end if;

  update public.tag_players set alive = false, caught_by = c.catcher_id, caught_at = now()
   where id = c.target_id;
  update public.tag_catches set status = 'confirmed', resolved_by = p_by, resolved_at = now()
   where id = c.id;
  -- whatever the caught player had pending against someone else is void now
  update public.tag_catches set status = 'cancelled', resolved_by = 'system', resolved_at = now()
   where status = 'pending' and (catcher_id = c.target_id or target_id = c.target_id);
  perform tag_private.check_finish();
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------- public (kids)
create or replace function public.tag_state() returns jsonb
language sql stable security definer set search_path = '' as $$
  with alive as (
    select id, position from public.tag_players where alive
  ), t as (
    select id,
           coalesce(lead(id) over (order by position),
                    first_value(id) over (order by position)) as target_id
    from alive
  ), cnt as (
    select catcher_id, count(*) as n from public.tag_catches
     where status = 'confirmed' group by catcher_id
  )
  select jsonb_build_object(
    'game', (select jsonb_build_object(
               'status', g.status, 'title', g.title,
               'needs_code', coalesce(btrim(g.join_code), '') <> '',
               'started_at', g.started_at, 'finished_at', g.finished_at,
               'winner_id', g.winner_id)
             from public.tag_game g where g.id = 1),
    'players', coalesce((
      select jsonb_agg(jsonb_build_object(
               'id', p.id, 'name', p.name, 'alive', p.alive,
               'target_id', case when t.target_id = p.id then null else t.target_id end,
               'caught_by', p.caught_by, 'caught_at', p.caught_at,
               'catches', coalesce(cnt.n, 0))
             order by p.position)
      from public.tag_players p
      left join t on t.id = p.id
      left join cnt on cnt.catcher_id = p.id), '[]'::jsonb),
    'feed', coalesce((
      select jsonb_agg(x order by x->>'at' desc) from (
        select jsonb_build_object('catcher', a.name, 'target', b.name, 'at', c.resolved_at) as x
          from public.tag_catches c
          join public.tag_players a on a.id = c.catcher_id
          join public.tag_players b on b.id = c.target_id
         where c.status = 'confirmed'
         order by c.resolved_at desc limit 40) f), '[]'::jsonb),
    'server_time', now());
$$;

create or replace function public.tag_register(p_name text, p_pin text, p_join_code text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare g public.tag_game; v_name text := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'));
        v_id bigint;
begin
  select * into g from public.tag_game where id = 1 for update;
  if g.status <> 'registration' then
    return tag_private.err('ההרשמה סגורה כי המשחק כבר התחיל. פנה למדריך');
  end if;
  if coalesce(btrim(g.join_code), '') <> '' and btrim(coalesce(p_join_code, '')) <> btrim(g.join_code) then
    return tag_private.err('קוד ההצטרפות לא נכון. בקש מהמדריך את הקישור');
  end if;
  if char_length(v_name) < 2 or char_length(v_name) > 30 then
    return tag_private.err('השם צריך להיות בין 2 ל-30 תווים');
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then
    return tag_private.err('הקוד האישי צריך להיות 4 ספרות');
  end if;
  if exists (select 1 from public.tag_players where lower(btrim(name)) = lower(v_name)) then
    return tag_private.err('השם הזה כבר רשום. אם זה אתה, היכנס עם הקוד שלך');
  end if;
  insert into public.tag_players (name, pin_hash, position)
  values (v_name, extensions.crypt(p_pin, extensions.gen_salt('bf')),
          coalesce((select max(position) from public.tag_players), 0) + 1)
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id, 'name', v_name);
end $$;

create or replace function public.tag_login(p_id bigint, p_pin text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; v_name text;
begin
  v_err := tag_private.check_pin(p_id, p_pin);
  if v_err is not null then return tag_private.err(v_err); end if;
  select name into v_name from public.tag_players where id = p_id;
  return jsonb_build_object('ok', true, 'id', p_id, 'name', v_name);
end $$;

create or replace function public.tag_me(p_id bigint, p_pin text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; me public.tag_players; v_target bigint; v_out jsonb; v_in jsonb;
begin
  v_err := tag_private.check_pin(p_id, p_pin);
  if v_err is not null then return tag_private.err(v_err); end if;
  select * into me from public.tag_players where id = p_id;
  if me.alive then v_target := tag_private.target_of(p_id); end if;

  select jsonb_build_object('id', c.id, 'status', c.status, 'reason', c.reject_reason,
                            'resolved_by', c.resolved_by, 'created_at', c.created_at)
    into v_out
    from public.tag_catches c
   where c.catcher_id = p_id and c.target_id = v_target and c.status in ('pending', 'rejected')
   order by c.created_at desc limit 1;

  select jsonb_build_object('id', c.id, 'catcher', a.name, 'photo', c.photo, 'created_at', c.created_at)
    into v_in
    from public.tag_catches c join public.tag_players a on a.id = c.catcher_id
   where c.target_id = p_id and c.status = 'pending'
   order by c.created_at desc limit 1;

  return jsonb_build_object(
    'ok', true,
    'me', jsonb_build_object('id', me.id, 'name', me.name, 'alive', me.alive,
            'caught_at', me.caught_at,
            'caught_by', (select name from public.tag_players where id = me.caught_by),
            'catches', (select count(*) from public.tag_catches
                         where catcher_id = p_id and status = 'confirmed')),
    'target', (select jsonb_build_object('id', id, 'name', name)
                 from public.tag_players where id = v_target),
    'outgoing', v_out,
    'incoming', v_in);
end $$;

create or replace function public.tag_submit_catch(p_id bigint, p_pin text, p_photo text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; g public.tag_game; me public.tag_players; v_target bigint;
begin
  select * into g from public.tag_game where id = 1 for update;
  v_err := tag_private.check_pin(p_id, p_pin);
  if v_err is not null then return tag_private.err(v_err); end if;
  if g.status <> 'active' then return tag_private.err('המשחק לא פעיל כרגע'); end if;
  select * into me from public.tag_players where id = p_id;
  if not me.alive then return tag_private.err('נתפסת, אז אתה כבר לא במשחק'); end if;
  v_target := tag_private.target_of(p_id);
  if v_target is null then return tag_private.err('אין לך את מי לתפוס'); end if;
  if p_photo is null or p_photo !~ '^data:image/' or char_length(p_photo) > 1500000 then
    return tag_private.err('התמונה לא תקינה או גדולה מדי');
  end if;
  if exists (select 1 from public.tag_catches where catcher_id = p_id and status = 'pending') then
    return tag_private.err('כבר שלחת תפיסה שמחכה לאישור');
  end if;
  insert into public.tag_catches (catcher_id, target_id, photo) values (p_id, v_target, p_photo);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_cancel_catch(p_id bigint, p_pin text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_pin(p_id, p_pin);
  if v_err is not null then return tag_private.err(v_err); end if;
  update public.tag_catches set status = 'cancelled', resolved_by = 'catcher', resolved_at = now(), photo = null
   where catcher_id = p_id and status = 'pending';
  return jsonb_build_object('ok', true);
end $$;

-- The caught player answers: true = "yes, I was caught", false = "not true".
-- p_reason when rejecting: 'tie' (I was wearing the scout tie) or 'no' (you did not catch me).
create or replace function public.tag_respond(p_id bigint, p_pin text, p_catch_id bigint,
                                              p_confirm boolean, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; c public.tag_catches;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_pin(p_id, p_pin);
  if v_err is not null then return tag_private.err(v_err); end if;
  select * into c from public.tag_catches where id = p_catch_id;
  if not found or c.target_id <> p_id then return tag_private.err('הבקשה לא נמצאה'); end if;
  if c.status <> 'pending' then return tag_private.err('הבקשה הזאת כבר טופלה'); end if;
  if p_confirm then
    return tag_private.apply_catch(p_catch_id, 'target');
  end if;
  update public.tag_catches
     set status = 'rejected', resolved_by = 'target', resolved_at = now(),
         reject_reason = case when p_reason in ('tie', 'no') then p_reason else 'no' end
   where id = p_catch_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------- admin (counselor)
create or replace function public.tag_admin_state(p_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  return jsonb_build_object(
    'ok', true,
    'join_code', (select join_code from public.tag_game where id = 1),
    'catches', coalesce((
      select jsonb_agg(jsonb_build_object(
               'id', c.id, 'catcher_id', c.catcher_id, 'target_id', c.target_id,
               'catcher', a.name, 'target', b.name, 'status', c.status,
               'reason', c.reject_reason, 'resolved_by', c.resolved_by, 'created_at', c.created_at,
               'resolved_at', c.resolved_at, 'has_photo', c.photo is not null)
             order by c.created_at desc)
        from public.tag_catches c
        join public.tag_players a on a.id = c.catcher_id
        join public.tag_players b on b.id = c.target_id), '[]'::jsonb),
    'locked', coalesce((
      select jsonb_agg(id) from public.tag_players where locked_until > now()), '[]'::jsonb));
end $$;

create or replace function public.tag_admin_photo(p_code text, p_catch_id bigint)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  return jsonb_build_object('ok', true,
    'photo', (select photo from public.tag_catches where id = p_catch_id));
end $$;

create or replace function public.tag_admin_resolve(p_code text, p_catch_id bigint, p_confirm boolean)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  if p_confirm then
    -- the counselor may also approve a catch the caught player rejected
    update public.tag_catches set status = 'pending', resolved_by = null, resolved_at = null
     where id = p_catch_id and status = 'rejected'
       and not exists (select 1 from public.tag_catches x
                        where x.catcher_id = tag_catches.catcher_id and x.status = 'pending');
    return tag_private.apply_catch(p_catch_id, 'admin');
  end if;
  update public.tag_catches set status = 'rejected', resolved_by = 'admin', resolved_at = now()
   where id = p_catch_id and status = 'pending';
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_start(p_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  if (select count(*) from public.tag_players where alive) < 2 then
    return tag_private.err('צריך לפחות 2 שחקנים כדי להתחיל');
  end if;
  update public.tag_game set status = 'active', started_at = now(), finished_at = null, winner_id = null
   where id = 1 and status = 'registration';
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_add_player(p_code text, p_name text, p_pin text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; v_name text := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g')); v_id bigint;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  if char_length(v_name) < 2 or char_length(v_name) > 30 then
    return tag_private.err('השם צריך להיות בין 2 ל-30 תווים');
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then
    return tag_private.err('הקוד האישי צריך להיות 4 ספרות');
  end if;
  if exists (select 1 from public.tag_players where lower(btrim(name)) = lower(v_name)) then
    return tag_private.err('השם הזה כבר רשום');
  end if;
  insert into public.tag_players (name, pin_hash, position)
  values (v_name, extensions.crypt(p_pin, extensions.gen_salt('bf')),
          coalesce((select max(position) from public.tag_players), 0) + 1)
  returning id into v_id;
  perform tag_private.check_finish();
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function public.tag_admin_remove_player(p_code text, p_player_id bigint)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  update public.tag_game set winner_id = null where id = 1 and winner_id = p_player_id;
  delete from public.tag_players where id = p_player_id;
  perform tag_private.check_finish();
  return jsonb_build_object('ok', true);
end $$;

-- Brings a caught player back into the game (undo a mistake).
create or replace function public.tag_admin_revive(p_code text, p_player_id bigint)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  update public.tag_catches set status = 'rejected', resolved_by = 'admin', resolved_at = now()
   where target_id = p_player_id and status = 'confirmed';
  update public.tag_players set alive = true, caught_by = null, caught_at = null where id = p_player_id;
  perform tag_private.check_finish();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_reset_pin(p_code text, p_player_id bigint, p_pin text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then
    return tag_private.err('הקוד האישי צריך להיות 4 ספרות');
  end if;
  update public.tag_players
     set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf')), failed_logins = 0, locked_until = null
   where id = p_player_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_settings(p_code text, p_title text, p_join_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  update public.tag_game
     set title = coalesce(nullif(btrim(p_title), ''), title),
         join_code = nullif(btrim(coalesce(p_join_code, '')), '')
   where id = 1;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_set_code(p_code text, p_new_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  if char_length(coalesce(p_new_code, '')) < 4 then
    return tag_private.err('קוד המדריך צריך להיות לפחות 4 תווים');
  end if;
  update public.tag_game set admin_hash = extensions.crypt(p_new_code, extensions.gen_salt('bf')) where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- p_keep_players = true: same kids, new round. false: empty list, new registration.
create or replace function public.tag_admin_reset(p_code text, p_keep_players boolean)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text;
begin
  perform 1 from public.tag_game where id = 1 for update;
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  delete from public.tag_catches where true;
  if p_keep_players then
    update public.tag_players set alive = true, caught_by = null, caught_at = null where true;
  else
    delete from public.tag_players where true;
  end if;
  update public.tag_game set status = 'registration', started_at = null, finished_at = null, winner_id = null
   where id = 1;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tag_admin_clear_photos(p_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_err text; v_n int;
begin
  v_err := tag_private.check_admin(p_code);
  if v_err is not null then return tag_private.err(v_err); end if;
  update public.tag_catches set photo = null where status <> 'pending' and photo is not null;
  get diagnostics v_n = row_count;
  return jsonb_build_object('ok', true, 'cleared', v_n);
end $$;

-- helpers are internal only
revoke execute on all functions in schema tag_private from public;

-- ask the Supabase API to pick up the new functions right away
notify pgrst, 'reload schema';
