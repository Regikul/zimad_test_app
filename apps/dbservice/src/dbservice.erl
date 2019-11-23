-module(dbservice).

-include("dbservice.hrl").
-define(AUTH_EXP_TIME_SECONDS, (60*15)).
-define(JWT_SECRET, <<"do_not_steal_this_secret">>).

-export([
    new_user/1,
    get_auth/1,
    get_profile/1,
    win_level/1,
    buy_stars/2,
    gdrp_erase_profile/1
]).

-type result(A, B) :: {ok, A} | {error, B}.

-spec new_user(binary()) -> result(binary(), atom()).
new_user(Username) when is_binary(Username) ->
    UUID = uuid:uuid_to_string(uuid:get_v4()),
    User = #?USERS_TAB{
        uid = UUID,
        nickname = Username,
        coins = 100,
        stars = 0,
        level = 0
    },
    Update = fun () ->
        mnesia:write(User),
        UUID
    end,
    run_transaction(Update).

-spec get_auth(binary()) -> result(binary(), atom()).
get_auth(UUID) ->
    Read = fun () ->
        case mnesia:read(?USERS_TAB, UUID) of
            [] -> false;
            [_] -> true
        end
    end,
    case run_transaction(Read) of
        {ok, true} ->
            Claims = #{
                uid => UUID
            },
            jwt:encode(<<"HS256">>, Claims, ?AUTH_EXP_TIME_SECONDS, ?JWT_SECRET);
        {ok, false} -> {error, bad_uid};
        _Else -> _Else
    end.

-spec get_profile(binary()) -> result(#?USERS_TAB{}, atom()).
get_profile(JWToken) ->
    with_jwtoken(JWToken, fun load_profile/1).

-spec load_profile(map()) -> result(ok, atom()).
load_profile(Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    ReadProfile = fun () ->
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        Profile
    end,
    run_transaction(ReadProfile).

-spec win_level(binary()) -> result(ok, atom()).
win_level(JWToken) ->
    with_jwtoken(JWToken, fun inc_win_level/1).

-spec inc_win_level(map()) -> result(term(), atom()).
inc_win_level(Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    UpdateProfile = fun () ->
        mnesia:write_lock_table(?USERS_TAB),
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        NewWinLevel = Profile#?USERS_TAB.level + 1,
        mnesia:write(Profile#?USERS_TAB{level = NewWinLevel}),
        NewWinLevel
    end,
    run_transaction(UpdateProfile).

-spec buy_stars(binary(), pos_integer()) -> result(term(), atom()).
buy_stars(JWToken, Count) when Count > 0 ->
    with_jwtoken(JWToken, add_stars(Count)).

-spec add_stars(pos_integer()) -> result(term(), atom()).
add_stars(Count) ->
    fun (Claims) -> 
        UUID = maps:get(<<"uid">>, Claims),
        AddStars = fun () ->
            mnesia:write_lock_table(?USERS_TAB),
            [Profile] = mnesia:read(?USERS_TAB, UUID),
            NewStarsCount = Profile#?USERS_TAB.stars + Count,
            mnesia:write(Profile#?USERS_TAB{stars = NewStarsCount}),
            NewStarsCount
        end,
        run_transaction(AddStars)
    end.

-spec gdrp_erase_profile(binary()) -> result(term(), atom()).
gdrp_erase_profile(JWToken) ->
    with_jwtoken(JWToken, fun erase_profile/1).

-spec erase_profile(map()) -> result(term(), atom()).
erase_profile(Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    EraseProfile = fun () ->
        mnesia:delete(?USERS_TAB, UUID, write)
    end,
    run_transaction(EraseProfile).

-spec run_transaction(fun()) -> result(term(), term()).
run_transaction(Fun) ->
    case mnesia:transaction(Fun) of
        {atomic, Value} -> {ok, Value};
        {aborted, Reason} when is_atom(Reason) -> 
            lager:error("error on mnesia ~p", [Reason]),
            {error, Reason};
        {aborted, {{Error, _}, _}} ->
            lager:error("error on mnesia ~p", [Error]),
            {error, Error}
    end.

-type jw_fun(A, B) :: fun( (map()) -> result(A, B) ).
-spec with_jwtoken(binary(), jw_fun(A, B)) -> result(A, B).
with_jwtoken(JWToken, Fun) ->
    case jwt:decode(JWToken, ?JWT_SECRET) of
        {error, expired} = Err -> Err;
        {ok, Claims} -> Fun(Claims)
    end.
