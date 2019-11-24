-module(dbservice).

-include("dbservice.hrl").

-export([
    new_user/1,
    is_exists/1,
    get_profile/1,
    win_level/1,
    buy_stars/2,
    gdrp_erase_profile/1,
    get_secret/1, set_secret/2
]).

-type result(A, B) :: {ok, A} | {error, B}.

-spec new_user(binary()) -> result(binary(), atom()).
new_user(Username) when is_binary(Username) ->
    UUID = list_to_binary(uuid:uuid_to_string(uuid:get_v4())),
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

-spec is_exists(binary()) -> result(binary(), atom()).
is_exists(UUID) ->
    Read = fun () ->
        case mnesia:read(?USERS_TAB, UUID) of
            [] -> false;
            [_] -> true
        end
    end,
    run_transaction(Read).

-spec get_profile(binary()) -> result(#?USERS_TAB{}, atom()).
get_profile(UUID) ->
    ReadProfile = fun () ->
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        Profile
    end,
    run_transaction(ReadProfile).

-spec win_level(binary()) -> result(ok, atom()).
win_level(UUID) ->
    UpdateProfile = fun () ->
        mnesia:write_lock_table(?USERS_TAB),
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        NewWinLevel = Profile#?USERS_TAB.level + 1,
        mnesia:write(Profile#?USERS_TAB{level = NewWinLevel}),
        NewWinLevel
    end,
    run_transaction(UpdateProfile).

-spec buy_stars(binary(), pos_integer()) -> result(term(), atom()).
buy_stars(UUID, Count) when Count > 0 ->
    AddStars = fun () ->
        mnesia:write_lock_table(?USERS_TAB),
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        NewStarsCount = Profile#?USERS_TAB.stars + Count,
        mnesia:write(Profile#?USERS_TAB{stars = NewStarsCount}),
        NewStarsCount
    end,
    run_transaction(AddStars).

-spec gdrp_erase_profile(binary()) -> result(term(), atom()).
gdrp_erase_profile(UUID) ->
    EraseProfile = fun () ->
        mnesia:delete(?USERS_TAB, UUID, write)
    end,
    run_transaction(EraseProfile).

-spec get_secret(binary()) -> binary().
get_secret(UUID) ->
    GetSecret = fun () ->
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        case Profile#?USERS_TAB.secret of
            undefined -> mnesia:abort(no_secret);
            Secret -> Secret
        end
    end,
    run_transaction(GetSecret).

-spec set_secret(binary(), binary() | undefined) -> binary().
set_secret(UUID, NewSecret) ->
    SetSecret = fun () ->
        mnesia:write_lock_table(?USERS_TAB),
        [Profile] = mnesia:read(?USERS_TAB, UUID),
        mnesia:write(Profile#?USERS_TAB{secret = NewSecret}),
        NewSecret
    end,
    run_transaction(SetSecret).

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

