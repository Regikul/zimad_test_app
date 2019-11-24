-module(ws_rest_h).

-export([
    init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    accept_json/2, provide_json/2,
    resource_exists/2,
    gen_secret/2
]).

-define(AUTH_EXP_TIME_SECONDS, (60*15)).
-define(JWT_SECRET, <<"do_not_steal_this_secret">>).
-define(ALPHABET, <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz">>).

-define(ROUTES, [
    {[<<"registration">>],       [<<"PUT">>],             fun make_reg/2},
    {[<<"authorize">>],          [<<"PUT">>],             fun make_auth/2},
    {[<<"profile">>],            [<<"GET">>, <<"HEAD">>], fun get_profile/2},
    {[<<"win_level">>],          [<<"POST">>],            fun update_wins/2},
    {[<<"buy_stars">>],          [<<"POST">>],            fun update_stars/2},
    {[<<"gdrp_erase_profile">>], [<<"POST">>],            fun erase_profile/2}
]).

-type http_path() :: list(binary()).
-type http_method() :: binary().
-type http_methods() :: list(http_method()).

-spec is_res_exists(http_path()) -> boolean().
is_res_exists(Path) ->
    case lists:keyfind(Path, 1, ?ROUTES) of
        false -> false;
        _Else -> true
    end.

-spec get_allowed_methods(http_path()) -> http_methods().
get_allowed_methods(Path) ->
    case lists:keyfind(Path, 1, ?ROUTES) of
        false -> [<<"GET">>, <<"HEAD">>];
        {Path, Methods, _} -> Methods
    end.

-type req_handler(T) :: fun( (cowboy_req:req(), term()) -> {T, cowboy_req:req(), term()}).
-spec get_handler(http_path()) -> req_handler(term()).
get_handler(Path) ->
    case lists:keyfind(Path, 1, ?ROUTES) of
        {Path, _, Handler} -> Handler
    end.

-spec get_path(cowboy_req:req()) -> http_path().
get_path(Req) ->
    Path = cowboy_req:path(Req),
    binary:split(Path, <<"/">>, [global, trim_all]).

init(Req, State) ->
    {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
    Path = get_path(Req),
    {get_allowed_methods(Path), Req, State}.

content_types_provided(Req, State) ->
    Value = [{{ <<"application">>, <<"json">>, '*'}, provide_json}],
    {Value, Req, State}.

content_types_accepted(Req, State) ->
    Value = [{{ <<"application">>, <<"json">>, '*'}, accept_json}],
    {Value, Req, State}.

accept_json(Req, State) ->
    Path = get_path(Req),
    lager:info("accepting json for path ~p", [Path]),
    Fun = get_handler(Path),
    Fun(Req, State).

provide_json(Req, State) ->
    Path = get_path(Req),
    lager:info("providing json for path ~p", [Path]),
    Fun = get_handler(Path),
    Fun(Req, State).

resource_exists(Req, State) ->
    Path = cowboy_req:path(Req),
    lager:info("got req to ~s", [Path]),
    Route = get_path(Req),
    Exists = is_res_exists(Route),
    {Exists, Req, State}.

-spec make_reg(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
make_reg(Req, State) ->
    {Body, Req0} = get_body_data(Req),
    Json = get_req_data(Body),
    lager:info("got body ~p", [Json]),
    Nick = maps:get(<<"nickname">>, Json),
    case dbservice:new_user(Nick) of
        {ok, UUID} ->
            Created = #{<<"uid">> => UUID},
            Req1 = cowboy_req:set_resp_body(mk_resp_body(Created), Req0),
            {true, Req1, State};
        {error, _} ->
            datastore_fault(Req0, State)
    end.

-spec make_auth(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
make_auth(Req, State) ->
    {Body, Req0} = get_body_data(Req),
    Json = get_req_data(Body),
    UUID = maps:get(<<"uid">>, Json),
    case dbservice:is_exists(UUID) of
        {ok, true} -> 
            generate_jwt(UUID, Req0, State);
        {ok, false} ->
            mk_err_body(<<"bad uid">>, Req0, State);
        {error, _} ->
            datastore_fault(Req0, State)
    end.

-spec generate_jwt(binary(), cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
generate_jwt(UUID, Req, State) ->
    Secret = gen_secret(8, <<>>),
    case dbservice:set_secret(UUID, Secret) of
        {ok, Secret} ->
            Claims = #{<<"uid">> => UUID},
            {ok, JWT} = jwt:encode(<<"HS256">>, Claims, ?AUTH_EXP_TIME_SECONDS, Secret),
            Auth = #{<<"auth_token">> => JWT},
            Req0 = cowboy_req:set_resp_body(mk_resp_body(Auth), Req),
            {true, Req0, State};
        {error, _} ->
            datastore_fault(Req, State)
    end.

-spec get_profile(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
get_profile(Req, State) ->
    with_auth_token(Req, State, fun load_profile/2).

load_profile(Req, Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    lager:info("loking for profile with UUID(~s)", [UUID]),
    case dbservice:get_profile(UUID) of
        {ok, Profile} ->
            JProfile = #{
                <<"uid">> => element(2, Profile),
                <<"nickname">> => element(3, Profile),
                <<"coins">> => element(4, Profile),
                <<"stars">> => element(5, Profile),
                <<"level">> => element(6, Profile)
            },
            lager:info("got profile: ~p", [JProfile]),
            {mk_resp_body(JProfile), Req, Claims};
        {error, _} ->
            mk_err_body(<<"datastore fault">>, Req, Claims)
    end.

-spec update_wins(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
update_wins(Req, State) ->
    with_auth_token(Req, State, fun inc_win/2).

-spec inc_win(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
inc_win(Req, Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    lager:info("updating win_level of UUID(~s)", [UUID]),
    case dbservice:win_level(UUID) of
        {ok, NewWins} ->
            Response = #{
                <<"wins_count">> => NewWins
            },
            NewReq = cowboy_req:set_resp_body(mk_resp_body(Response), Req),
            {true, NewReq, Claims};
        {error, _} ->
            datastore_fault(Req, Claims)
    end.

-spec update_stars(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
update_stars(Req, State) ->
    with_auth_token(Req, State, fun add_stars/2).

-spec add_stars(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
add_stars(Req, Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    {Body, Req0} = get_body_data(Req),
    ReqJson = get_req_data(Body),
    Stars = maps:get(<<"stars_count">>, ReqJson),
    lager:info("updating stars for UUID(~s)", [UUID]),
    case dbservice:buy_stars(UUID, Stars) of
        {ok, NewStars} ->
            lager:info("got new stars count: ~p", [NewStars]),
            Response = #{
                <<"stars_count">> => NewStars
            },
            NewReq = cowboy_req:set_resp_body(mk_resp_body(Response), Req0),
            {true, NewReq, Claims};
        {error, _} ->
            datastore_fault(Req, Claims)
    end.

-spec erase_profile(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
erase_profile(Req, State) ->
    with_auth_token(Req, State, fun gdrp_delete/2).

-spec gdrp_delete(cowboy_req:req(), term()) -> {boolean(), cowboy_req:req(), term()}.
gdrp_delete(Req, Claims) ->
    UUID = maps:get(<<"uid">>, Claims),
    lager:info("trying to delete profile with UUID(~s) by GDRP request", [UUID]),
    case dbservice:gdrp_erase_profile(UUID) of
        {ok, _} ->
            NewReq = cowboy_req:set_resp_body(mk_resp_body(#{}), Req),
            {true, NewReq, Claims};
        {error, _} ->
            datastore_fault(Req, Claims)
    end.

-spec get_body_data(cowboy_req:req()) -> {binary(), cowboy_req:req()}.
get_body_data(Req) ->
    get_body_data(Req, <<>>).

-spec get_body_data(cowboy_req:req(), binary()) -> {binary(), cowboy_req:req()}.
get_body_data(Req, Acc) ->
    case cowboy_req:read_body(Req) of
        {ok, Body, NewReq} -> {<<Acc/binary, Body/binary>>, NewReq};
        {more, Part, NewReq} -> get_body_data(NewReq, <<Acc/binary, Part/binary>>)
    end.

-spec get_req_data(binary()) -> map() | undefined.
get_req_data(Data) ->
    Map = jsx:decode(Data, [return_maps]),
    maps:get(<<"data">>, Map).

-spec mk_resp_body(map()) -> map().
mk_resp_body(Body) when is_map(Body) ->
    Resp = #{
        <<"status">> => <<"success">>,
        <<"data">> => Body
    },
    jsx:encode(Resp).

-spec mk_err_body(binary(), cowboy_req:req(), term()) -> map().
mk_err_body(Reason, Req, State) ->
    Resp = #{
        <<"status">> => <<"error">>,
        <<"reason">> => Reason
    },
    Body = jsx:encode(Resp),
    case lists:member(cowboy_req:method(Req), [<<"GET">>, <<"HEAD">>]) of
        true -> 
            {Body, Req, State};
        false ->
            NewReq = cowboy_req:set_resp_body(Body, Req),
            {false, NewReq, State}
    end.

-spec get_auth_token(cowboy_req:req()) -> binary().
get_auth_token(Req) ->
    cowboy_req:header(<<"x-auth-token">>, Req).

-type http_handler(T) :: fun( (cowboy_req:req(), term()) -> {T, cowboy_req:req(), term()}).
-spec with_auth_token(cowboy_req:req(), term(), http_handler(T)) -> {T, cowboy_req:req(), term()}.
with_auth_token(Req, State, Handler) ->
    JWToken = get_auth_token(Req),
    Secret = get_secret_for_jwt(JWToken),
    case Secret =/= undefined andalso jwt:decode(JWToken, Secret) of
        false -> 
            mk_err_body(<<"can not check auth token">>, Req, State);
        {error, expired} -> 
            mk_err_body(<<"token expired">>, Req, State);
        {error, invalid_token} ->
            mk_err_body(<<"invalid token">>, Req, State);
        {error, invalid_signature} ->
            mk_err_body(<<"invalid signature">>, Req, State);
        {ok, Claims} -> Handler(Req, Claims)
    end.

-spec get_secret_for_jwt(binary()) -> binary() | undefined.
get_secret_for_jwt(JWT) ->
    UUID = case binary:split(JWT, <<".">>, [global, trim_all]) of
        [_Header, Claims64, _Signature] ->
            JSON = base64:decode(Claims64),
            JObj = jsx:decode(JSON, [return_maps]),
            maps:get(<<"uid">>, JObj);
        _Else -> undefined
    end,
    case UUID =/= undefined andalso dbservice:get_secret(UUID) of
        {ok, S} -> S;
        _Otherwise -> undefined
    end.

-spec datastore_fault(cowboy_req:req(), term()) -> {false, cowboy_req:req(), term()}.
datastore_fault(Req, State) ->
    mk_err_body(<<"datastore fault">>, Req, State).

-spec gen_secret(pos_integer(), binary()) -> binary().
gen_secret(Length, Acc) when Length =:= 0 ->
    Acc;
gen_secret(Length, Acc) when Length > 0 ->
    Index = rand:uniform(byte_size(?ALPHABET)) - 1,
    Char = binary:at(?ALPHABET, Index),
    gen_secret(Length - 1, <<Acc/binary, Char>>).
