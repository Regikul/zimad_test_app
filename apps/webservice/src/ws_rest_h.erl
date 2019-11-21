-module(ws_rest_h).

-export([
    init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    accept_json/2, provide_json/2,
    resource_exists/2
]).

-define(ROUTES, [
    {[<<"registration">>], [<<"PUT">>]},
    {[<<"authorize">>], [<<"PUT">>]},
    {[<<"profile">>], [<<"GET">>, <<"HEAD">>]},
    {[<<"win_level">>], [<<"POST">>]},
    {[<<"buy_stars">>], [<<"POST">>]},
    {[<<"gdrp_erase_profile">>], [<<"POST">>]}
]).

-type http_path() :: list(binary()).
-type http_method() :: binary().
-type http_methods() :: list(binary()).

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
        {Path, Methods} -> Methods
    end.

-spec get_path(cowboy_req:req()) -> http_path().
get_path(Req) ->
    Path = cowboy_req:path(Req),
    binary:split(Path, <<"/">>, [global, trim_all]).

init(Req, State) ->
    lager:info("init with state ~p", [State]),
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
    lager:info("accepting json"),
    {true, Req,State}.

provide_json(Req, State) ->
    lager:info("providing json"),
    {<<"{}">>, Req, State}.

resource_exists(Req, State) ->
    Path = cowboy_req:path(Req),
    lager:info("got req to ~s", [Path]),
    Route = get_path(Req),
    Exists = is_res_exists(Route),
    {Exists, Req, State}.
