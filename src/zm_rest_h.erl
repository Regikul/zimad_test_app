-module(zm_rest_h).

-export([
    init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    accept_json/2, provide_json/2
]).

init(Req, State) ->
    lager:info("init with state ~p", [State]),
    {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
    {[<<"GET">>, <<"PUT">>, <<"POST">>, <<"HEAD">>, <<"OPTIONS">>], Req, State}.

content_types_provided(Req, State) ->
    Value = [{{ <<"application">>, <<"json">>, '*'}, provide_json}],
    {Value, Req, State}.

content_types_accepted(Req, State) ->
    Value = [{{ <<"application">>, <<"json">>, '*'}, accept_json}],
    {Value, Req, State}.

accept_json(Req, State) ->
    lager:info("accepting json"),
    {ok, Req,State}.

provide_json(Req, State) ->
    lager:info("providing json"),
    {<<"{}">>, Req, State}.