%%%-------------------------------------------------------------------
%% @doc webservice public API
%% @end
%%%-------------------------------------------------------------------

-module(webservice_app).

-behaviour(application).

-export([start/2, stop/1]).

-define(HTTP_LISTENER, 'tiny_webserver').

start(_StartType, _StartArgs) ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {'_', ws_rest_h, []}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(?HTTP_LISTENER, [{port, 8080}], #{
        env => #{dispatch => Dispatch}
    }),
    webservice_sup:start_link().

stop(_State) ->
    cowboy:stop_listener(?HTTP_LISTENER),
    ok.

%% internal functions
