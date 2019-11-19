%%%-------------------------------------------------------------------
%% @doc zimad public API
%% @end
%%%-------------------------------------------------------------------

-module(zimad_app).

-behaviour(application).

-export([start/2, stop/1]).

-define(HTTP_LISTENER, 'tiny_webserver').

start(_StartType, _StartArgs) ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/", zm_rest_h, []}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(?HTTP_LISTENER, [{port, 8080}], #{
        env => #{dispatch => Dispatch}
    }),

    zimad_sup:start_link().

stop(_State) ->
    cowboy:stop_listener(?HTTP_LISTENER),
    ok.

%% internal functions
