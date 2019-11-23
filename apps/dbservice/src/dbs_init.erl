-module(dbs_init).

-behaviour(gen_server).

-include("dbservice.hrl").

%% API
-export([start_link/0]).

-export([
    init/1
]).

start_link() ->
    gen_server:start_link(?MODULE, [], []).

init(_Args) ->
    case mnesia:create_schema([node()]) of
        ok -> lager:debug("trying to create tables");
        {error, _} -> lager:notice("tables should be created")
    end,
    mnesia:start(),
    create_tables(),
    ignore.

create_tables() ->
    mnesia:create_table(?USERS_TAB, [
        {disc_copies, [node()]},
        {attributes, record_info(fields, ?USERS_TAB)}
    ]).
