-ifndef(_DBSERVICE_HRL).
-define(_DBSERVICE_HRL, true).

-define(USERS_TAB, profile).

-record(?USERS_TAB, {
    uid :: binary(),
    nickname :: binary(),
    coins = 100 :: non_neg_integer(),
    stars = 0 :: non_neg_integer(),
    level = 0 :: non_neg_integer(),
    secret :: binary()
}).

-endif.