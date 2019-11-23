-ifndef(_COMMONS_HRL).
-define(_COMMONS_HRL, true).

-define(WORKER(Name), #{id => Name, start => {Name, start_link, []}, type => worker}).

-endif.