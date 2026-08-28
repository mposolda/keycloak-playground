### Move data to the application context

The current disadvantage of the "fapi-playground" application is, that OIDC client needs to be always re-registered when
application is restarted. The information about the client (together with some other related data like "initial access token")
are stored within `SessionData`, which is application-scoped class, but this class does not survive restart of fapi-playground
application.

Instead of this, I would like to make sure that data, which are currently stored in `SessionData.clientConfigContext`
and `SessionData.registeredClient` and `SessionData.keys` are persisted across application restarts. Other data in `SessionData` should not survive server restart.

I do not want to introduce integration with some "real" database. What I want is something simple like storing those data in JSON file. The behavior should be something like this:

- When application is executed, check if there is directory called `data` inside application root

- If application starts and directory `data` does not exists, then create this directory

- Make sure that when new OIDC client is registered from fapi-playground application, there will be the data, which I want to persist 
(see above) to be stored inside some file into that directory.
The file name could be something like `data/client-data.json`

- Whenever new client is registered by the button "Register client", the application data in that directory `data` should be overwritten

- Whenever application is started and directory `data` exists with that file `client-data.json`, the `SessionData` should be pre-loaded from it.
This means that restarted application will see the client (and initial access token) from the previous run and will not need to
re-register client again.

- It would be nice if directory `data` is put into the `.gitignore` so that it is not stored on github repository

- Regarding implementation, I would like to have the data still saved within `SessionData` class. However it would be nice to have 
some class (maybe something called `PersistentProvider`), which will make sure of pre-load `SessionData` at the server startup (likely at
the time when `SessionData` instance is created) and also will have "save" callback, which will be called always after client registration.
