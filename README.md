# SRP module for WoW emulators

this lua module implements the SRP authentication mechanism for WoW emulators.

## example client

the example client creates `v` and `s` values that can be inserted into the accounts table of
your realmd database.

    $ wowpasswd johndoe
    Password: topsecret
    v: 2AC0D7DA1BB846EE917B281A9C01C5E0E7A0B121AC51F5C77F4F26522D71F1C6
    s: AA8B4FFC9D83B3A5F2EA919A53991183B7860F298A59E9999742F1FA9F52FC23

## build from source

    git clone https://github.com/esno/srp.git && cd srp
    mkdir build && cd build
    cmake .. && make
    sudo make install
