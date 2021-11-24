# SecureRemotePassword protocol for WoW
 
SRP is a secure password-based authentication and key-exchange protocol.
Using SRP avoids sending the plaintext password unencrypted.
[This lua module](https://github.com/esno/srp) implements the SRP authentication mechanism for WoW.

## Authentication workflow

    User                                     Host
     |                                         |
     |                                         |
     |   authentication challenge request      | (I)
     | --------------------------------------> |
     |                                         |
     |   authentication challenge response     | (B, g, N, s)
     | <-------------------------------------- |
     |                                         |
     |   authentication logon proof request    | (A, M1)
     | --------------------------------------> |
     |                                         |
     |   authentication logon proof response   | (M2)
     | <-------------------------------------- |
     |                                         |

> The host MUST send B after receiving A from the client, never before.
[RFC2945](https://datatracker.ietf.org/doc/html/rfc2945)

This is a deviation of the origin SRP specification where [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054)
requires to send the host public ephemeral (B) in it's server key exchange message.

Further information can be read [here](http://srp.stanford.edu/).

### Parameters

    | Parameter | Description                  |
    | --------- | ---------------------------- |
    | a         | Private user ephemeral       |
    |           | 19 byte random number        |
    | A         | Public user ephemeral        |
    | b         | Private host ephemeral       |
    |           | 19 byte random number        |
    | B         | Public host ephemeral        |
    | g         | Generator                    |
    | I         | Identifier                   |
    |           | The plaintext account name   |
    | k         | multiplier                   |
    | K         | The hashed secret key        |
    | M1        | The first message proof      |
    | M2        | The second message proof     |
    | N         | A safe/large prime           |
    | p         | sha1(USERNAME:PASSWORD)      |
    |           | Deviates from RFC where p is |
    |           | the raw password             |
    | s         | A random salt                |
    | S         | The session key              |
    | u         | Random scrambling parameter  |
    | v         | The password verifier        |
    | x         | Private key                  |
    |           | Derived from p and s         |

### Calculate salt and verifier

The salt (s) is a random 32 byte large number and the verifier (v)
is calculated as:

    v = g ^ x % N

While `N` is a large prime number, it may take a lot of time to compute one
therefore most implementations use static values for `g` and `N`.

[MaNGOS](https://getmangos.eu) based emulators are using this values:

    N = 894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7
    g = 7

Those values could be variable per account since the client extracts them from
the initial authentication challenge response. Changing such values afterwards
will break already calculated password verifier.

The value of `x` can be generated as sha1 hash of the salt concatenated with
a sha1 hash of the string `USERNAME:PASSWORD`. The official clients convert
all lowercase letters into it's uppercase equivalent.

## Build from source

srp works properly with at least lua 5.3

    $ sudo apt-get install build-essential cmake git libssl-dev
    $ sudo apt-get install lua5.3 liblua5.3-dev

    $ git clone https://github.com/esno/srp.git && cd srp
    $ mkdir build && cd build
    $ cmake .. && make
    $ sudo make install

### Uninstall

`make install` generates the file `install_manifest.txt` in your build directory.
This can be used to delete all installed files.

    $ xargs rm < install_manifest.txt
