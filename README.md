# SRP module for WoW emulators

this lua module implements the SRP authentication mechanism for WoW.
SRP is a secure password-based authentication and key-exchange protocol.
Using SRP avoids sending the plaintext password unencrypted.

## authentication workflow

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

### authentication challenge

The user starts the authentication by sending a authentication challenge request.

    | command | error | packet size | game name | version 1 | version 2 | version 3 | build | platform | OS | locale | timezone bias | ip address | I length | I |

The value of command for the authentication challenge is `0x00`.

The host responds by sending a response.

    | command | error | B | g length | g | N length | N | s |

## build from source

srp works properly with at least lua 5.3

    $ sudo apt-get install build-essential cmake git libssl-dev
    $ sudo apt-get install lua5.3 liblua5.3-dev

    $ git clone https://github.com/esno/srp.git && cd srp
    $ mkdir build && cd build
    $ cmake .. && make
    $ sudo make install

### uninstall

`make install` generates the file `install_manifest.txt` in your build directory.
This can be used to delete all installed files.

    $ xargs rm < install_manifest.txt
