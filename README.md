# lan-chat
**The application needs `npcap` to work!!**  
A chat application which supports 2 modes:  
> lan-chat and wireless-chat

It also supports message sending, group chat and P2P file transfer.
## mode `lan-chat`
The chat room id is in $[0,65536)$, which can hold up to 65536 chat rooms in the same LAN.
## mode `wireless-chat`
**This mode requires `Microsoft Network Monitor` to work!!**  
It also require your net card to support `monitor` mode!!  
The chat room id is in $[-15,-1]$, the absolute value of chat room id is the channel id.  
The -11, -6 and -1 chat room id is the best choice.

Note: the `jit` pyd has the same logic as `_jit.py` but written in C++ (which code is in `a_main.cpp`, to support Nuitka building. (Nuitka doesn't support Numba)

## Features
 1. hidden: In lan mode, it use IPSec message transfer and UDP broadcast discover to hide it's Network.(also uses randomized UDP data and fixed IPSec data size)
 2. safe: It uses ECDH handshaking and RSA plus AES encryption, which adds safety.
 3. convenient: In wireless mode, it use RSBCH correction code, dynamic lengthing based on rssi and loss, as well as retransmission, in order to ensure data integrity.

## Problems
1. speed: The file send speed is very slow. (About 30KB/s)
2. wireless concealment: The wireless data doesn't have fixed length.
