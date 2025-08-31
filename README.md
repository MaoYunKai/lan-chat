# lan-chat
The application needs `npcap` to work!!  
A chat application which supports 2 modes:  
> lan-chat and wireless-chat
## mode `lan-chat`
The chat room id is in $[0,65536)$, which supports 65536 lan chat rooms.
## mode `wireless-chat`
This mode require `Microsoft Network Monitor` to work!!  
It also require your net card to support `monitor` mode!!  
The chat room id is in $[-15,-1]$, the absolute value of chat room id is the channel id.  
The -11, -6 and -1 chat room id is the best choice.
