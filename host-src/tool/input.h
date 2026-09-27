#ifndef __INPUT_H__
#define __INPUT_H__

 ///////////////////////////////
 // NETWORK INPUT FUNCTIONS //
 ///////////////////////////////

 // Loads an optional input module (ps2link-input.h ABI v1) by path or by
 // name ("keyboard" -> input-keyboard.so beside the client, then in the
 // working directory). Repeat for up to eight modules; their states merge.
 // Returns -1 when it is missing, incompatible or already loaded.
 int input_load_module(const char *name);

 // Streams the merged controller state to the console loader (ps2link P5,
 // dcload P8) until input_stop(), and opens the loopback control port
 // (INPUT_CONTROL_PORT; default INPUT_CONTROL_DEFAULT_PORT, 18199 for
 // ps2client) that loads, unloads and reloads modules by text datagram:
 //   list | load <name|path> | unload <name> | reload <name>
 // Without --input both calls do nothing.
 int input_start(const char *hostname);

 // Releases every control, ends the session and unloads the modules.
 void input_stop(void);

#endif
