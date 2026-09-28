 #include <stdio.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include <unistd.h>
 #include <pthread.h>
#ifdef _WIN32
 #include <winsock2.h>  // must precede windows.h
 #include <windows.h>
#else
 #include <dlfcn.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <sys/select.h>
 #include <sys/socket.h>
#endif
 #include "ps2link-input.h"
 #include "input.h"

 // The modules are polled every millisecond and a changed state is sent at
 // once; an unchanged one is resent every heartbeat. The console expires a
 // state after INPUT_VALID_MS without a newer one, so a lost datagram costs
 // nothing. Changes are spaced at least INPUT_MIN_GAP_MS apart: a moving
 // analog stick changes on nearly every poll, and ~250 datagrams/s is ample
 // for a game that samples input once per 16.7 ms frame.
 #define INPUT_POLL_MS      1
 #define INPUT_MIN_GAP_MS   4
 #define INPUT_HEARTBEAT_MS 16
 #define INPUT_VALID_MS     250
#define INPUT_GO_MS        500

 // Several modules drive the console together: buttons combine, each stick
 // axis takes the most deflected source and each trigger the strongest.
 // While streaming, a loopback control port loads, unloads and reloads
 // modules by text command (see input.h).
 #define INPUT_MAX_MODULES    8
 #ifndef INPUT_CONTROL_DEFAULT_PORT   // one per client, so tandem clients coexist
 #define INPUT_CONTROL_DEFAULT_PORT 0x4717
 #endif
 #define INPUT_CONTROL_WAIT_MS 100

 typedef struct {
  char label[64];                       // "gamepad" for input-gamepad.so
  char path[1024 + 64];                 // as resolved, for reload
  void *handle;
  const ps2_input_module_v1_t *api;
  int started;
 } input_slot_t;

 static input_slot_t input_slots[INPUT_MAX_MODULES];
 static pthread_mutex_t input_lock = PTHREAD_MUTEX_INITIALIZER;
 static pthread_t input_thread_id, input_control_id;
 // input_lock guards running and the go request as well as the slots.
 static int input_running = 0;
 static int input_requested = 0;       // --input was given
 static int input_go_armed = 0;        // a go deadline is pending
 static uint32_t input_go_until = 0;   // SYNC_GO on every datagram until then
 static int input_go_now = 0;          // send the first GO datagram at once
 static int input_socket = -1;
 static int input_control_socket = -1;
 static uint32_t input_session = 0;
 static uint32_t input_sequence = 0;

 ///////////////////////////////
 // NETWORK INPUT FUNCTIONS //
 ///////////////////////////////

 // This file is shared verbatim by ps2client and dc-tool-ip; it owns its
 // sockets (the client has started Winsock).
 static void input_socket_close(int sock) {
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif
 }

 static int input_connect(const char *hostname, int port) {
  struct hostent *host = gethostbyname(hostname);
  struct sockaddr_in addr;
  int sock;
  if (!host) { return -1; }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr = *(struct in_addr *)host->h_addr;
  sock = (int)socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) { return -1; }
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { input_socket_close(sock); return -1; }
  return sock;
 }

 static void *input_open(const char *path) {
#ifdef _WIN32
  return (void *)LoadLibraryA(path);
#else
  return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
 }

 static void input_close(void *handle) {
#ifdef _WIN32
  FreeLibrary((HMODULE)handle);
#else
  dlclose(handle);
#endif
 }

 static const ps2_input_module_v1_t *input_entry(void *handle) {
  ps2_input_module_get_v1_fn get = NULL;
#ifdef _WIN32
  get = (ps2_input_module_get_v1_fn)(void (*)(void))GetProcAddress((HMODULE)handle, PS2_INPUT_MODULE_ENTRY);
#else
  *(void **)&get = dlsym(handle, PS2_INPUT_MODULE_ENTRY);
#endif
  return get ? get() : NULL;
 }

 // "lib/input-gamepad.so" and "gamepad" both name "gamepad".
 static void input_label(const char *name, char *label, size_t size) {
  const char *base = name, *p;
  for (p = name; *p; p++) { if (*p == '/' || *p == '\\') { base = p + 1; } }
  if (strncmp(base, "input-", 6) == 0) { base += 6; }
  snprintf(label, size, "%s", base);
  size_t n = strlen(label);
  if (n > 3 && strcmp(label + n - 3, ".so") == 0) { label[n - 3] = 0; }
 }

 // A path is used as given; a bare name is "input-<name>.so" beside this
 // executable, then in the working directory.
 static void *input_resolve(const char *name, char *path, size_t size) {
  void *handle;
  snprintf(path, size, "%s", name);
  if ((handle = input_open(path))) { return handle; }
#ifdef _WIN32
  char exe[1024]; DWORD n = GetModuleFileNameA(NULL, exe, sizeof(exe));
  char *slash = (n > 0 && n < sizeof(exe)) ? strrchr(exe, '\\') : NULL;
  if (slash) { *slash = 0; snprintf(path, size, "%s\\input-%s.so", exe, name); if ((handle = input_open(path))) { return handle; } }
#endif
  snprintf(path, size, "input-%s.so", name);
  return input_open(path);
 }

 // Loads one module into a free slot; the caller holds input_lock while
 // streaming. Writes a one-line result to msg.
 static int input_add(const char *name, char *msg, size_t size) {
  input_slot_t slot; int i, free_slot = -1;

  memset(&slot, 0, sizeof(slot));
  input_label(name, slot.label, sizeof(slot.label));
  for (i = 0; i < INPUT_MAX_MODULES; i++) {
   if (input_slots[i].api && strcmp(input_slots[i].label, slot.label) == 0) { snprintf(msg, size, "error: '%s' is already loaded", slot.label); return -1; }
   if (!input_slots[i].api && free_slot < 0) { free_slot = i; }
  }
  if (free_slot < 0) { snprintf(msg, size, "error: at most %d input modules", INPUT_MAX_MODULES); return -1; }
  slot.handle = input_resolve(name, slot.path, sizeof(slot.path));
  if (!slot.handle) { snprintf(msg, size, "error: input module '%s' not found", name); return -1; }
  slot.api = input_entry(slot.handle);
  if (!slot.api || slot.api->abi_version != PS2_INPUT_MODULE_ABI_V1 || slot.api->struct_size < sizeof(*slot.api) ||
      !slot.api->start || !slot.api->poll || !slot.api->stop) {
   input_close(slot.handle);
   snprintf(msg, size, "error: input module '%s' has an incompatible ABI", name);
   return -1;
  }
  // One library loaded twice shares its state: refuse the second copy.
  for (i = 0; i < INPUT_MAX_MODULES; i++) {
   if (input_slots[i].api && input_slots[i].handle == slot.handle) {
    input_close(slot.handle);
    snprintf(msg, size, "error: '%s' is already loaded as '%s'", name, input_slots[i].label);
    return -1;
   }
  }
  input_slots[free_slot] = slot;
  snprintf(msg, size, "loaded %s: %s", slot.label, slot.api->name ? slot.api->name : slot.path);
  return 0;
 }

 static void input_remove(input_slot_t *slot) {
  if (slot->started) { slot->api->stop(); }
  input_close(slot->handle);
  memset(slot, 0, sizeof(*slot));
 }

 static input_slot_t *input_find(const char *name) {
  char label[64]; int i;
  input_label(name, label, sizeof(label));
  for (i = 0; i < INPUT_MAX_MODULES; i++) { if (input_slots[i].api && strcmp(input_slots[i].label, label) == 0) { return &input_slots[i]; } }
  return NULL;
 }

 int input_load_module(const char *name) {
  char msg[1200];
  input_requested = 1;
  // "none": stream a released pad with no module, a carrier for control
  // commands such as go (make multi-hw); modules can still be loaded later.
  if (strcmp(name, "none") == 0) { fprintf(stderr, "input: streaming with no module\n"); return 0; }
  if (input_add(name, msg, sizeof(msg)) < 0) { fprintf(stderr, "input: %s.\n", msg); return -1; }
  fprintf(stderr, "input: %s\n", msg);
  return 0;
 }

 static void input_send(const ps2_input_state_t *state, uint8_t flags) {
  uint8_t packet[PS2LINK_INPUT_V1_SIZE];
  const uint32_t size = ps2link_input_encode_v1(packet, input_session, ++input_sequence, state, INPUT_VALID_MS, flags);

  send(input_socket, (const char *)packet, (int)size, 0);
 }

 static uint32_t input_now_ms(void) {
#ifdef _WIN32
  return (uint32_t)timeGetTime();   // 1 ms resolution under timeBeginPeriod(1)
#else
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
#endif
 }

 static void input_released(ps2_input_state_t *state) {
  memset(state, 0, sizeof(*state));
  state->lx = state->ly = state->rx = state->ry = PS2_PAD_AXIS_CENTRE;
 }

 static uint8_t input_axis(uint8_t a, uint8_t b) {
  return abs((int)b - PS2_PAD_AXIS_CENTRE) > abs((int)a - PS2_PAD_AXIS_CENTRE) ? b : a;
 }

 // Starts new modules and merges every module's state. Module calls happen
 // under input_lock, so the control thread never races a poll.
 static void input_poll_all(ps2_input_state_t *merged) {
  int i;
  input_released(merged);
  pthread_mutex_lock(&input_lock);
  for (i = 0; i < INPUT_MAX_MODULES; i++) {
   input_slot_t *slot = &input_slots[i];
   ps2_input_state_t state;
   if (!slot->api) { continue; }
   if (!slot->started) {
    if (slot->api->start() != 0) { fprintf(stderr, "input: module %s failed to start; unloaded.\n", slot->label); input_remove(slot); continue; }
    slot->started = 1;
   }
   input_released(&state);
   if (slot->api->poll(&state) < 0) { fprintf(stderr, "input: module %s stopped; unloaded.\n", slot->label); input_remove(slot); continue; }
   merged->buttons |= state.buttons;
   merged->lx = input_axis(merged->lx, state.lx);
   merged->ly = input_axis(merged->ly, state.ly);
   merged->rx = input_axis(merged->rx, state.rx);
   merged->ry = input_axis(merged->ry, state.ry);
   if (state.l2 > merged->l2) { merged->l2 = state.l2; }
   if (state.r2 > merged->r2) { merged->r2 = state.r2; }
  }
  pthread_mutex_unlock(&input_lock);
 }

 static int input_is_running(void) {
  int running;
  pthread_mutex_lock(&input_lock);
  running = input_running;
  pthread_mutex_unlock(&input_lock);
  return running;
 }

 // Samples the go request as one coherent state. Only an armed deadline sends
 // GO; an expired one is disarmed, so the modular delta is only ever taken
 // for a short future deadline. The immediate-send request is consumed here,
 // in the same critical section, so a go arriving meanwhile is never lost.
 static int input_go_sample(uint32_t now, int *send_now) {
  int go;
  pthread_mutex_lock(&input_lock);
  if (input_go_armed && (int32_t)(input_go_until - now) <= 0) { input_go_armed = 0; }
  go = input_go_armed;
  *send_now = input_go_now;
  input_go_now = 0;
  pthread_mutex_unlock(&input_lock);
  return go;
 }

 static void *input_thread(void *arg) { ps2_input_state_t state, sent; uint32_t sent_ms = 0; int have_sent = 0;
  (void)arg;

  while (input_is_running()) {
   int go_now;
   input_poll_all(&state);
   const uint32_t now = input_now_ms();
   const uint32_t since = now - sent_ms;
   const int go = input_go_sample(now, &go_now);
   if (!have_sent || since >= INPUT_HEARTBEAT_MS || go_now ||
       (since >= INPUT_MIN_GAP_MS && memcmp(&state, &sent, sizeof(state)) != 0)) {
    input_send(&state, go ? PS2LINK_INPUT_FLAG_SYNC_GO : 0);
    sent = state; sent_ms = now; have_sent = 1;
   }
#ifdef _WIN32
   Sleep(INPUT_POLL_MS);
#else
   usleep(INPUT_POLL_MS * 1000);
#endif
  }
  return NULL;
 }

 // One command per datagram, one reply per command:
 //   list | load <name|path> | unload <name> | reload <name> | go
 static void input_command(char *cmd, char *reply, size_t size) {
  char *arg = strchr(cmd, ' ');
  input_slot_t *slot;
  int i, n = 0;

  if (arg) { *arg++ = 0; while (*arg == ' ') { arg++; } }
  pthread_mutex_lock(&input_lock);
  if (strcmp(cmd, "list") == 0) {
   reply[0] = 0;
   for (i = 0; i < INPUT_MAX_MODULES; i++) {
    if (input_slots[i].api) { n += snprintf(reply + n, size - n, "%s: %s\n", input_slots[i].label, input_slots[i].api->name ? input_slots[i].api->name : input_slots[i].path); }
    if ((size_t)n >= size) { break; }
   }
   if (n == 0) { snprintf(reply, size, "no input modules loaded\n"); }
  } else if (strcmp(cmd, "load") == 0 && arg && *arg) {
   input_add(arg, reply, size);
  } else if ((strcmp(cmd, "unload") == 0 || strcmp(cmd, "reload") == 0) && arg && *arg) {
   if (!(slot = input_find(arg))) { snprintf(reply, size, "error: '%s' is not loaded", arg); }
   else {
    char path[sizeof(slot->path)];
    snprintf(path, sizeof(path), "%s", slot->path);
    input_remove(slot);
    if (cmd[0] == 'u') { snprintf(reply, size, "unloaded %s", arg); }
    else { input_add(path, reply, size); }   // the rebuilt file at the same path
   }
  } else if (strcmp(cmd, "go") == 0) {
   // Synchronized start: SYNC_GO rides every datagram for GO_MS (a lost one
   // costs nothing); the next datagram leaves at once.
   input_go_until = input_now_ms() + INPUT_GO_MS;
   input_go_armed = 1;
   input_go_now = 1;
   snprintf(reply, size, "go");
  } else {
   snprintf(reply, size, "error: commands are list, load <module>, unload <module>, reload <module>, go");
  }
  pthread_mutex_unlock(&input_lock);
  fprintf(stderr, "input: control: %s%s", reply, reply[0] && reply[strlen(reply) - 1] == '\n' ? "" : "\n");
 }

 static void *input_control_thread(void *arg) {
  (void)arg;
  while (input_is_running()) {
   fd_set fds; struct timeval tv;
   struct sockaddr_in from;
#ifdef _WIN32
   int fromlen = sizeof(from);
#else
   socklen_t fromlen = sizeof(from);
#endif
   char cmd[1100], reply[2048];
   int len;

   FD_ZERO(&fds); FD_SET(input_control_socket, &fds);
   tv.tv_sec = 0; tv.tv_usec = INPUT_CONTROL_WAIT_MS * 1000;
   if (select(input_control_socket + 1, &fds, NULL, NULL, &tv) <= 0) { continue; }
   len = recvfrom(input_control_socket, cmd, sizeof(cmd) - 1, 0, (struct sockaddr *)&from, &fromlen);
   if (len <= 0) { continue; }
   while (len > 0 && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r')) { len--; }
   cmd[len] = 0;
   input_command(cmd, reply, sizeof(reply));
   sendto(input_control_socket, reply, (int)strlen(reply), 0, (struct sockaddr *)&from, fromlen);
  }
  return NULL;
 }

 // Loopback only: the control port must not be reachable from the network.
 static void input_control_open(void) {
  const char *env = getenv("INPUT_CONTROL_PORT");
  const int port = env ? atoi(env) : INPUT_CONTROL_DEFAULT_PORT;
  struct sockaddr_in addr;

  input_control_socket = (int)socket(AF_INET, SOCK_DGRAM, 0);
  if (input_control_socket < 0) { return; }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(input_control_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
   fprintf(stderr, "input: control port %d unavailable; modules are fixed for this session.\n", port);
   input_socket_close(input_control_socket);
   input_control_socket = -1;
   return;
  }
#ifdef _WIN32
  // A reply to a sender that has already gone (a timed-out script) raises an
  // ICMP port unreachable, which Windows reports as WSAECONNRESET on this
  // socket's next receive. Commands must never depend on that history.
  {
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
   BOOL off = FALSE; DWORD bytes = 0;
   WSAIoctl(input_control_socket, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &bytes, NULL, NULL);
  }
#endif
  fprintf(stderr, "input: control on 127.0.0.1:%d (list, load, unload, reload, go).\n", port);
 }

 int input_start(const char *hostname) {
  if (!input_requested) { return 0; }
  input_socket = input_connect(hostname, PS2LINK_INPUT_PORT);
  if (input_socket < 0) { fprintf(stderr, "input: could not open the input port 0x%x.\n", PS2LINK_INPUT_PORT); return -1; }
  // A new session supersedes any earlier client's stream on the console.
  input_session = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16);
  if (input_session == 0) { input_session = 1; }
  pthread_mutex_lock(&input_lock);
  input_running = 1;
  pthread_mutex_unlock(&input_lock);
#ifdef _WIN32
  // The default ~15.6 ms scheduler tick would stretch every 1 ms poll.
  timeBeginPeriod(1);
#endif
  if (pthread_create(&input_thread_id, NULL, input_thread, NULL) != 0) {
   fprintf(stderr, "input: could not start the input thread.\n");
   pthread_mutex_lock(&input_lock);
   input_running = 0;
   pthread_mutex_unlock(&input_lock);
#ifdef _WIN32
   timeEndPeriod(1);
#endif
   input_socket_close(input_socket);
   input_socket = -1;
   return -1;
  }
  input_control_open();
  if (input_control_socket >= 0 && pthread_create(&input_control_id, NULL, input_control_thread, NULL) != 0) {
   fprintf(stderr, "input: could not start the control thread; modules are fixed for this session.\n");
   input_socket_close(input_control_socket);
   input_control_socket = -1;
  }
  return 0;
 }

 // Only the main thread starts and stops the threads.
 void input_stop(void) { ps2_input_state_t released; int i;
  pthread_mutex_lock(&input_lock);
  const int running = input_running;
  input_running = 0;
  pthread_mutex_unlock(&input_lock);
  if (!running) { return; }
  pthread_join(input_thread_id, NULL);
  if (input_control_socket >= 0) { pthread_join(input_control_id, NULL); input_socket_close(input_control_socket); input_control_socket = -1; }
#ifdef _WIN32
  timeEndPeriod(1);
#endif
  // Release every control and end the session explicitly.
  input_released(&released);
  input_send(&released, PS2LINK_INPUT_FLAG_END);
  for (i = 0; i < INPUT_MAX_MODULES; i++) { if (input_slots[i].api) { input_remove(&input_slots[i]); } }
  input_socket_close(input_socket);
  input_socket = -1;
 }
