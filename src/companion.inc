// ═════════════════════════════════════════════════════════════════════════════
//  Spectra-Cascadia Companion — the MeshCore app over USB serial
//  (128 KB build, -DSPECTER_COMPANION; included from main.cpp after xl_admin.inc)
//
//  Implements the companion side of upstream MeshCore examples/companion_radio
//  (MyMesh.cpp + BaseChatMesh.cpp, FIRMWARE_VER_CODE 14): contacts, direct
//  messages with ACKs, channels, the offline message queue, and logging in to /
//  querying repeaters and room servers. Frames ('<' len16 payload in, '>' len16
//  payload out) share the USB serial port with the text console: a '<' at the
//  start of a line begins a frame, anything else is a console command.
//
//  Differences from upstream, all because of the 20 KB of RAM:
//    - C_MAX_CONTACTS contacts, C_MAX_CHANNELS channels, a ~1 KB offline queue;
//    - shared secrets are cached for the few most recently used contacts;
//    - adverts are not stored, so SHARE_CONTACT and exporting someone else's
//      contact answer "not found" (exporting our own works);
//    - the node never forwards (no client repeat); signing, raw packets and
//      channel data are not supported.
// ═════════════════════════════════════════════════════════════════════════════

#ifndef C_MAX_CONTACTS
#define C_MAX_CONTACTS 32
#endif
#define C_MAX_CHANNELS 8
#define C_FRAME        176            // MAX_FRAME_SIZE
#define C_QUEUE_BYTES  1024           // offline queue (upstream: 16 frames)
#define C_ACKS         8              // EXPECTED_ACK_TABLE_SIZE
#define C_SECRETS      6
#define C_VER_CODE     14             // FIRMWARE_VER_CODE of upstream 1.18.0
#define C_MAX_TEXT     160            // MAX_TEXT_LEN
#define C_MAGIC        0x31434353UL   // "SCC1"

#define C_HI XL_HI                    // big handlers live in the upper 64 KB (run from loop() only)

XL_HI static void handle_command(char* cmd, char* reply);   // the console's commands (RUN_CLI_COMMAND)

// Contact store: two copies (written alternately) of C_SLOT_PAGES pages each, just below
// the admin-list page. specter_companion.ld keeps code out of 0x0801CC00-0x0801FBFF.
#define C_SLOT_PAGES 6
#ifndef COMP_STORE_ADDR
#define COMP_STORE_ADDR (ACL_ADDR - 2UL * C_SLOT_PAGES * PAGE_SIZE)
#endif

// RESP_CODE_* / PUSH_CODE_* / ERR_CODE_*
enum {
    R_OK = 0, R_ERR = 1, R_CONTACTS_START = 2, R_CONTACT = 3, R_END_CONTACTS = 4, R_SELF_INFO = 5,
    R_SENT = 6, R_CONTACT_MSG = 7, R_CHANNEL_MSG = 8, R_CURR_TIME = 9, R_NO_MORE = 10, R_EXPORT = 11,
    R_BATT = 12, R_DEVICE_INFO = 13, R_DISABLED = 15, R_CONTACT_MSG_V3 = 16, R_CHANNEL_MSG_V3 = 17,
    R_CHANNEL_INFO = 18, R_CUSTOM_VARS = 21, R_TUNING = 23, R_STATS = 24, R_AUTOADD = 25,
    R_REPEAT_FREQ = 26, R_DEFAULT_SCOPE = 28, R_CLI_REPLY = 29
};
enum {
    P_ADVERT = 0x80, P_PATH_UPDATED = 0x81, P_SEND_CONFIRMED = 0x82, P_MSG_WAITING = 0x83,
    P_LOGIN_OK = 0x85, P_LOGIN_FAIL = 0x86, P_STATUS = 0x87, P_LOG_RX = 0x88, P_TRACE = 0x89,
    P_NEW_ADVERT = 0x8A, P_TELEMETRY = 0x8B, P_BINARY = 0x8C, P_DISCOVERY = 0x8D, P_CONTROL = 0x8E,
    P_CONTACT_DELETED = 0x8F, P_CONTACTS_FULL = 0x90
};
enum { E_UNSUPPORTED = 1, E_NOT_FOUND = 2, E_TABLE_FULL = 3, E_BAD_STATE = 4, E_ILLEGAL_ARG = 6 };
#define TXT_TYPE_SIGNED 2
#define REQ_TYPE_STATUS 0x01
#define REQ_TYPE_TELEM  0x03

struct Contact {                      // ContactInfo, minus the cached shared secret
    uint8_t  pub[32];
    char     name[32];
    uint8_t  type, flags, out_len, pad;   // out_len: packed path_len, or OUT_PATH_UNKNOWN (flood)
    uint8_t  out_path[MAX_PATH_SIZE];
    uint32_t last_advert, lastmod, sync_since;
    int32_t  lat, lon;
};
struct Channel { char name[32]; uint8_t secret[16]; };
struct CompPrefs {
    uint8_t  manual_add, autoadd, autoadd_hops, telem, adv_loc, pad[3];
    uint32_t pin;
};
struct CompStore {
    uint32_t  magic, seq;
    CompPrefs pr;
    uint16_t  n, pad;
    Contact   c[C_MAX_CONTACTS];
    Channel   ch[C_MAX_CHANNELS];
    uint32_t  check;
};
static_assert(sizeof(CompStore) % 4 == 0, "word-aligned store");
static_assert(sizeof(CompStore) <= C_SLOT_PAGES * PAGE_SIZE, "contact store must fit its flash slot");

static CompStore ks;                   // RAM copy is the truth; flash is the saved snapshot
static Contact   c_anon;               // transient contact for SEND_ANON_REQ to a non-contact
static bool      c_anon_used = false;
static uint8_t   ch_hash[C_MAX_CHANNELS];
static uint8_t   c_slot = 0;           // flash copy holding the newest snapshot
static uint32_t  c_dirty_at = 0;

static bool      c_app = false;        // the app has spoken since boot: pushes go out, logging stops
static uint8_t   c_app_ver = 0;        // app_target_ver from DEVICE_QUERY (≥3: V3 message frames)
static uint8_t   c_in[C_FRAME + 1];
static uint16_t  c_in_len = 0, c_in_need = 0;
static uint8_t   c_in_state = 0;       // 0 idle, 1 length LSB, 2 length MSB, 3 payload
static uint32_t  c_in_ms = 0;
static uint8_t   c_f[C_FRAME];         // outgoing frame being built

static uint8_t   c_q[C_QUEUE_BYTES];   // offline queue: [len][frame] ...
static uint16_t  c_q_len = 0;

struct AckWait { uint32_t ack, ms; uint8_t pfx[4]; };
static AckWait   c_acks[C_ACKS];
static uint8_t   c_ack_next = 0;

struct SecretSlot { uint8_t pfx[8]; uint8_t s[32]; uint32_t used; };
static SecretSlot c_sec[C_SECRETS];
static uint32_t  c_sec_tick = 0;

static uint32_t  c_pend_login = 0, c_pend_status = 0, c_pend_tele = 0, c_pend_req = 0, c_pend_disc = 0;
static bool      c_iter = false;       // GET_CONTACTS stream in progress
static uint16_t  c_iter_i = 0;
static uint32_t  c_iter_since = 0, c_iter_max = 0;
static uint32_t  c_reboot_at = 0;

static void     wr32(uint8_t* p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static bool     comp_advert_loc(void) { return ks.pr.adv_loc == 1; }
static int      path_bytes(uint8_t pl) { return (pl & 63) * ((pl >> 6) + 1); }
static bool     path_ok(uint8_t pl) { return (pl >> 6) != 3 && path_bytes(pl) <= MAX_PATH_SIZE; }

// ── serial frames ───────────────────────────────────────────────────────────

static void c_write(const uint8_t* f, int n) {
    if (n <= 0 || n > C_FRAME) return;                // upstream drops oversized frames too
    uint8_t h[3] = { '>', (uint8_t)n, (uint8_t)(n >> 8) };
    Serial1.write(h, 3);
    Serial1.write(f, n);
}
static void c_push(const uint8_t* f, int n) { if (c_app) c_write(f, n); }
static void c_ok(void) { uint8_t f = R_OK; c_write(&f, 1); }
static void c_err(uint8_t e) { uint8_t f[2] = { R_ERR, e }; c_write(f, 2); }
static void c_push_key(uint8_t code, const uint8_t* pub) { c_f[0] = code; memcpy(c_f + 1, pub, 32); c_push(c_f, 33); }

// ── persistence ─────────────────────────────────────────────────────────────

static uintptr_t c_store_addr(uint8_t slot) { return COMP_STORE_ADDR + slot * C_SLOT_PAGES * PAGE_SIZE; }
static bool c_store_valid(uint8_t slot) {
    const CompStore* s = (const CompStore*)c_store_addr(slot);
    return s->magic == C_MAGIC && s->n <= C_MAX_CONTACTS && s->check == fnv_words(s, offsetof(CompStore, check) / 4);
}

static void comp_save(void) {
    ks.magic = C_MAGIC;
    ks.seq++;
    ks.check = fnv_words(&ks, offsetof(CompStore, check) / 4);
    uint8_t s = c_slot ^ 1;
    uint32_t base = (uint32_t)c_store_addr(s);           // flash API addresses are 32-bit
    HAL_FLASH_Unlock();
    for (uint32_t p = 0; p < C_SLOT_PAGES; p++) flash_erase(base + p * PAGE_SIZE);
    const uint32_t* w = (const uint32_t*)&ks;
    for (unsigned i = 0; i < sizeof(ks) / 4; i++) {
        if ((i & 255) == 0) IWatchdog.reload();
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, base + i * 4, w[i]);
    }
    HAL_FLASH_Lock();
    c_slot = s;
    c_dirty_at = 0;
}
static void comp_flush(void) { if (c_dirty_at) comp_save(); }

// Structural changes are saved after 5 s (LAZY_CONTACTS_WRITE_DELAY); advert time
// stamps only within the hour, to spare the flash in a busy mesh.
static void c_dirty(bool soon) {
    uint32_t at = (millis() + (soon ? 5000UL : 3600000UL)) | 1;
    if (!c_dirty_at || (int32_t)(at - c_dirty_at) < 0) c_dirty_at = at;
}

static void c_channel_rehash(int i) {
    uint8_t h[32];
    SHA256 sha; sha.reset(); sha.update(ks.ch[i].secret, 16); sha.finalize(h, 32);
    ch_hash[i] = h[0];
}

static void c_defaults(void) {
    static const uint8_t pub_psk[16] = { 0x8b,0x33,0x87,0xe9,0xc5,0xcd,0xea,0x6a,0xc9,0xe5,0xed,0xba,0xa1,0x15,0xcd,0x72 };
    memset(&ks, 0, sizeof(ks));
    ks.magic = C_MAGIC;
    strcpy(ks.ch[0].name, "Public");
    memcpy(ks.ch[0].secret, pub_psk, 16);
}

static void comp_init(void) {
    bool a = c_store_valid(0), b = c_store_valid(1);
    const CompStore* s0 = (const CompStore*)c_store_addr(0);
    const CompStore* s1 = (const CompStore*)c_store_addr(1);
    if (a && b) c_slot = (int32_t)(s1->seq - s0->seq) > 0 ? 1 : 0;
    else c_slot = b ? 1 : 0;
    if (a || b) memcpy(&ks, (const void*)c_store_addr(c_slot), sizeof(ks));
    else c_defaults();
    uint32_t newest = 0;
    for (int i = 0; i < ks.n; i++) {
        ks.c[i].name[31] = 0;
        if (ks.c[i].lastmod > newest) newest = ks.c[i].lastmod;
    }
    for (int i = 0; i < C_MAX_CHANNELS; i++) { ks.ch[i].name[31] = 0; c_channel_rehash(i); }
    if (newest + 1 > clock_now()) clock_set(newest + 1);      // no RTC: never earlier than the newest contact
    for (int i = 0; i < C_ACKS; i++) c_acks[i].ack = 0;
}

// ── contacts ────────────────────────────────────────────────────────────────

static int c_find(const uint8_t* key, int len) {           // first contact matching a key prefix
    for (int i = 0; i < ks.n; i++) if (!memcmp(ks.c[i].pub, key, len)) return i;
    return -1;
}
static Contact* c_by_key(const uint8_t* pub) {             // full key: contacts, then the anon slot
    int i = c_find(pub, 32);
    if (i >= 0) return &ks.c[i];
    return (c_anon_used && !memcmp(c_anon.pub, pub, 32)) ? &c_anon : NULL;
}
static void c_remove(int i) {
    memmove(&ks.c[i], &ks.c[i + 1], (ks.n - i - 1) * sizeof(Contact));
    ks.n--;
}

// Table full: drop the oldest non-favourite if the app allows it (autoadd bit 0).
static bool c_make_room(void) {
    if (!(ks.pr.autoadd & 1)) return false;
    int old = -1;
    for (int k = 0; k < ks.n; k++)
        if (!(ks.c[k].flags & 1) && (old < 0 || ks.c[k].lastmod < ks.c[old].lastmod)) old = k;
    if (old < 0) return false;
    c_push_key(P_CONTACT_DELETED, ks.c[old].pub);
    c_remove(old);
    return true;
}

// Shared secret for a key (Identity::calcSharedSecret), cached: a key exchange costs a few ms.
static const uint8_t* c_secret(const uint8_t* pub) {
    int slot = 0;
    for (int i = 0; i < C_SECRETS; i++) {
        if (c_sec[i].used && !memcmp(c_sec[i].pfx, pub, 8)) { c_sec[i].used = ++c_sec_tick; return c_sec[i].s; }
        if (c_sec[i].used < c_sec[slot].used) slot = i;
    }
    ecdh(c_sec[slot].s, pub);
    memcpy(c_sec[slot].pfx, pub, 8);
    c_sec[slot].used = ++c_sec_tick;
    return c_sec[slot].s;
}

static int c_contact_frame(uint8_t* f, uint8_t code, const Contact& c) {
    f[0] = code;
    memcpy(f + 1, c.pub, 32);
    f[33] = c.type; f[34] = c.flags; f[35] = c.out_len;
    memcpy(f + 36, c.out_path, MAX_PATH_SIZE);
    memcpy(f + 100, c.name, 32);
    wr32(f + 132, c.last_advert);
    wr32(f + 136, (uint32_t)c.lat); wr32(f + 140, (uint32_t)c.lon);
    wr32(f + 144, c.lastmod);
    return 148;
}

// ── offline queue ───────────────────────────────────────────────────────────

static bool c_is_channel_frame(uint8_t code) { return code == R_CHANNEL_MSG || code == R_CHANNEL_MSG_V3 || code == 27; }

static void c_enqueue(const uint8_t* f, int n) {
    while (c_q_len + n + 1 > C_QUEUE_BYTES) {           // full: drop the oldest channel message, else this one
        int at = 0;
        while (at < c_q_len && !c_is_channel_frame(c_q[at + 1])) at += 1 + c_q[at];
        if (at >= c_q_len) return;
        int sz = 1 + c_q[at];
        memmove(c_q + at, c_q + at + sz, c_q_len - at - sz);
        c_q_len -= sz;
    }
    c_q[c_q_len] = (uint8_t)n;
    memcpy(c_q + c_q_len + 1, f, n);
    c_q_len += 1 + n;
    uint8_t w = P_MSG_WAITING;
    c_push(&w, 1);
}

static int c_dequeue(uint8_t* out) {
    if (!c_q_len) return 0;
    int n = c_q[0];
    memcpy(out, c_q + 1, n);
    memmove(c_q, c_q + 1 + n, c_q_len - 1 - n);
    c_q_len -= 1 + n;
    return n;
}

// ── sending ─────────────────────────────────────────────────────────────────

static uint8_t c_hash_size(void) { return (uint8_t)(cfg.path_hash_mode + 1); }

// Payload already built: direct along the contact's path, else flood. Returns raw length or -1.
static int c_route(const Contact& c, uint8_t ptype, const uint8_t* pl, int n, bool* flood, uint32_t delay) {
    *flood = c.out_len == OUT_PATH_UNKNOWN;
    if (*flood) return xl_send_flood(ptype, pl, n, c_hash_size(), -1, delay);
    return xl_send_direct(ptype, pl, n, c.out_len, c.out_path, delay);
}

// createDatagram: dest hash, src hash, MAC + AES of data with the contact's secret.
static int c_send_dgram(const Contact& c, uint8_t ptype, const uint8_t* data, int len, bool* flood, uint32_t delay) {
    if (len + CIPHER_MAC_SIZE + 15 > 184) return -1;
    uint8_t pl[MAX_PKT];
    pl[0] = c.pub[0];
    pl[1] = own_pubkey[0];
    int n = 2 + encrypt_then_mac(c_secret(c.pub), pl + 2, data, len);
    return c_route(c, ptype, pl, n, flood, delay);
}

// createAnonDatagram: dest hash, our full key, MAC + AES.
static int c_send_anon(const Contact& c, const uint8_t* data, int len, bool* flood) {
    if (len + 1 + 32 + 15 > 184) return -1;
    uint8_t pl[MAX_PKT];
    pl[0] = c.pub[0];
    memcpy(pl + 1, own_pubkey, 32);
    int n = 33 + encrypt_then_mac(c_secret(c.pub), pl + 33, data, len);
    return c_route(c, PT_ANON_REQ, pl, n, flood, 0);
}

// createPathReturn: tell dest how to reach us (path), optionally carrying an ACK or RESPONSE.
static int c_path_return(uint8_t* pl, const uint8_t* dest_pub, uint8_t path_len, const uint8_t* path,
                         uint8_t extra_type, const uint8_t* extra, int extra_len) {
    int pb = path_bytes(path_len);
    if (pb + extra_len + 5 > 184 - 2 - 16) return -1;           // MAX_COMBINED_PATH
    uint8_t data[184];
    int d = 0;
    data[d++] = path_len;
    memcpy(data + d, path, pb); d += pb;
    if (extra_len) { data[d++] = extra_type; memcpy(data + d, extra, extra_len); d += extra_len; }
    else { data[d++] = 0xFF; for (int k = 0; k < 4; k++) data[d++] = (uint8_t)rnd(); }
    pl[0] = dest_pub[0];
    pl[1] = own_pubkey[0];
    return 2 + encrypt_then_mac(c_secret(dest_pub), pl + 2, data, d);
}

// handleReturnPathRetry: they still flood to us although we have a direct path; resend ours.
static void c_path_retry(const Contact& c, const Pkt& p) {
    uint8_t pl[MAX_PKT];
    int n = c_path_return(pl, c.pub, p.path_len, p.path, 0, NULL, 0);
    if (n > 0) xl_send_direct(PT_PATH, pl, n, c.out_len, c.out_path, 3000);
}

static uint32_t c_timeout(int raw, bool flood, uint8_t out_len) {      // calc{Flood,Direct}TimeoutMillisFor
    uint32_t t = airtime_ms(raw);
    return flood ? 500 + 16 * t : 500 + (6 * t + 250) * ((out_len & 63) + 1);
}
static void c_sent(bool flood, uint32_t tag, uint32_t timeout) {
    uint8_t f[10];
    f[0] = R_SENT; f[1] = flood ? 1 : 0;
    wr32(f + 2, tag); wr32(f + 6, timeout);
    c_write(f, 10);
}
static void c_clear_pending(void) { c_pend_login = c_pend_status = c_pend_tele = c_pend_req = c_pend_disc = 0; }

// ── receiving ───────────────────────────────────────────────────────────────

static bool c_rx_direct(const Pkt& p) { return p.route == ROUTE_DIRECT || p.route == ROUTE_TRANSPORT_DIRECT; }

// A DM or channel message for the app (MyMesh::queueMessage).
static void c_queue_dm(const Contact& c, const Pkt& p, int8_t snr4, uint32_t ts, uint8_t tt, const uint8_t* extra4, const char* text) {
    uint8_t f[C_FRAME];
    int i = 0;
    if (c_app_ver >= 3) { f[i++] = R_CONTACT_MSG_V3; f[i++] = (uint8_t)snr4; f[i++] = 0; f[i++] = 0; }
    else f[i++] = R_CONTACT_MSG;
    memcpy(f + i, c.pub, 6); i += 6;
    f[i++] = c_rx_direct(p) ? 0xFF : p.path_len;
    f[i++] = tt;
    wr32(f + i, ts); i += 4;
    if (extra4) { memcpy(f + i, extra4, 4); i += 4; }
    int tl = strlen(text);
    if (tl > C_FRAME - i) tl = C_FRAME - i;
    memcpy(f + i, text, tl);
    c_enqueue(f, i + tl);
}

// An ACK we were waiting for (processAck). Returns the contact it was for, if still known.
static Contact* c_ack(const uint8_t* a) {
    uint32_t v = rd32(a);
    for (int i = 0; i < C_ACKS; i++) {
        if (!c_acks[i].ack || c_acks[i].ack != v) continue;
        uint8_t f[9];
        f[0] = P_SEND_CONFIRMED;
        wr32(f + 1, v); wr32(f + 5, millis() - c_acks[i].ms);
        c_push(f, 9);
        c_acks[i].ack = 0;
        int k = c_find(c_acks[i].pfx, 4);
        return k >= 0 ? &ks.c[k] : NULL;
    }
    return NULL;
}
static void c_ack_pkt(const Pkt& p, const uint8_t* a) {
    Contact* c = c_ack(a);
    if (c && !c_rx_direct(p) && c->out_len != OUT_PATH_UNKNOWN) c_path_retry(*c, p);
}

// ACK for a received DM: in a PATH return when it came by flood, else direct (or flood).
static void c_send_ack(const Contact& c, const Pkt& p, const uint8_t* ack, int len) {
    if (!c_rx_direct(p)) {
        uint8_t pl[MAX_PKT];
        int n = c_path_return(pl, c.pub, p.path_len, p.path, PT_ACK, ack, len);
        if (n > 0) xl_send_flood(PT_PATH, pl, n, c_hash_size(), -1, TXT_ACK_DELAY);
    } else if (c.out_len != OUT_PATH_UNKNOWN) {               // sendAckTo
        uint32_t d = TXT_ACK_DELAY;
        if (app.multi_acks) {                                  // a multipart copy first, 300 ms ahead
            uint8_t mp[1 + 6];
            mp[0] = (uint8_t)((1 << 4) | PT_ACK);
            memcpy(mp + 1, ack, len);
            xl_send_direct(PT_MULTIPART, mp, 1 + len, c.out_len, c.out_path, d);
            d += 300;
        }
        xl_send_direct(PT_ACK, ack, len, c.out_len, c.out_path, d);
    } else {
        xl_send_flood(PT_ACK, ack, len, c_hash_size(), -1, TXT_ACK_DELAY);
    }
}

C_HI static void c_txt(Contact& c, const Pkt& p, int8_t snr4, uint8_t* data, int n) {
    if (n <= 5) return;
    uint32_t ts = rd32(data);
    uint8_t flags = data[4] >> 2;
    if (flags == TXT_TYPE_PLAIN) {
        c.lastmod = clock_now(); c_dirty(false);
        const char* text = (const char*)data + 5;
        c_queue_dm(c, p, snr4, ts, TXT_TYPE_PLAIN, NULL, text);
        int tl = strlen(text);
        uint8_t ack[6], h[32];
        SHA256 sha; sha.reset(); sha.update(data, 5 + tl); sha.update(c.pub, 32); sha.finalize(h, 32);
        memcpy(ack, h, 4);
        ack[4] = (5 + tl + 1 < n) ? data[5 + tl + 1] : 0;     // extended attempt byte, if any
        ack[5] = (uint8_t)rnd();
        c_send_ack(c, p, ack, 6);
    } else if (flags == TXT_TYPE_CLI_DATA || flags == TXT_TYPE_CLI_COMMAND) {
        c_queue_dm(c, p, snr4, ts, flags, NULL, (const char*)data + 5);   // no ACK for CLI traffic
    } else if (flags == TXT_TYPE_SIGNED && n > 9) {
        if (ts > c.sync_since) c.sync_since = ts;
        c.lastmod = clock_now(); c_dirty(true);               // sync_since: a room server re-sends from here
        const char* text = (const char*)data + 9;
        c_queue_dm(c, p, snr4, ts, TXT_TYPE_SIGNED, data + 5, text);
        uint8_t h[32];
        SHA256 sha; sha.reset(); sha.update(data, 9 + strlen(text)); sha.update(own_pubkey, 32); sha.finalize(h, 32);
        c_send_ack(c, p, h, 4);
    }
}

// onContactResponse: match a RESPONSE to the request the app is waiting for.
C_HI static void c_response(const Contact& c, const uint8_t* data, int len) {
    if (len < 4) return;
    uint32_t tag = rd32(data);
    uint8_t* f = c_f;
    int i = 0;
    if (c_pend_login && !memcmp(&c_pend_login, c.pub, 4)) {
        c_pend_login = 0;
        if (len >= 6 && !memcmp(data + 4, "OK", 2)) {          // legacy repeater
            f[i++] = P_LOGIN_OK; f[i++] = 0;
            memcpy(f + i, c.pub, 6); i += 6;
        } else if (len > 4 && data[4] == RESP_SERVER_LOGIN_OK) {
            f[i++] = P_LOGIN_OK; f[i++] = len > 6 ? data[6] : 0;
            memcpy(f + i, c.pub, 6); i += 6;
            wr32(f + i, tag); i += 4;
            f[i++] = len > 7 ? data[7] : 0;
            f[i++] = len > 12 ? data[12] : 0;
        } else {
            f[i++] = P_LOGIN_FAIL; f[i++] = 0;
            memcpy(f + i, c.pub, 6); i += 6;
        }
    } else if (len > 4 && c_pend_status && !memcmp(&c_pend_status, c.pub, 4)) {
        c_pend_status = 0;
        f[i++] = P_STATUS; f[i++] = 0;
        memcpy(f + i, c.pub, 6); i += 6;
    } else if (len > 4 && c_pend_tele && tag == c_pend_tele) {
        c_pend_tele = 0;
        f[i++] = P_TELEMETRY; f[i++] = 0;
        memcpy(f + i, c.pub, 6); i += 6;
    } else if (len > 4 && c_pend_req && tag == c_pend_req) {
        c_pend_req = 0;
        f[i++] = P_BINARY; f[i++] = 0;
        wr32(f + i, tag); i += 4;
    } else {                                                  // unhandled: the whole response
        f[i++] = P_BINARY; f[i++] = 0;
        if (len > C_FRAME - i) len = C_FRAME - i;
        memcpy(f + i, data, len); i += len;
        c_push(f, i);
        return;
    }
    if (f[0] != P_LOGIN_OK && f[0] != P_LOGIN_FAIL) {        // status / telemetry / binary: data after the tag
        int dl = len - 4;
        if (dl > C_FRAME - i) dl = C_FRAME - i;
        memcpy(f + i, data + 4, dl); i += dl;
    }
    c_push(f, i);
}

// PATH from a contact: learn its path to us, then the ACK or RESPONSE it carries.
C_HI static void c_path_in(Contact& c, const Pkt& p, const uint8_t* data, int n) {
    uint8_t pl_len = data[0];
    if (!path_ok(pl_len)) return;
    int pb = path_bytes(pl_len);
    if (2 + pb > n) return;
    const uint8_t* path = data + 1;
    uint8_t et = data[1 + pb] & 0x0F;
    const uint8_t* extra = data + 2 + pb;
    int el = n - (2 + pb);
    if (et == PT_RESPONSE && el > 4 && c_pend_disc && rd32(extra) == c_pend_disc) {   // path discovery answer
        c_pend_disc = 0;
        if (!path_ok(p.path_len)) return;
        int i = 0;
        c_f[i++] = P_DISCOVERY; c_f[i++] = 0;
        memcpy(c_f + i, c.pub, 6); i += 6;
        c_f[i++] = pl_len; memcpy(c_f + i, path, pb); i += pb;
        int ib = path_bytes(p.path_len);
        c_f[i++] = p.path_len; memcpy(c_f + i, p.path, ib); i += ib;
        c_push(c_f, i);
        return;                                               // no reciprocal path
    }
    c.out_len = pl_len;
    memcpy(c.out_path, path, pb);
    c.lastmod = clock_now();
    if (&c != &c_anon) c_dirty(true);
    c_push_key(P_PATH_UPDATED, c.pub);
    if (et == PT_ACK && el >= 4) c_ack(extra);
    else if (et == PT_RESPONSE && el > 0) c_response(c, extra, el);
    if (!c_rx_direct(p)) {                                    // reciprocal path, sent direct along the new one
        uint8_t rp[MAX_PKT];
        int rn = c_path_return(rp, c.pub, p.path_len, p.path, 0, NULL, 0);
        if (rn > 0) xl_send_direct(PT_PATH, rp, rn, pl_len, path, 500);
    }
}

static int c_lpp_self(uint8_t* p);
// REQ from a contact (MyMesh::onContactRequest): only GET_TELEMETRY_DATA, base telemetry
// (battery, MCU temperature), as the app's telemetry mode allows (deny / contact flags / all).
C_HI static void c_request_in(const Contact& c, const Pkt& p, const uint8_t* data) {
    if (data[4] != REQ_TYPE_TELEM) return;
    uint8_t mode = ks.pr.telem & 3, perm = 0;
    if (mode == 2) perm = 1;
    else if (mode == 1) perm = (c.flags >> 1) & 1;
    perm &= (uint8_t)~data[5];                                // the requester's inverse mask
    if (!(perm & 1)) return;
    uint8_t reply[4 + 16];
    memcpy(reply, data, 4);                                   // sender's timestamp as the tag
    int rl = 4 + c_lpp_self(reply + 4);
    if (!c_rx_direct(p)) {                                    // flood: answer inside a PATH return
        uint8_t pl[MAX_PKT];
        int n = c_path_return(pl, c.pub, p.path_len, p.path, PT_RESPONSE, reply, rl);
        if (n > 0) xl_send_flood(PT_PATH, pl, n, c_hash_size(), -1, SERVER_RESPONSE_DELAY);
    } else {
        bool flood;
        c_send_dgram(c, PT_RESPONSE, reply, rl, &flood, SERVER_RESPONSE_DELAY);
    }
}

// TXT_MSG / REQ / RESPONSE / PATH addressed to us: try each contact with that source hash.
C_HI static void c_peer(const Pkt& p, int8_t snr4) {
    if (p.payload_len < 4 || p.payload[0] != own_pubkey[0]) return;
    uint8_t data[MAX_PKT + 1];
    for (int i = -1; i < ks.n; i++) {
        Contact* c = i < 0 ? (c_anon_used ? &c_anon : NULL) : &ks.c[i];
        if (!c || c->pub[0] != p.payload[1]) continue;
        int n = mac_then_decrypt(c_secret(c->pub), data, p.payload + 2, p.payload_len - 2);
        if (n <= 0) continue;
        data[n] = 0;
        if (p.ptype == PT_PATH) c_path_in(*c, p, data, n);
        else if (p.ptype == PT_TXT_MSG) c_txt(*c, p, snr4, data, n);
        else if (p.ptype == PT_RESPONSE) {
            c_response(*c, data, n);
            if (!c_rx_direct(p) && c->out_len != OUT_PATH_UNKNOWN) c_path_retry(*c, p);
        }
        else if (p.ptype == PT_REQ && n > 5) c_request_in(*c, p, data);
        return;
    }
}

C_HI static void c_group(const Pkt& p, int8_t snr4) {
    if (p.payload_len < 1 + CIPHER_MAC_SIZE + 16) return;
    uint8_t data[MAX_PKT + 1];
    for (int i = 0; i < C_MAX_CHANNELS; i++) {
        if (!ks.ch[i].name[0] || ch_hash[i] != p.payload[0]) continue;
        uint8_t sec[32];
        memcpy(sec, ks.ch[i].secret, 16); memset(sec + 16, 0, 16);
        int n = mac_then_decrypt(sec, data, p.payload + 1, p.payload_len - 1);
        if (n < 5) continue;
        if (data[4] >> 2) return;                             // only plain text
        data[n] = 0;
        uint8_t f[C_FRAME];
        int k = 0;
        if (c_app_ver >= 3) { f[k++] = R_CHANNEL_MSG_V3; f[k++] = (uint8_t)snr4; f[k++] = 0; f[k++] = 0; f[k++] = (uint8_t)i; }
        else { f[k++] = R_CHANNEL_MSG; f[k++] = (uint8_t)i; }
        f[k++] = c_rx_direct(p) ? 0xFF : p.path_len;
        f[k++] = 0;
        memcpy(f + k, data, 4); k += 4;
        int tl = strlen((char*)data + 5);
        if (tl > C_FRAME - k) tl = C_FRAME - k;
        memcpy(f + k, data + 5, tl);
        c_enqueue(f, k + tl);
        return;
    }
}

// A verified advert: update the contact, or add it (BaseChatMesh::onAdvertRecv).
C_HI static void c_advert(const uint8_t* pl, int plen, uint8_t hops) {
    if (plen < 101) return;
    uint8_t fl = pl[100];
    int i = 101, end = plen;
    if (end > 100 + MAX_ADVERT_DATA_SIZE) end = 100 + MAX_ADVERT_DATA_SIZE;
    int32_t lat = 0, lon = 0;
    if (fl & ADV_LATLON_MASK) { if (i + 8 > end) return; memcpy(&lat, pl + i, 4); memcpy(&lon, pl + i + 4, 4); i += 8; }
    if (fl & 0x20) i += 2;                                    // feature words
    if (fl & 0x40) i += 2;
    if (!(fl & ADV_NAME_MASK) || i >= end || !pl[i]) return;
    uint32_t ts = rd32(pl + 32);
    if (c_anon_used && !memcmp(c_anon.pub, pl, 32)) c_anon_used = false;    // becomes a real contact
    int idx = c_find(pl, 32);
    Contact t;
    if (idx >= 0) {
        if (ts <= ks.c[idx].last_advert) return;              // replay
        t = ks.c[idx];
    } else {
        memset(&t, 0, sizeof(t));
        memcpy(t.pub, pl, 32);
        t.out_len = OUT_PATH_UNKNOWN;
    }
    t.type = fl & 0x0F;
    memset(t.name, 0, sizeof(t.name));
    memcpy(t.name, pl + i, end - i > 31 ? 31 : end - i);
    if (fl & ADV_LATLON_MASK) { t.lat = lat; t.lon = lon; }
    t.last_advert = ts;
    t.lastmod = clock_now();
    if (idx < 0) {
        bool add = !(ks.pr.manual_add & 1) || (t.type >= 1 && t.type <= 4 && (ks.pr.autoadd & (1 << t.type)));
        if (add && ks.pr.autoadd_hops && hops >= ks.pr.autoadd_hops) add = false;
        if (add && ks.n >= C_MAX_CONTACTS) {
            add = false;
            add = c_make_room();
            if (!add) { c_push(c_f, c_contact_frame(c_f, P_NEW_ADVERT, t)); uint8_t full = P_CONTACTS_FULL; c_push(&full, 1); return; }
        }
        if (!add) { c_push(c_f, c_contact_frame(c_f, P_NEW_ADVERT, t)); return; }
        idx = ks.n++;
        c_dirty(true);
    } else c_dirty(false);
    ks.c[idx] = t;
    c_push_key(P_ADVERT, t.pub);
}

C_HI static void c_trace(const Pkt& p, int8_t snr4) {
    if (p.path_len >= MAX_PATH_SIZE || p.payload_len < 9) return;
    uint8_t flags = p.payload[8], sz = flags & 3;
    int tlen = p.payload_len - 9;
    if (((int)p.path_len << sz) < tlen) return;               // not at the end of its path (we don't relay)
    if (12 + tlen + (tlen >> sz) + 1 > C_FRAME) return;
    int i = 0;
    c_f[i++] = P_TRACE; c_f[i++] = 0; c_f[i++] = (uint8_t)tlen; c_f[i++] = flags;
    memcpy(c_f + i, p.payload, 8); i += 8;                    // tag, auth
    memcpy(c_f + i, p.payload + 9, tlen); i += tlen;
    memcpy(c_f + i, p.path, tlen >> sz); i += tlen >> sz;     // SNR×4 per hop
    c_f[i++] = (uint8_t)snr4;
    c_push(c_f, i);
}

C_HI static void comp_on_receive(const uint8_t* d, int len, int8_t snr4) {
    if (c_app && len + 3 <= C_FRAME) {                        // RX log for the app
        c_f[0] = P_LOG_RX; c_f[1] = (uint8_t)snr4; c_f[2] = (uint8_t)(int8_t)last_rssi;
        memcpy(c_f + 3, d, len);
        c_push(c_f, len + 3);
    }
    Pkt p;
    if (!parse(d, len, p)) { stat_drop++; return; }
    bool direct = c_rx_direct(p);
    if (direct) stat_direct_rx++; else stat_flood_rx++;
    if (direct && p.ptype == PT_TRACE) { c_trace(p, snr4); return; }
    if (direct && p.ptype == PT_CONTROL && (p.payload[0] & 0x80)) {
        if (p.hash_count == 0 && p.payload_len + 4 <= C_FRAME) {
            c_f[0] = P_CONTROL; c_f[1] = (uint8_t)snr4; c_f[2] = (uint8_t)(int8_t)last_rssi; c_f[3] = p.path_len;
            memcpy(c_f + 4, p.payload, p.payload_len);
            c_push(c_f, p.payload_len + 4);
        }
        return;
    }
    if (direct && p.hash_count > 0) {                         // passing through: only an early ACK matters
        if (p.ptype == PT_ACK && p.payload_len >= 4) c_ack(p.payload);
        return;
    }
    uint8_t h[8];
    packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
    if (was_seen(h)) return;
    mark_seen(h);
    stat_for_us++;
    switch (p.ptype) {
        case PT_TXT_MSG: case PT_REQ: case PT_RESPONSE: case PT_PATH: c_peer(p, snr4); break;
        case PT_GRP_TXT: c_group(p, snr4); break;
        case PT_ADVERT:
            if (advert_verify(p.payload, p.payload_len, p.hash_count)) c_advert(p.payload, p.payload_len, p.hash_count);
            break;
        case PT_ACK: if (p.payload_len >= 4) c_ack_pkt(p, p.payload); break;
        case PT_MULTIPART:
            if (p.payload_len >= 5 && (p.payload[0] & 0x0F) == PT_ACK) c_ack_pkt(p, p.payload + 1);
            break;
        default: break;
    }
}

// ── commands ────────────────────────────────────────────────────────────────

static void c_self_info(void) {
    uint8_t* f = c_f;
    int i = 0;
    f[i++] = R_SELF_INFO;
    f[i++] = ADV_TYPE_SELF;
    f[i++] = (uint8_t)cfg.tx_dbm;
    f[i++] = 22;                                              // MAX_LORA_TX_POWER (SX1262)
    memcpy(f + i, own_pubkey, 32); i += 32;
    wr32(f + i, (uint32_t)cfg.lat_e6); i += 4;
    wr32(f + i, (uint32_t)cfg.lon_e6); i += 4;
    f[i++] = app.multi_acks;
    f[i++] = ks.pr.adv_loc;
    f[i++] = ks.pr.telem;
    f[i++] = ks.pr.manual_add;
    wr32(f + i, cfg.freq_khz); i += 4;
    wr32(f + i, cfg.bw_hz); i += 4;
    f[i++] = cfg.sf;
    f[i++] = cfg.cr;
    int nl = strlen(cfg.name);
    memcpy(f + i, cfg.name, nl); i += nl;
    c_write(f, i);
}

static void c_device_info(void) {
    uint8_t* f = c_f;
    memset(f, 0, 82);
    f[0] = R_DEVICE_INFO;
    f[1] = C_VER_CODE;
    f[2] = C_MAX_CONTACTS / 2;                                // the app doubles it
    f[3] = C_MAX_CHANNELS;
    wr32(f + 4, ks.pr.pin);
    const char* d = __DATE__;                                 // "Nov 14 2026" → "14 Nov 2026"
    char* b = (char*)f + 8;
    int k = 0;
    if (d[4] != ' ') b[k++] = d[4];
    b[k++] = d[5]; b[k++] = ' ';
    memcpy(b + k, d, 3); k += 3; b[k++] = ' ';
    memcpy(b + k, d + 7, 4);
    strcpy((char*)f + 20, "DX-LR30 (" FW_NAME ")");
    strncpy((char*)f + 60, FW_VERSION, 19);
    f[80] = 0;                                                // client repeat: not supported
    f[81] = cfg.path_hash_mode;
    c_write(f, 82);
}

static int c_lpp_self(uint8_t* p) {                          // Cayenne LPP: voltage + MCU temperature, channel 1
    uint32_t mv = battery_mv();
    int t10 = temp_c() * 10;
    p[0] = 1; p[1] = 116; p[2] = (uint8_t)((mv / 10) >> 8); p[3] = (uint8_t)(mv / 10);
    p[4] = 1; p[5] = 103; p[6] = (uint8_t)((uint16_t)t10 >> 8); p[7] = (uint8_t)t10;
    return 8;
}

// REQ with a 13-byte typed body (sendRequest(type)) or app-supplied data.
static int c_request(const Contact& c, const uint8_t* body, int blen, uint32_t* tag, bool* flood) {
    uint8_t data[MAX_PKT];
    *tag = now_unique();
    wr32(data, *tag);
    memcpy(data + 4, body, blen);
    return c_send_dgram(c, PT_REQ, data, 4 + blen, flood, 0);
}
static int c_typed_request(const Contact& c, uint8_t type, uint32_t* tag, bool* flood) {
    uint8_t body[9] = { type, 0, 0, 0, 0 };
    for (int k = 5; k < 9; k++) body[k] = (uint8_t)rnd();
    return c_request(c, body, 9, tag, flood);
}

C_HI static void c_cmd_send_txt(uint8_t* f, int n) {
    if (n < 14) { c_err(E_UNSUPPORTED); return; }
    uint8_t tt = f[1], att = f[2];
    uint32_t ts = rd32(f + 3);
    int idx = c_find(f + 7, 6);
    if (idx < 0) { c_err(E_NOT_FOUND); return; }
    if (tt != TXT_TYPE_PLAIN && tt != TXT_TYPE_CLI_DATA && tt != TXT_TYPE_CLI_COMMAND) { c_err(E_UNSUPPORTED); return; }
    Contact& c = ks.c[idx];
    int tl = strlen((const char*)f + 13);                     // frame is NUL-terminated past n
    bool tail = tt == TXT_TYPE_PLAIN && att > 3;              // extended attempt: plain messages only
    if (tl > (tail ? C_MAX_TEXT - 2 : C_MAX_TEXT)) { c_err(E_TABLE_FULL); return; }
    if (tt != TXT_TYPE_PLAIN) ts = now_unique();
    uint8_t data[8 + C_MAX_TEXT];
    wr32(data, ts);
    data[4] = (uint8_t)((tt << 2) | (att & 3));
    memcpy(data + 5, f + 13, tl);
    int dl = 5 + tl;
    uint32_t ack = 0;
    if (tt == TXT_TYPE_PLAIN) {
        uint8_t h[32];
        SHA256 sha; sha.reset(); sha.update(data, dl); sha.update(own_pubkey, 32); sha.finalize(h, 32);
        ack = rd32(h);
    }
    if (tail) { data[dl++] = 0; data[dl++] = att; }         // extended attempt (not hashed)
    bool flood;
    int raw = c_send_dgram(c, PT_TXT_MSG, data, dl, &flood, 0);
    if (raw < 0) { c_err(E_TABLE_FULL); return; }
    if (ack) {
        AckWait& w = c_acks[c_ack_next];
        c_ack_next = (c_ack_next + 1) % C_ACKS;
        w.ack = ack; w.ms = millis(); memcpy(w.pfx, c.pub, 4);
    }
    c_sent(flood, ack, c_timeout(raw, flood, c.out_len));
}

C_HI static void c_cmd_send_channel(uint8_t* f, int n) {
    if (n < 7 || f[1] != 0) { c_err(E_UNSUPPORTED); return; }
    uint8_t idx = f[2];
    if (idx >= C_MAX_CHANNELS || !ks.ch[idx].name[0]) { c_err(E_NOT_FOUND); return; }
    uint8_t data[5 + C_MAX_TEXT + 1];
    memcpy(data, f + 3, 4);
    data[4] = TXT_TYPE_PLAIN << 2;
    char* m = (char*)data + 5;
    int k = 0, nl = strlen(cfg.name);
    for (int j = 0; j < nl && k < C_MAX_TEXT; j++) m[k++] = cfg.name[j];
    if (k < C_MAX_TEXT) m[k++] = ':';
    if (k < C_MAX_TEXT) m[k++] = ' ';
    for (int j = 7; j < n && k < C_MAX_TEXT; j++) m[k++] = (char)f[j];
    uint8_t sec[32];
    memcpy(sec, ks.ch[idx].secret, 16); memset(sec + 16, 0, 16);
    uint8_t pl[MAX_PKT];
    pl[0] = ch_hash[idx];
    int pn = 1 + encrypt_then_mac(sec, pl + 1, data, 5 + k);
    if (xl_send_flood(PT_GRP_TXT, pl, pn, c_hash_size(), -1, 0) < 0) { c_err(E_NOT_FOUND); return; }
    c_ok();
}

C_HI static void c_cmd_add_contact(const uint8_t* f, int n) {
    if (n < 36) { c_err(E_UNSUPPORTED); return; }
    int idx = c_find(f + 1, 32);
    if (idx < 0) {
        if (ks.n >= C_MAX_CONTACTS && !c_make_room()) { c_err(E_TABLE_FULL); return; }
        idx = ks.n++;
        memset(&ks.c[idx], 0, sizeof(Contact));
    }
    Contact& c = ks.c[idx];
    memcpy(c.pub, f + 1, 32);
    c.type = f[33]; c.flags = f[34]; c.out_len = f[35];
    if (c.out_len != OUT_PATH_UNKNOWN && !path_ok(c.out_len)) c.out_len = OUT_PATH_UNKNOWN;
    memcpy(c.out_path, f + 36, MAX_PATH_SIZE);
    memcpy(c.name, f + 100, 32); c.name[31] = 0;
    c.last_advert = rd32(f + 132);
    if (n >= 144) { c.lat = (int32_t)rd32(f + 136); c.lon = (int32_t)rd32(f + 140); }
    c.lastmod = n >= 148 ? rd32(f + 144) : clock_now();
    c_dirty(true);
    c_ok();
}

C_HI static void c_cmd_stats(uint8_t type) {
    uint8_t* f = c_f;
    f[0] = R_STATS; f[1] = type;
    if (type == 0) {
        uint16_t mv = (uint16_t)battery_mv();
        memcpy(f + 2, &mv, 2); wr32(f + 4, uptime_s());
        f[8] = f[9] = 0;                                      // error flags
        int q = 0; for (int i = 0; i < TXQ_SIZE; i++) q += txq[i].used;
        f[10] = (uint8_t)q;
        c_write(f, 11);
    } else if (type == 1) {
        int16_t nf = (int16_t)noise_floor;
        memcpy(f + 2, &nf, 2); f[4] = (uint8_t)(int8_t)last_rssi; f[5] = (uint8_t)(int8_t)last_snr4;
        wr32(f + 6, stat_tx_air_ms / 1000); wr32(f + 10, stat_rx_air_ms / 1000);
        c_write(f, 14);
    } else if (type == 2) {
        uint32_t v[7] = { stat_rx, stat_tx, stat_flood_tx, stat_direct_tx, stat_flood_rx, stat_direct_rx, stat_rx_err };
        memcpy(f + 2, v, sizeof(v));
        c_write(f, 30);
    } else c_err(E_ILLEGAL_ARG);
}

// Commands that talk to another node (login, status, telemetry, requests, trace).
C_HI static bool c_cmd_remote(uint8_t* f, int n) {
    uint32_t tag = 0;
    bool flood = false;
    int raw = -1;
    Contact* c = NULL;
    switch (f[0]) {
    case 26: {                                                // SEND_LOGIN
        if (n < 33) return false;
        if (!(c = c_by_key(f + 1))) { c_err(E_NOT_FOUND); return true; }
        uint8_t data[24];
        uint32_t now = now_unique();
        wr32(data, now);
        int pw = n - 33; if (pw > 15) pw = 15;
        int dl = 4;
        if (c->type == 3) { wr32(data + 4, c->sync_since); dl = 8; }   // room server
        memcpy(data + dl, f + 33, pw); dl += pw;
        raw = c_send_anon(*c, data, dl, &flood);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        memcpy(&c_pend_login, c->pub, 4);
        tag = c_pend_login;
        break;
    }
    case 27:                                                  // SEND_STATUS_REQ
        if (n < 33) return false;
        if (!(c = c_by_key(f + 1))) { c_err(E_NOT_FOUND); return true; }
        raw = c_typed_request(*c, REQ_TYPE_STATUS, &tag, &flood);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        memcpy(&c_pend_status, c->pub, 4);                    // legacy matching: by sender
        break;
    case 39:                                                  // SEND_TELEMETRY_REQ
        if (n == 4) {                                         // our own
            int i = 0;
            c_f[i++] = P_TELEMETRY; c_f[i++] = 0;
            memcpy(c_f + i, own_pubkey, 6); i += 6;
            i += c_lpp_self(c_f + i);
            c_write(c_f, i);
            return true;
        }
        if (n < 36) return false;
        if (!(c = c_by_key(f + 4))) { c_err(E_NOT_FOUND); return true; }
        raw = c_typed_request(*c, REQ_TYPE_TELEM, &tag, &flood);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        c_pend_tele = tag;
        break;
    case 50:                                                  // SEND_BINARY_REQ
        if (n < 34) return false;
        if (!(c = c_by_key(f + 1))) { c_err(E_NOT_FOUND); return true; }
        if (n - 33 > 168) { c_err(E_TABLE_FULL); return true; }
        raw = c_request(*c, f + 33, n - 33, &tag, &flood);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        c_pend_req = tag;
        break;
    case 52: {                                                // SEND_PATH_DISCOVERY_REQ: flood telemetry request
        if (n < 34 || f[1] != 0) return false;
        if (!(c = c_by_key(f + 2))) { c_err(E_NOT_FOUND); return true; }
        uint8_t body[9] = { REQ_TYPE_TELEM, (uint8_t)~1, 0, 0, 0 };   // inverse mask: base telemetry only
        for (int k = 5; k < 9; k++) body[k] = (uint8_t)rnd();
        uint8_t save = c->out_len;
        c->out_len = OUT_PATH_UNKNOWN;
        raw = c_request(*c, body, 9, &tag, &flood);
        c->out_len = save;
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        c_pend_disc = tag;
        break;
    }
    case 57: {                                                // SEND_ANON_REQ (also to non-contacts)
        if (n <= 33) return false;
        if (!(c = c_by_key(f + 1))) {
            memset(&c_anon, 0, sizeof(c_anon));
            memcpy(c_anon.pub, f + 1, 32);
            c_anon.out_len = 0;                               // zero-hop direct
            c_anon.lastmod = clock_now();
            c_anon_used = true;
            c = &c_anon;
        }
        if (n - 33 > 140) { c_err(E_TABLE_FULL); return true; }
        uint8_t data[MAX_PKT];
        tag = now_unique();
        wr32(data, tag);
        memcpy(data + 4, f + 33, n - 33);
        raw = c_send_anon(*c, data, 4 + n - 33, &flood);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        c_clear_pending();
        c_pend_req = tag;
        break;
    }
    case 36: {                                                // SEND_TRACE_PATH
        if (n <= 10) return false;
        uint8_t flags = f[9];
        int sz = 1 << (flags & 3), plen = n - 10;
        if (plen % sz || plen / sz > MAX_PATH_SIZE) { c_err(E_ILLEGAL_ARG); return true; }
        raw = xl_send_direct(PT_TRACE, f + 1, 9 + plen, 0, NULL, 0);
        if (raw < 0) { c_err(E_TABLE_FULL); return true; }
        tag = rd32(f + 1);
        c_sent(false, tag, c_timeout(raw, false, (uint8_t)(plen / sz)));
        return true;
    }
    case 29: c_ok(); return true;                             // LOGOUT
    case 28: c_err(E_NOT_FOUND); return true;                 // HAS_CONNECTION: no keep-alive sessions
    default: return false;
    }
    c_sent(flood, tag, c_timeout(raw, flood, c->out_len));
    return true;
}

C_HI static void comp_frame(uint8_t* f, int n) {
    if (!c_app) { c_app = true; log_on = false; }            // binary from here on: no unsolicited text
    memset(f + n, 0, sizeof(c_in) - n);                       // short frames read as zeros
    uint8_t cmd = f[0];
    switch (cmd) {
    case 22:                                                  // DEVICE_QUERY
        if (n < 2) break;
        c_app_ver = f[1];
        c_device_info();
        return;
    case 1:                                                   // APP_START (also ends a contact listing)
        if (n < 8) break;
        c_iter = false;
        c_self_info();
        return;
    case 5: { uint8_t r[5] = { R_CURR_TIME }; wr32(r + 1, clock_now()); c_write(r, 5); return; }
    case 6: {                                                 // SET_DEVICE_TIME: never backwards
        if (n < 5) break;
        uint32_t t = rd32(f + 1);
        if (t < clock_now()) { c_err(E_ILLEGAL_ARG); return; }
        clock_set(t);
        cs_manual = true;
        c_ok();
        return;
    }
    case 4: {                                                 // GET_CONTACTS [since]
        if (c_iter) { c_err(E_BAD_STATE); return; }
        c_iter = true; c_iter_i = 0; c_iter_max = 0;
        c_iter_since = n >= 5 ? rd32(f + 1) : 0;
        uint8_t r[5] = { R_CONTACTS_START };
        wr32(r + 1, ks.n);
        c_write(r, 5);
        return;
    }
    case 30: {                                                // GET_CONTACT_BY_KEY
        int i = c_find(f + 1, 32);
        if (i < 0) { c_err(E_NOT_FOUND); return; }
        c_write(c_f, c_contact_frame(c_f, R_CONTACT, ks.c[i]));
        return;
    }
    case 9: c_cmd_add_contact(f, n); return;                  // ADD_UPDATE_CONTACT
    case 15: case 13: {                                       // REMOVE_CONTACT / RESET_PATH
        if (n < 33) break;
        int i = c_find(f + 1, 32);
        if (i < 0) { c_err(E_NOT_FOUND); return; }
        if (cmd == 15) c_remove(i); else ks.c[i].out_len = OUT_PATH_UNKNOWN;
        c_dirty(true);
        c_ok();
        return;
    }
    case 16: c_err(E_NOT_FOUND); return;                      // SHARE_CONTACT: adverts aren't stored
    case 17: {                                                // EXPORT_CONTACT (ourselves only)
        if (n >= 33) { c_err(E_NOT_FOUND); return; }
        uint8_t* r = c_f;
        r[0] = R_EXPORT;
        r[1] = (PT_ADVERT << 2) | ROUTE_FLOOD;
        r[2] = 0;
        int i = make_advert(r + 3, clock_now());
        c_write(r, 3 + i);
        return;
    }
    case 18: {                                                // IMPORT_CONTACT: a raw advert packet
        Pkt p;
        if (n <= 98 || !parse(f + 1, n - 1, p) || p.ptype != PT_ADVERT) { c_err(E_ILLEGAL_ARG); return; }
        if (advert_verify(p.payload, p.payload_len, p.hash_count))    // a bad one is dropped quietly, as upstream
            c_advert(p.payload, p.payload_len, p.hash_count);
        c_ok();
        return;
    }
    case 7: send_advert(n >= 2 && f[1] == 1); c_ok(); return; // SEND_SELF_ADVERT
    case 8: {                                                 // SET_ADVERT_NAME
        if (n < 2) break;
        int l = n - 1; if (l > 31) l = 31;
        memset(cfg.name, 0, sizeof(cfg.name));
        memcpy(cfg.name, f + 1, l);
        cfg_save();
        c_ok();
        return;
    }
    case 14: {                                                // SET_ADVERT_LATLON
        if (n < 9) break;
        int32_t lat = (int32_t)rd32(f + 1), lon = (int32_t)rd32(f + 5);
        if (lat > 90000000 || lat < -90000000 || lon > 180000000 || lon < -180000000) { c_err(E_ILLEGAL_ARG); return; }
        cfg.lat_e6 = lat; cfg.lon_e6 = lon;
        cfg_save();
        c_ok();
        return;
    }
    case 11: {                                                // SET_RADIO_PARAMS (applied at once, as upstream)
        if (n < 11) break;
        uint32_t fr = rd32(f + 1), bw = rd32(f + 5);
        uint8_t sf = f[9], cr = f[10];
        if (fr < 150000 || fr > 2500000 || bw < 7000 || bw > 500000 || sf < 5 || sf > 12 || cr < 5 || cr > 8 ||
            (n >= 12 && f[11])) { c_err(E_ILLEGAL_ARG); return; }    // client repeat: not supported
        cfg.freq_khz = fr; cfg.bw_hz = bw; cfg.sf = sf; cfg.cr = cr;
        cfg_save();
        c_ok();
        Serial1.flush();
        if (!radio_init()) NVIC_SystemReset();
        rx_start();
        return;
    }
    case 12: {                                                // SET_RADIO_TX_POWER
        if (n < 2) break;
        int8_t p = (int8_t)f[1];
        if (p < -9 || p > 22) { c_err(E_ILLEGAL_ARG); return; }
        cfg.tx_dbm = p;
        radio.setOutputPower(p);
        rx_start();
        cfg_save();
        c_ok();
        return;
    }
    case 21: {                                                // SET_TUNING_PARAMS (×1000)
        if (n < 9) break;
        uint32_t rx = rd32(f + 1) / 100, af = rd32(f + 5) / 10;
        more.rxdelay_x10 = (uint16_t)(rx > 200 ? 200 : rx);
        cfg.af_x100 = (uint16_t)(af > 900 ? 900 : af);
        cfg_save();
        c_ok();
        return;
    }
    case 43: {                                                // GET_TUNING_PARAMS
        uint8_t r[9] = { R_TUNING };
        wr32(r + 1, more.rxdelay_x10 * 100UL); wr32(r + 5, cfg.af_x100 * 10UL);
        c_write(r, 9);
        return;
    }
    case 38:                                                  // SET_OTHER_PARAMS
        if (n < 2) break;
        ks.pr.manual_add = f[1];
        if (n >= 3) ks.pr.telem = f[2] & 0x3F;
        if (n >= 4) ks.pr.adv_loc = f[3];
        if (n >= 5 && app.multi_acks != f[4]) { app.multi_acks = f[4]; cfg_save(); }
        c_dirty(true);
        c_ok();
        return;
    case 58:                                                  // SET_AUTOADD_CONFIG
        if (n < 2) break;
        ks.pr.autoadd = f[1];
        if (n >= 3) ks.pr.autoadd_hops = f[2] > 64 ? 64 : f[2];
        c_dirty(true);
        c_ok();
        return;
    case 59: { uint8_t r[3] = { R_AUTOADD, ks.pr.autoadd, ks.pr.autoadd_hops }; c_write(r, 3); return; }
    case 2: c_cmd_send_txt(f, n); return;
    case 3: c_cmd_send_channel(f, n); return;
    case 10: {                                                // SYNC_NEXT_MESSAGE
        int m = c_dequeue(c_f);
        if (m) c_write(c_f, m);
        else { uint8_t r = R_NO_MORE; c_write(&r, 1); }
        return;
    }
    case 31: {                                                // GET_CHANNEL
        if (n < 2) break;
        if (f[1] >= C_MAX_CHANNELS) { c_err(E_NOT_FOUND); return; }
        uint8_t* r = c_f;
        r[0] = R_CHANNEL_INFO; r[1] = f[1];
        memcpy(r + 2, ks.ch[f[1]].name, 32);
        memcpy(r + 34, ks.ch[f[1]].secret, 16);
        c_write(r, 50);
        return;
    }
    case 32:                                                  // SET_CHANNEL (16-byte secrets only)
        if (n < 50 || n >= 66) break;
        if (f[1] >= C_MAX_CHANNELS) { c_err(E_NOT_FOUND); return; }
        memcpy(ks.ch[f[1]].name, f + 2, 32); ks.ch[f[1]].name[31] = 0;
        memcpy(ks.ch[f[1]].secret, f + 34, 16);
        c_channel_rehash(f[1]);
        c_dirty(true);
        c_ok();
        return;
    case 20: {                                                // GET_BATT_AND_STORAGE
        uint8_t r[11] = { R_BATT };
        uint16_t mv = (uint16_t)battery_mv();
        memcpy(r + 1, &mv, 2);
        wr32(r + 3, (offsetof(CompStore, c) + ks.n * sizeof(Contact) + 1023) / 1024);
        wr32(r + 7, C_SLOT_PAGES);
        c_write(r, 11);
        return;
    }
    case 19:                                                  // REBOOT (no reply)
        if (n < 7 || memcmp(f + 1, "reboot", 6)) break;
        Serial1.flush();
        journal_write(clock_now(), j_last_flood_ts);
        reboot_now();
        return;
    case 51:                                                  // FACTORY_RESET: contacts, channels, preferences
        if (n < 6 || memcmp(f + 1, "reset", 5)) break;
        c_defaults();
        for (int i = 0; i < C_MAX_CHANNELS; i++) c_channel_rehash(i);
        comp_save();
        c_ok();
        c_reboot_at = (millis() + 500) | 1;
        return;
    case 37: {                                                // SET_DEVICE_PIN (no BLE: stored and reported only)
        if (n < 5) break;
        uint32_t pin = rd32(f + 1);
        if (pin && (pin < 100000 || pin > 999999)) { c_err(E_ILLEGAL_ARG); return; }
        ks.pr.pin = pin;
        c_dirty(true);
        c_ok();
        return;
    }
    case 40: { uint8_t r = R_CUSTOM_VARS; c_write(&r, 1); return; }    // GET_CUSTOM_VARS: none
    case 41: c_err(E_ILLEGAL_ARG); return;                    // SET_CUSTOM_VAR
    case 23: case 24: { uint8_t r = R_DISABLED; c_write(&r, 1); return; }   // private key export/import
    case 42: c_err(E_NOT_FOUND); return;                      // GET_ADVERT_PATH: not kept
    case 54: case 63: c_ok(); return;                         // flood scope: use "region default" on the console
    case 64: { uint8_t r = R_DEFAULT_SCOPE; c_write(&r, 1); return; }
    case 56: if (n < 2) break; c_cmd_stats(f[1]); return;     // GET_STATS
    case 60: { uint8_t r = R_REPEAT_FREQ; c_write(&r, 1); return; }    // no client repeat
    case 61:                                                  // SET_PATH_HASH_MODE
        if (n < 3 || f[1] != 0) break;
        if (f[2] > 2) { c_err(E_ILLEGAL_ARG); return; }
        cfg.path_hash_mode = f[2];
        cfg_save();
        c_ok();
        return;
    case 66: {                                                // RUN_CLI_COMMAND: the USB console's commands
        char reply[176];
        reply[0] = 0;
        f[n] = 0;
        handle_command((char*)f + 1, reply);
        c_f[0] = R_CLI_REPLY;
        int rl = strlen(reply); if (rl > C_FRAME - 1) rl = C_FRAME - 1;
        memcpy(c_f + 1, reply, rl);
        c_write(c_f, 1 + rl);
        if (reboot_pending) { reboot_pending = false; c_reboot_at = (millis() + 500) | 1; }
        return;
    }
    default:
        if (c_cmd_remote(f, n)) return;
        break;
    }
    c_err(E_UNSUPPORTED);
}

// A byte from USB serial. Returns true if it belongs to an app frame.
// Once the app is attached, '<' always starts a frame (as upstream, which skips anything
// else), so a frame that lost a byte resyncs on the next one.
static bool comp_serial_byte(uint8_t b, bool line_start) {
    if (c_in_state == 0) {
        if (b != '<' || !(line_start || c_app)) return false;
        c_in_state = 1;
        c_in_ms = millis();
        return true;
    }
    c_in_ms = millis();
    if (c_in_state == 1) { c_in_need = b; c_in_state = 2; return true; }
    if (c_in_state == 2) {
        c_in_need |= (uint16_t)b << 8;
        c_in_len = 0;
        c_in_state = c_in_need ? 3 : 0;
        return true;
    }
    if (c_in_len < C_FRAME) c_in[c_in_len] = b;
    if (++c_in_len >= c_in_need) {
        c_in_state = 0;
        comp_frame(c_in, c_in_need > C_FRAME ? C_FRAME : c_in_need);
    }
    return true;
}

static bool comp_quiet(void) { return c_app; }                // console: no echo, no noise replies
static bool comp_frame_open(void) { return c_in_state != 0; } // inside a frame every byte is data

static void comp_service(void) {
    if (c_in_state && millis() - c_in_ms > 1000) c_in_state = 0;     // half a frame, then silence: resync
    if (c_iter && !c_in_state) {                              // one contact per pass, so the radio keeps up
        while (c_iter_i < ks.n && ks.c[c_iter_i].lastmod <= c_iter_since) c_iter_i++;
        if (c_iter_i < ks.n) {
            const Contact& c = ks.c[c_iter_i++];
            if (c.lastmod > c_iter_max) c_iter_max = c.lastmod;
            c_write(c_f, c_contact_frame(c_f, R_CONTACT, c));
        } else {
            uint8_t r[5] = { R_END_CONTACTS };
            wr32(r + 1, c_iter_max);
            c_write(r, 5);
            c_iter = false;
        }
    }
    if (c_dirty_at && (int32_t)(millis() - c_dirty_at) >= 0) comp_save();
    if (c_reboot_at && (int32_t)(millis() - c_reboot_at) >= 0) { Serial1.flush(); reboot_now(); }
}
