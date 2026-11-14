// Host-side tests for the companion build: the MeshCore app's serial protocol and
// the over-the-air side (contacts, DMs with ACKs, channels, repeater login/status),
// with the other nodes' crypto done by upstream MeshCore's own ed25519 (orlp).
// Build/run with ./run.sh (needs rweather Crypto and MESHCORE_DIR).
#include <stdint.h>
#include <assert.h>
#include <string>
#include <vector>

static uint32_t fake_config[256];
static uint32_t fake_journal[256];
static uint32_t fake_acl[256];
static uint32_t fake_store[12 * 256];      // two 6 KB copies of the contact store
static uint32_t fake_uid[3] = { 0x11223344, 0x55667788, 0x99AABBCC };
#define CONFIG_ADDR     ((uintptr_t)fake_config)
#define JOURNAL_ADDR    ((uintptr_t)fake_journal)
#define ACL_ADDR        ((uintptr_t)fake_acl)
#define COMP_STORE_ADDR ((uintptr_t)fake_store)
#define UID_BASE        ((uintptr_t)fake_uid)
#define SPECTER_XL 1
#define SPECTER_COMPANION 1
extern "C" {
#include "ed_25519.h"
}

#include "Arduino.h"
uint32_t fake_ms = 0;
FakeSerial Serial1;

static int erases = 0;
static uint32_t* page_for(uint32_t addr, uint32_t* idx) {
    uint32_t c = (uint32_t)(uintptr_t)fake_config, j = (uint32_t)(uintptr_t)fake_journal;
    uint32_t q = (uint32_t)(uintptr_t)fake_acl, s = (uint32_t)(uintptr_t)fake_store;
    if (addr - c < 1024) { *idx = (addr - c) / 4; return fake_config; }
    if (addr - j < 1024) { *idx = (addr - j) / 4; return fake_journal; }
    if (addr - q < 1024) { *idx = (addr - q) / 4; return fake_acl; }
    if (addr - s < sizeof(fake_store)) { *idx = (addr - s) / 4; return fake_store; }
    assert(!"flash address outside the fake pages");
    return nullptr;
}
int HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef* e, uint32_t*) {
    uint32_t i; uint32_t* p = page_for(e->PageAddress, &i);
    assert(i % 256 == 0);
    memset(p + i, 0xFF, 1024); erases++; return 0;
}
int HAL_FLASH_Program(uint32_t, uint32_t addr, uint64_t v) {
    uint32_t i; uint32_t* p = page_for(addr, &i);
    assert(p[i] == 0xFFFFFFFF);          // flash programs once per erase
    p[i] = (uint32_t)v; return 0;
}

#include "SPI.h"
#include "IWatchdog.h"
FakeSPI SPI; FakeWD IWatchdog;
#include "../../src/main.cpp"

static uint16_t fake_adc[18];
static uint16_t fake_bkp = 0, fake_bkp_dr[8];
static uint32_t fake_csr = (1UL << 27);
uint16_t adc_read(uint8_t ch) { return fake_adc[ch]; }
uint16_t bkp_read(void) { return fake_bkp; }
void bkp_write(uint16_t v) { fake_bkp = v; }
void enter_standby(void) { assert(!"standby"); }
uint16_t bkp_get(int n) { return fake_bkp_dr[n]; }
void bkp_set(int n, uint16_t v) { fake_bkp_dr[n] = v; }
uint32_t reset_csr(void) { uint32_t c = fake_csr; fake_csr = 0; return c; }

static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("PASS  %s\n", msg); else { printf("FAIL  %s\n", msg); fails++; } } while (0)

static int queued() { int n = 0; for (int i = 0; i < TXQ_SIZE; i++) n += txq[i].used; return n; }
static TxItem* last_q() { TxItem* b = nullptr; for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used) b = &txq[i]; return b; }
static void clearq() { for (int i = 0; i < TXQ_SIZE; i++) txq[i].used = false; }
static uint32_t r32(const std::string& s, int at) { uint32_t v; memcpy(&v, s.data() + at, 4); return v; }

// ── the app side: frames in and out of the serial port
static std::vector<std::string> frames_in(const std::string& out) {
    std::vector<std::string> v;
    size_t i = 0;
    while ((i = out.find('>', i)) != std::string::npos && i + 3 <= out.size()) {
        int n = (uint8_t)out[i + 1] | (uint8_t)out[i + 2] << 8;
        if (i + 3 + n > out.size()) break;
        v.push_back(out.substr(i + 3, n));
        i += 3 + n;
    }
    return v;
}
static std::vector<std::string> frame(const std::string& f, int passes = 1) {
    Serial1.out.clear();
    Serial1.in = std::string("<") + (char)(f.size() & 255) + (char)(f.size() >> 8) + f;
    cli_poll();
    for (int k = 0; k < passes; k++) comp_service();
    return frames_in(Serial1.out);
}
static std::string B(std::initializer_list<int> b) { std::string s; for (int x : b) s += (char)x; return s; }
static std::string K(const uint8_t* p, int n) { return std::string((const char*)p, n); }
static std::string U32(uint32_t v) { return K((const uint8_t*)&v, 4); }
static std::string cli(const char* line) {
    Serial1.out.clear();
    Serial1.in = std::string(line) + "\r";
    cli_poll();
    size_t p = Serial1.out.find("  -> ");
    if (p == std::string::npos) return "";
    std::string r = Serial1.out.substr(p + 5);
    if (!r.empty() && r.back() == '\n') r.pop_back();
    return r;
}

// ── other nodes: upstream's crypto (Utils::encryptThenMAC / MACThenDecrypt)
static int t_enc(const uint8_t* ss, uint8_t* dest, const uint8_t* src, int len) {
    AES128 aes; aes.setKey(ss, 16);
    int n = 0;
    for (; len > 0; len -= 16, src += 16, n += 16) {
        uint8_t b[16] = {0}; memcpy(b, src, len < 16 ? len : 16); aes.encryptBlock(dest + 2 + n, b);
    }
    SHA256 h; h.resetHMAC(ss, 32); h.update(dest + 2, n); h.finalizeHMAC(ss, 32, dest, 2);
    return n + 2;
}
static int t_dec(const uint8_t* ss, uint8_t* dest, const uint8_t* src, int len) {
    uint8_t mac[2]; SHA256 h; h.resetHMAC(ss, 32); h.update(src + 2, len - 2); h.finalizeHMAC(ss, 32, mac, 2);
    if (memcmp(mac, src, 2)) return -1;
    AES128 aes; aes.setKey(ss, 16);
    int n = 0; for (; n + 16 <= len - 2; n += 16) aes.decryptBlock(dest + n, src + 2 + n);
    return n;
}
struct Node { uint8_t pub[32], prv[64], ss[32]; const char* name; uint8_t type; };
static void mk_node(Node& c, uint8_t k, const char* name, uint8_t type) {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(k * 37 + i * 3 + 7);
    ed25519_create_keypair(c.pub, c.prv, seed);
    ed25519_key_exchange(c.ss, own_pubkey, c.prv);
    c.name = name; c.type = type;
}
static int mk_pkt(uint8_t* out, uint8_t hdr, const uint8_t* path, int hops, const uint8_t* pl, int plen) {
    int n = 0; out[n++] = hdr; out[n++] = (uint8_t)hops;
    memcpy(out + n, path, hops); n += hops; memcpy(out + n, pl, plen); return n + plen;
}
static int mk_advert(uint8_t* pk, const Node& c, uint32_t ts, int hops = 0) {
    uint8_t pl[140]; memcpy(pl, c.pub, 32); memcpy(pl + 32, &ts, 4);
    int i = 100; pl[i++] = (uint8_t)(c.type | 0x80);
    int nl = strlen(c.name); memcpy(pl + i, c.name, nl); i += nl;
    uint8_t msg[80]; memcpy(msg, pl, 36); memcpy(msg + 36, pl + 100, i - 100);
    ed25519_sign(pl + 36, msg, 36 + i - 100, c.pub, c.prv);
    uint8_t path[4] = { 0x31, 0x32, 0x33, 0x34 };
    return mk_pkt(pk, (PT_ADVERT << 2) | ROUTE_FLOOD, path, hops, pl, i);
}
static void rx(const uint8_t* pk, int n, int8_t snr4 = 24) { Serial1.out.clear(); on_receive(pk, n, snr4); }
// decrypt a datagram we queued for node c (dest, src, MAC+AES); returns plaintext length
static int open_for(const TxItem* t, const Node& c, Pkt& p, uint8_t* out) {
    if (!t || !parse(t->buf, t->len, p) || p.payload[0] != c.pub[0] || p.payload[1] != own_pubkey[0]) return -1;
    return t_dec(c.ss, out, p.payload + 2, p.payload_len - 2);
}

int main() {
    fake_adc[17] = (uint16_t)(1200UL * 4095UL / 3300UL); fake_adc[16] = (uint16_t)(1430UL * 4095UL / 3300UL);
    memset(fake_config, 0xFF, sizeof(fake_config)); memset(fake_journal, 0xFF, sizeof(fake_journal));
    memset(fake_acl, 0xFF, sizeof(fake_acl)); memset(fake_store, 0xFF, sizeof(fake_store));
    setup();
    CHECK(Serial1.out.find("MeshCore Companion") != std::string::npos, "boot banner says companion");
    CHECK(ks.n == 0 && !strcmp(ks.ch[0].name, "Public"), "fresh store: no contacts, Public channel in slot 0");
    CHECK(sizeof(CompStore) <= C_SLOT_PAGES * 1024, "store fits its flash slot");

    // ── connect handshake. Opening the port can hand the MCU a junk byte first (CH340 glitch):
    //    the app's first frame must still be seen as a frame, not echoed back as console text.
    std::vector<std::string> r;
    { Serial1.out.clear();
      Serial1.in = std::string("\x00\xff", 2) + std::string("<\x02\x00\x16\x03", 5);
      cli_poll();
      r = frames_in(Serial1.out);
      CHECK(r.size() == 1 && r[0].size() == 82 && r[0][0] == R_DEVICE_INFO && Serial1.out.find('<') == std::string::npos,
            "junk byte(s) before the app's first frame: DEVICE_INFO, no echo");
      c_app = false; cli_len = 0;
      Serial1.out.clear(); Serial1.in = "xy"; cli_poll();     // leftovers of an earlier attempt
      fake_ms += 600;
      Serial1.in = std::string("<\x02\x00\x16\x03", 5); cli_poll();
      r = frames_in(Serial1.out);
      CHECK(r.size() == 1 && r[0][0] == R_DEVICE_INFO && cli_len == 0, "a stale half line doesn't hide the next frame");
      c_app = false;
      Serial1.out.clear(); Serial1.in = "\r"; cli_poll(); }
    r = frame(B({1, 3, 0,0,0,0,0,0}) + "mccli");
    CHECK(r.size() == 1 && r[0][0] == R_SELF_INFO && r[0][1] == 1 && r[0].size() == 58 + strlen(cfg.name)
          && r[0].substr(4, 32) == K(own_pubkey, 32) && r[0].substr(58) == cfg.name, "APP_START → SELF_INFO (chat node, key, name)");
    CHECK(r32(r[0], 48) == cfg.freq_khz && r32(r[0], 52) == cfg.bw_hz && (uint8_t)r[0][56] == cfg.sf, "SELF_INFO radio params");
    CHECK(Serial1.out.find("  ->") == std::string::npos && !log_on, "app attached: binary only, logging off");
    r = frame(B({22, 3}));
    CHECK(r.size() == 1 && r[0].size() == 82 && r[0][0] == R_DEVICE_INFO && r[0][1] == 14 && r[0][2] == C_MAX_CONTACTS / 2 && r[0][3] == 8,
          "DEVICE_QUERY → 82-byte DEVICE_INFO (ver 14, contacts/2, 8 channels)");
    CHECK(r[0].substr(60, strlen(FW_VERSION)) == FW_VERSION && r[0][8] != ' ' && r[0].find("DX-LR30") == 20, "DEVICE_INFO strings");
    CHECK(c_app_ver == 3, "app target version stored");
    uint32_t now = 1800000000UL;
    r = frame(B({6}) + U32(now));
    CHECK(r.size() == 1 && r[0] == B({0}), "SET_DEVICE_TIME forward → OK");
    r = frame(B({6}) + U32(now - 100));
    CHECK(r.size() == 1 && r[0] == B({1, 6}), "SET_DEVICE_TIME backwards → ERR 6");
    r = frame(B({5}));
    CHECK(r.size() == 1 && r[0][0] == R_CURR_TIME && r32(r[0], 1) >= now && r32(r[0], 1) < now + 5, "GET_DEVICE_TIME");
    r = frame(B({31, 0}));
    CHECK(r.size() == 1 && r[0].size() == 50 && r[0].substr(2, 6) == std::string("Public", 6) && (uint8_t)r[0][34] == 0x8b, "GET_CHANNEL 0: Public + PSK");
    r = frame(B({31, 9}));
    CHECK(r.size() == 1 && r[0] == B({1, 2}), "GET_CHANNEL out of range → ERR 2");
    r = frame(B({99}));
    CHECK(r.size() == 1 && r[0] == B({1, 1}), "unknown command → ERR 1");
    r = frame(B({10}));
    CHECK(r.size() == 1 && r[0] == B({10}), "SYNC_NEXT_MESSAGE with nothing queued → NO_MORE_MESSAGES");
    CHECK(cli("get name") == std::string("> ") + cfg.name, "text console still answers between frames");
    r = frame(B({66}) + "get name");
    CHECK(r.size() == 1 && r[0][0] == R_CLI_REPLY && r[0].substr(1) == std::string("> ") + cfg.name, "RUN_CLI_COMMAND runs a console command");

    // ── adverts → contacts
    Node bob, carol, rpt;
    mk_node(bob, 1, "Bob", 1); mk_node(carol, 2, "Carol", 1); mk_node(rpt, 3, "Rpt-1", 2);
    uint8_t pk[260]; int n;
    n = mk_advert(pk, bob, now - 50, 2); rx(pk, n);
    r = frames_in(Serial1.out);
    CHECK(ks.n == 1 && !strcmp(ks.c[0].name, "Bob") && ks.c[0].type == 1 && ks.c[0].out_len == OUT_PATH_UNKNOWN,
          "advert from a new node: contact auto-added (no path yet)");
    CHECK(r.size() == 2 && (uint8_t)r[0][0] == P_LOG_RX && (uint8_t)r[1][0] == P_ADVERT && r[1].substr(1) == K(bob.pub, 32),
          "RX log push, then PUSH_ADVERT with the key");
    rx(pk, n);
    CHECK(frames_in(Serial1.out).size() == 1, "the same advert again: deduplicated (log only)");
    n = mk_advert(pk, bob, now - 60, 1); rx(pk, n);
    CHECK(frames_in(Serial1.out).size() == 1 && ks.c[0].last_advert == now - 50, "older advert timestamp: ignored (replay)");
    r = frame(B({38, 1}));                                       // manual add on
    n = mk_advert(pk, carol, now - 10); rx(pk, n);
    r = frames_in(Serial1.out);
    CHECK(ks.n == 1 && r.size() == 2 && (uint8_t)r[1][0] == P_NEW_ADVERT && r[1].size() == 148 && r[1].substr(1, 32) == K(carol.pub, 32),
          "manual add: unknown node → NEW_ADVERT frame, not stored");
    frame(B({58, 0x04}));                                        // ... but auto-add repeaters
    fake_ms += 2000;
    n = mk_advert(pk, rpt, now - 5, 1); rx(pk, n);
    CHECK(ks.n == 2 && ks.c[1].type == 2, "autoadd config: repeaters still added in manual mode");
    { Node z; mk_node(z, 9, "Zero", 0); frame(B({38, 1})); frame(B({58, 0x1F}));
      n = mk_advert(pk, z, now - 3); rx(pk, n);
      CHECK(ks.n == 2 && (uint8_t)frames_in(Serial1.out).back()[0] == P_NEW_ADVERT, "manual mode: type-0 nodes are never auto-added");
      frame(B({58, 0x04})); }
    r = frame(B({59}));
    CHECK(r.size() == 1 && r[0] == B({R_AUTOADD, 0x04, 0}), "GET_AUTOADD_CONFIG");
    frame(B({38, 0}));

    r = frame(B({4}), 4);
    CHECK(r.size() == 4 && r[0] == B({2}) + U32(2) && r[1][0] == R_CONTACT && r[1].size() == 148 && r[1].substr(100, 3) == "Bob"
          && r[2].substr(100, 5) == "Rpt-1" && r[3][0] == R_END_CONTACTS && r32(r[3], 1) == ks.c[1].lastmod,
          "GET_CONTACTS: start, one frame per pass, end with newest lastmod");
    { std::string out; Serial1.out.clear();
      Serial1.in = std::string("<\x01\x00\x04", 4); cli_poll(); comp_service();
      Serial1.in = std::string("<\x01\x00\x0a", 4); cli_poll(); comp_service(); comp_service(); comp_service();
      r = frames_in(Serial1.out);
      CHECK(r.size() == 5 && r[0][0] == R_CONTACTS_START && r[2] == B({10}) && r.back()[0] == R_END_CONTACTS,
            "a command during GET_CONTACTS doesn't cut the listing short"); }
    r = frame(B({4}) + U32(ks.c[0].lastmod), 3);
    CHECK(r.size() == 3 && r[1].substr(100, 5) == "Rpt-1" && r[2][0] == R_END_CONTACTS, "GET_CONTACTS since: only newer ones");

    // ── DM out: flood first (no path), ACK comes back in a PATH return
    clearq();
    std::string hi = "hello bob";
    r = frame(B({2, 0, 0}) + U32(now + 1) + K(bob.pub, 6) + hi);
    uint8_t h[32];
    uint8_t plain[64]; uint32_t ts1 = now + 1; memcpy(plain, &ts1, 4); plain[4] = 0; memcpy(plain + 5, hi.data(), hi.size());
    { SHA256 s; s.reset(); s.update(plain, 5 + hi.size()); s.update(own_pubkey, 32); s.finalize(h, 32); }
    uint32_t want_ack; memcpy(&want_ack, h, 4);
    CHECK(r.size() == 1 && r[0][0] == R_SENT && r[0][1] == 1 && r32(r[0], 2) == want_ack, "SEND_TXT_MSG → SENT flood with the expected ACK hash");
    { Pkt p; uint8_t d[200]; TxItem* t = last_q();
      int m = open_for(t, bob, p, d);
      uint32_t air = airtime_ms(t->len);
      CHECK(m >= 14 && p.ptype == PT_TXT_MSG && p.route == ROUTE_FLOOD && !memcmp(d, plain, 5 + hi.size()), "Bob decrypts the DM (flood)");
      CHECK(r32(r[0], 6) == 500 + 16 * air, "flood timeout = 500 + 16 × airtime"); }
    CHECK(r32(r[0], 2) == c_acks[0].ack, "ACK awaited");
    // Bob answers with PATH (flood, via 0x42) carrying the ACK
    { uint8_t path_in[1] = { 0x42 };
      uint8_t data[40]; int d = 0; data[d++] = 1; data[d++] = 0x51; data[d++] = PT_ACK; memcpy(data + d, &want_ack, 4); d += 4; data[d++] = 0; data[d++] = 9;
      uint8_t pl[80]; pl[0] = own_pubkey[0]; pl[1] = bob.pub[0]; int pn = 2 + t_enc(bob.ss, pl + 2, data, d);
      clearq(); n = mk_pkt(pk, (PT_PATH << 2) | ROUTE_FLOOD, path_in, 1, pl, pn); rx(pk, n);
      r = frames_in(Serial1.out);
      CHECK(ks.c[0].out_len == 1 && ks.c[0].out_path[0] == 0x51, "PATH: Bob's route to us learned (via 0x51)");
      CHECK(r.size() == 3 && (uint8_t)r[1][0] == P_PATH_UPDATED && (uint8_t)r[2][0] == P_SEND_CONFIRMED && r32(r[2], 1) == want_ack,
            "PUSH_PATH_UPDATED, then SEND_CONFIRMED for the ACK in the PATH");
      Pkt p; uint8_t dd[200]; int m = open_for(last_q(), bob, p, dd);
      CHECK(m > 0 && p.ptype == PT_PATH && p.route == ROUTE_DIRECT && p.hash_count == 1 && p.path[0] == 0x51 && dd[0] == 1 && dd[1] == 0x42 && dd[2] == 0xFF,
            "reciprocal PATH sent direct, telling Bob our route (via 0x42)"); }
    // now direct
    clearq();
    r = frame(B({2, 0, 1}) + U32(now + 2) + K(bob.pub, 6) + "again");
    { TxItem* t = last_q(); Pkt p; parse(t->buf, t->len, p);
      uint32_t air = airtime_ms(t->len);
      CHECK(r[0][1] == 0 && p.route == ROUTE_DIRECT && p.hash_count == 1 && p.path[0] == 0x51, "with a path: DM goes direct");
      CHECK(r32(r[0], 6) == 500 + (6 * air + 250) * 2, "direct timeout = 500 + (6 × airtime + 250) × (hops + 1)"); }
    // plain ACK packet (direct, arrived)
    { uint32_t a2 = r32(r[0], 2); uint8_t ack[6]; memcpy(ack, &a2, 4); ack[4] = 0; ack[5] = 7;
      n = mk_pkt(pk, (PT_ACK << 2) | ROUTE_DIRECT, NULL, 0, ack, 6); rx(pk, n);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 2 && (uint8_t)r[1][0] == P_SEND_CONFIRMED && r32(r[1], 1) == a2, "6-byte ACK matched on its first 4 bytes");
      rx(pk, n);
      CHECK(frames_in(Serial1.out).size() == 1, "ACK only confirms once"); }
    { clearq(); std::string txt = "nul"; txt += '\0'; txt += "tail";
      r = frame(B({2, 0, 0}) + U32(now + 3) + K(bob.pub, 6) + txt);
      uint8_t d2[20]; uint32_t t3 = now + 3; memcpy(d2, &t3, 4); d2[4] = 0; memcpy(d2 + 5, "nul", 3);
      uint8_t hh[32]; SHA256 s; s.reset(); s.update(d2, 8); s.update(own_pubkey, 32); s.finalize(hh, 32);
      CHECK(r32(r[0], 2) == r32(K(hh, 4), 0), "text ends at a NUL (ACK hash over strlen, as upstream)"); }
    { app.multi_acks = 1; clearq();
      uint8_t data[20]; uint32_t ts = now + 8; memcpy(data, &ts, 4); data[4] = 0; strcpy((char*)data + 5, "ma");
      uint8_t pl[60]; pl[0] = own_pubkey[0]; pl[1] = bob.pub[0]; int pn = 2 + t_enc(bob.ss, pl + 2, data, 7);
      n = mk_pkt(pk, (PT_TXT_MSG << 2) | ROUTE_DIRECT, NULL, 0, pl, pn); rx(pk, n);
      int mp = 0, ak = 0; uint32_t dm = 0, da = 0;
      for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used) { int t = (txq[i].buf[0] >> 2) & 15;
          if (t == PT_MULTIPART) { mp++; dm = txq[i].due; } if (t == PT_ACK) { ak++; da = txq[i].due; } }
      CHECK(mp == 1 && ak == 1 && da - dm == 300, "multi.acks: a multipart ACK, then the ACK 300 ms later");
      app.multi_acks = 0; while (c_dequeue(c_f)) {} }
    r = frame(B({2, 0, 0}) + U32(now) + B({1,2,3,4,5,6}) + "x");
    CHECK(r.size() == 1 && r[0] == B({1, 2}), "SEND_TXT_MSG to an unknown prefix → ERR 2");
    r = frame(B({2, 0, 0}) + U32(now) + K(bob.pub, 6) + std::string(161, 'a'));
    CHECK(r.size() == 1 && r[0] == B({1, 3}), "text over 160 bytes → ERR 3");

    // ── DM in (flood) → queued V3 frame, ACK in a PATH return
    { std::string txt = "hi from bob";
      uint8_t data[64]; uint32_t ts = now + 7; memcpy(data, &ts, 4); data[4] = 0; memcpy(data + 5, txt.data(), txt.size());
      uint8_t pl[100]; pl[0] = own_pubkey[0]; pl[1] = bob.pub[0]; int pn = 2 + t_enc(bob.ss, pl + 2, data, 5 + txt.size());
      uint8_t path_in[2] = { 0x61, 0x62 };
      clearq(); n = mk_pkt(pk, (PT_TXT_MSG << 2) | ROUTE_FLOOD, path_in, 2, pl, pn); rx(pk, n, -10);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 2 && (uint8_t)r[1][0] == P_MSG_WAITING, "incoming DM: PUSH_MSG_WAITING");
      Pkt p; uint8_t dd[200]; int m = open_for(last_q(), bob, p, dd);
      uint8_t hh[32]; { SHA256 s; s.reset(); s.update(data, 5 + txt.size()); s.update(bob.pub, 32); s.finalize(hh, 32); }
      CHECK(m > 0 && p.ptype == PT_PATH && p.route == ROUTE_FLOOD && dd[0] == 2 && dd[1] == 0x61 && dd[2] == 0x62 && dd[3] == PT_ACK
            && !memcmp(dd + 4, hh, 4), "ACK (upstream hash) sent back inside a flooded PATH with the route to us");
      r = frame(B({10}));
      CHECK(r.size() == 1 && r[0][0] == R_CONTACT_MSG_V3 && (int8_t)r[0][1] == -10 && r[0].substr(4, 6) == K(bob.pub, 6)
            && (uint8_t)r[0][10] == 2 && r[0][11] == 0 && r32(r[0], 12) == ts && r[0].substr(16) == txt,
            "SYNC_NEXT_MESSAGE → CONTACT_MSG_RECV_V3 (snr, key prefix, hops, text)");
      r = frame(B({10}));
      CHECK(r[0] == B({10}), "queue empty again"); }

    // ── channels
    { uint8_t sec[32] = {0}; memcpy(sec, ks.ch[0].secret, 16);
      std::string body = "Dave: anyone?";
      uint8_t data[64]; uint32_t ts = now + 9; memcpy(data, &ts, 4); data[4] = 0; memcpy(data + 5, body.data(), body.size());
      uint8_t pl[100]; pl[0] = ch_hash[0]; int pn = 1 + t_enc(sec, pl + 1, data, 5 + body.size());
      n = mk_pkt(pk, (PT_GRP_TXT << 2) | ROUTE_FLOOD, NULL, 0, pl, pn); rx(pk, n);
      r = frame(B({10}));
      CHECK(r.size() == 1 && r[0][0] == R_CHANNEL_MSG_V3 && r[0][4] == 0 && r[0][5] == 0 && r32(r[0], 7) == ts && r[0].substr(11) == body,
            "Public channel message → CHANNEL_MSG_RECV_V3");
      clearq();
      r = frame(B({3, 0, 0}) + U32(now + 10) + "hello all");
      Pkt p; TxItem* t = last_q(); parse(t->buf, t->len, p);
      uint8_t dd[200]; int m = t_dec(sec, dd, p.payload + 1, p.payload_len - 1); dd[m] = 0;
      CHECK(r[0] == B({0}) && p.ptype == PT_GRP_TXT && p.payload[0] == ch_hash[0] && !strcmp((char*)dd + 5, (std::string(cfg.name) + ": hello all").c_str()),
            "SEND_CHANNEL_TXT_MSG: flooded as \"name: text\""); }
    { uint8_t k[32]; SHA256 s; s.reset(); s.update("#test", 5); s.finalize(k, 32);
      std::string f = B({32, 1}) + std::string("#test") + std::string(27, '\0') + K(k, 16);
      r = frame(f);
      CHECK(r[0] == B({0}) && !strcmp(ks.ch[1].name, "#test"), "SET_CHANNEL #test (key from the app)");
      uint8_t sec[32] = {0}; memcpy(sec, k, 16);
      uint8_t data[32]; uint32_t ts = now + 11; memcpy(data, &ts, 4); data[4] = 0; strcpy((char*)data + 5, "Eve: t");
      uint8_t pl[60]; uint8_t hh[32]; SHA256 s2; s2.reset(); s2.update(k, 16); s2.finalize(hh, 32);
      pl[0] = hh[0]; int pn = 1 + t_enc(sec, pl + 1, data, 11);
      n = mk_pkt(pk, (PT_GRP_TXT << 2) | ROUTE_FLOOD, NULL, 0, pl, pn); rx(pk, n);
      r = frame(B({10}));
      CHECK(r.size() == 1 && r[0][4] == 1 && r[0].substr(11) == "Eve: t", "message on #test lands on channel 1"); }

    // ── repeater: login, status, telemetry
    { ed25519_key_exchange(rpt.ss, own_pubkey, rpt.prv);
      clearq();
      r = frame(B({26}) + K(rpt.pub, 32) + "s3cret");
      CHECK(r.size() == 1 && r[0][0] == R_SENT && r[0][1] == 1 && r32(r[0], 2) == r32(K(rpt.pub, 4), 0), "SEND_LOGIN → SENT, tag = key prefix");
      Pkt p; TxItem* t = last_q(); parse(t->buf, t->len, p);
      uint8_t dd[100]; int m = t_dec(rpt.ss, dd, p.payload + 33, p.payload_len - 33); dd[m] = 0;
      CHECK(p.ptype == PT_ANON_REQ && p.payload[0] == rpt.pub[0] && !memcmp(p.payload + 1, own_pubkey, 32) && !strcmp((char*)dd + 4, "s3cret"),
            "ANON_REQ the repeater can open: timestamp + password");
      // the repeater answers by flood PATH carrying RESPONSE (as simple_repeater does)
      uint8_t resp[13]; uint32_t sts = now + 20; memcpy(resp, &sts, 4); resp[4] = 0; resp[5] = 0; resp[6] = 1; resp[7] = 3; memset(resp + 8, 0x55, 4); resp[12] = 2;
      uint8_t data[40]; int d = 0; data[d++] = 0; data[d++] = PT_RESPONSE; memcpy(data + d, resp, 13); d += 13;
      uint8_t pl[80]; pl[0] = own_pubkey[0]; pl[1] = rpt.pub[0]; int pn = 2 + t_enc(rpt.ss, pl + 2, data, d);
      n = mk_pkt(pk, (PT_PATH << 2) | ROUTE_FLOOD, NULL, 0, pl, pn); rx(pk, n);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 3 && (uint8_t)r[2][0] == P_LOGIN_OK && r[2][1] == 1 && r[2].substr(2, 6) == K(rpt.pub, 6) && r32(r[2], 8) == sts
            && r[2][12] == 3 && r[2][13] == 2, "PUSH_LOGIN_SUCCESS (permissions, prefix, server time, ACL, firmware level)");
      CHECK(ks.c[1].out_len == 0, "zero-hop path to the repeater learned");
      clearq();
      r = frame(B({27}) + K(rpt.pub, 32));
      t = last_q(); parse(t->buf, t->len, p);
      m = t_dec(rpt.ss, dd, p.payload + 2, p.payload_len - 2);
      uint32_t tag = r32(r[0], 2);
      CHECK(r[0][0] == R_SENT && r[0][1] == 0 && p.ptype == PT_REQ && p.route == ROUTE_DIRECT && m == 16 && !memcmp(dd, &tag, 4) && dd[4] == 1,
            "SEND_STATUS_REQ → direct REQ type 1 with the tag");
      uint8_t st[40]; memcpy(st, &tag, 4); for (int k = 4; k < 40; k++) st[k] = (uint8_t)k;
      pl[0] = own_pubkey[0]; pl[1] = rpt.pub[0]; pn = 2 + t_enc(rpt.ss, pl + 2, st, 40);
      n = mk_pkt(pk, (PT_RESPONSE << 2) | ROUTE_DIRECT, NULL, 0, pl, pn); rx(pk, n);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 2 && (uint8_t)r[1][0] == P_STATUS && r[1].substr(2, 6) == K(rpt.pub, 6) && (uint8_t)r[1][8] == 4 && r[1].size() >= 44,
            "PUSH_STATUS_RESPONSE: prefix + the repeater's stats");
      { clearq();                                     // telemetry request from a contact
        uint8_t q[13]; uint32_t qt = now + 33; memcpy(q, &qt, 4); q[4] = 3; memset(q + 5, 0, 8);
        uint8_t pl[60]; pl[0] = own_pubkey[0]; pl[1] = rpt.pub[0]; int pn = 2 + t_enc(rpt.ss, pl + 2, q, 13);
        n = mk_pkt(pk, (PT_REQ << 2) | ROUTE_DIRECT, NULL, 0, pl, pn); rx(pk, n);
        CHECK(queued() == 0, "telemetry mode deny (default): request not answered");
        frame(B({38, 0, 2}));
        q[0]++; memcpy(q, &(qt = now + 34), 4); pn = 2 + t_enc(rpt.ss, pl + 2, q, 13);
        n = mk_pkt(pk, (PT_REQ << 2) | ROUTE_DIRECT, NULL, 0, pl, pn); rx(pk, n);
        Pkt pp; uint8_t dd2[64]; int m2 = open_for(last_q(), rpt, pp, dd2);
        CHECK(m2 >= 12 && pp.ptype == PT_RESPONSE && r32(K(dd2, 4), 0) == qt && dd2[4] == 1 && dd2[5] == 116,
              "telemetry mode allow: RESPONSE with the tag and LPP battery voltage");
        frame(B({38, 0, 0})); }
      r = frame(B({39, 0, 0, 0}));
      CHECK(r.size() == 1 && (uint8_t)r[0][0] == P_TELEMETRY && r[0].substr(2, 6) == K(own_pubkey, 6) && r[0][8] == 1 && (uint8_t)r[0][9] == 116,
            "own telemetry: LPP voltage on channel 1");
      clearq();
      r = frame(B({57}) + K(carol.pub, 32) + B({2}));     // owner-info query to a non-contact
      t = last_q(); parse(t->buf, t->len, p);
      CHECK(r[0][0] == R_SENT && r[0][1] == 0 && p.ptype == PT_ANON_REQ && p.hash_count == 0 && c_anon_used, "SEND_ANON_REQ to a non-contact: zero-hop");
      Node cc = carol; ed25519_key_exchange(cc.ss, own_pubkey, cc.prv);
      uint32_t atag = r32(r[0], 2);
      uint8_t ar[12]; memcpy(ar, &atag, 4); memcpy(ar + 4, "ownerinf", 8);
      pl[0] = own_pubkey[0]; pl[1] = carol.pub[0]; pn = 2 + t_enc(cc.ss, pl + 2, ar, 12);
      n = mk_pkt(pk, (PT_RESPONSE << 2) | ROUTE_DIRECT, NULL, 0, pl, pn); rx(pk, n);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 2 && (uint8_t)r[1][0] == P_BINARY && r32(r[1], 2) == atag && r[1].substr(6, 8) == "ownerinf", "anon reply → PUSH_BINARY_RESPONSE with the tag"); }

    // ── trace
    { clearq();
      r = frame(B({36}) + U32(0xABCD) + U32(0) + B({0, 0x51, 0x99}));
      TxItem* t = last_q(); Pkt p; parse(t->buf, t->len, p);
      CHECK(r[0][0] == R_SENT && r32(r[0], 2) == 0xABCD && p.ptype == PT_TRACE && p.route == ROUTE_DIRECT && p.path_len == 0, "SEND_TRACE_PATH → direct TRACE");
      std::vector<std::string> r2 = frame(B({36}) + U32(1) + U32(0) + B({1}) + std::string(80, 'h'));
      CHECK(r2[0][0] == R_SENT, "trace with 2-byte hashes: 40 hops allowed (limit is hops, not bytes)");
      uint8_t back[64]; int bn = 0; back[bn++] = t->buf[0]; back[bn++] = 2; back[bn++] = 20; back[bn++] = (uint8_t)-8;
      memcpy(back + bn, t->buf + 2, t->len - 2); bn += t->len - 2;
      rx(back, bn, 12);
      r = frames_in(Serial1.out);
      CHECK(r.size() == 2 && (uint8_t)r[1][0] == P_TRACE && r[1][2] == 2 && r32(r[1], 4) == 0xABCD && (uint8_t)r[1][12] == 0x51
            && r[1][14] == 20 && (int8_t)r[1][15] == -8 && r[1][16] == 12, "returning TRACE → PUSH_TRACE_DATA (hashes, SNRs, final SNR)"); }

    // ── contact editing
    { Contact c = ks.c[0];
      r = frame(B({13}) + K(bob.pub, 32));
      CHECK(r[0] == B({0}) && ks.c[0].out_len == OUT_PATH_UNKNOWN, "RESET_PATH");
      std::string f(148, '\0'); f[0] = 9; memcpy(&f[1], carol.pub, 32); f[33] = 1; f[34] = 1; f[35] = (char)0xFF; memcpy(&f[100], "Carol", 5);
      r = frame(f);
      CHECK(r[0] == B({0}) && ks.n == 3 && !strcmp(ks.c[2].name, "Carol") && ks.c[2].flags == 1, "ADD_UPDATE_CONTACT adds");
      r = frame(B({30}) + K(carol.pub, 32));
      CHECK(r[0].size() == 148 && r[0].substr(100, 5) == "Carol", "GET_CONTACT_BY_KEY");
      r = frame(B({15}) + K(carol.pub, 32));
      CHECK(r[0] == B({0}) && ks.n == 2, "REMOVE_CONTACT");
      r = frame(B({15}) + K(carol.pub, 32));
      CHECK(r[0] == B({1, 2}), "REMOVE_CONTACT unknown → ERR 2");
      (void)c; }
    { r = frame(B({17}));
      Pkt p; bool ok = r[0][0] == R_EXPORT && parse((const uint8_t*)r[0].data() + 1, r[0].size() - 1, p) && p.ptype == PT_ADVERT;
      uint8_t msg[80]; memcpy(msg, p.payload, 36); memcpy(msg + 36, p.payload + 100, p.payload_len - 100);
      CHECK(ok && r[0][1] == 0x11 && Ed25519::verify(p.payload + 36, p.payload, msg, 36 + p.payload_len - 100) && (p.payload[100] & 15) == 1,
            "EXPORT_CONTACT (self): a signed chat advert");
      n = mk_advert(pk, carol, now + 30);
      r = frame(B({18}) + K(pk, n));
      CHECK(r.size() == 2 && (uint8_t)r[0][0] == P_ADVERT && r[1] == B({0}) && ks.n == 3 && !strcmp(ks.c[2].name, "Carol"),
            "IMPORT_CONTACT: a raw advert becomes a contact (PUSH_ADVERT, then OK)"); }

    // ── persistence
    { fake_ms += 6000; comp_service();
      Contact b = ks.c[0];
      setup();
      CHECK(ks.n == 3 && !memcmp(&ks.c[0], &b, sizeof(Contact)) && !strcmp(ks.ch[1].name, "#test") && ks.pr.autoadd == 0x04,
            "contacts, channels and app settings survive a reboot");
      uint8_t s0 = c_slot;
      frame(B({15}) + K(carol.pub, 32)); fake_ms += 6000; comp_service();
      CHECK(c_slot != s0, "saves alternate between the two flash copies");
      fake_store[c_slot * C_SLOT_PAGES * 256 + 300] ^= 1;    // newest copy torn
      setup();
      CHECK(ks.n == 3, "a damaged newest copy falls back to the previous one");
      uint32_t e0 = erases;
      n = mk_advert(pk, bob, now + 40); rx(pk, n); fake_ms += 6000; comp_service();
      CHECK(erases == (int)e0 && c_dirty_at, "advert time stamps alone: saved lazily, not within seconds"); }

    // ── offline queue: channel messages give way, DMs are kept
    { while (c_dequeue(c_f)) {}
      uint8_t f[C_FRAME]; memset(f, 'x', sizeof(f));
      f[0] = R_CHANNEL_MSG_V3;
      for (int k = 0; k < 10; k++) c_enqueue(f, 150);
      f[0] = R_CONTACT_MSG_V3;
      c_enqueue(f, 150);
      int dms = 0, chans = 0; uint8_t o[C_FRAME]; int m;
      while ((m = c_dequeue(o))) { if (o[0] == R_CONTACT_MSG_V3) dms++; else chans++; }
      CHECK(dms == 1 && chans == 5, "queue full: oldest channel messages dropped for a DM");
      for (int k = 0; k < 10; k++) c_enqueue(f, 150);
      m = 0; while (c_dequeue(o)) m++;
      CHECK(m == 6, "queue full of DMs: new ones dropped, nothing overwritten"); }

    // ── framing robustness
    { Serial1.out.clear(); Serial1.in = std::string("<\x05\x00\x01", 4); cli_poll();
      fake_ms += 2000; comp_service();
      CHECK(c_in_state == 0, "half a frame then silence: back to idle");
      CHECK(cli("get name") == std::string("> ") + cfg.name, "console works after a broken frame");
      Serial1.out.clear(); Serial1.in = std::string("ab") + std::string("<\x01\x00\x0a", 4); cli_poll();
      r = frames_in(Serial1.out);
      CHECK(r.size() == 1 && r[0] == B({10}) && cli_len == 0, "app attached: '<' starts a frame even mid-line (resync)");
      Serial1.out.clear(); Serial1.in = std::string("\x01\x07zz\r", 5); cli_poll();
      CHECK(Serial1.out.find('>') == std::string::npos, "line noise: no echo, no 'Unknown command' reply on the app's stream"); }

    // ── radio settings from the app
    { r = frame(B({11}) + U32(869618) + U32(62500) + B({8, 8}));
      CHECK(r[0] == B({0}) && cfg.freq_khz == 869618 && cfg.bw_hz == 62500 && cfg.sf == 8, "SET_RADIO_PARAMS applied and saved");
      r = frame(B({11}) + U32(869618) + U32(62500) + B({8, 8, 1}));
      CHECK(r[0] == B({1, 6}), "client repeat requested → ERR 6 (not supported)");
      r = frame(B({12, 30}));
      CHECK(r[0] == B({1, 6}), "TX power above 22 dBm → ERR 6");
      r = frame(B({12, 17}));
      CHECK(r[0] == B({0}) && cfg.tx_dbm == 17, "SET_RADIO_TX_POWER");
      r = frame(B({21}) + U32(0) + U32(2000));
      r = frame(B({43}));
      CHECK(r[0].size() == 9 && r32(r[0], 5) == 2000 && cfg.af_x100 == 200, "tuning params round-trip (airtime factor 2.0)");
      r = frame(B({20}));
      CHECK(r[0].size() == 11 && r[0][0] == R_BATT && r32(r[0], 7) == C_SLOT_PAGES, "GET_BATT_AND_STORAGE");
      r = frame(B({56, 2}));
      CHECK(r[0].size() == 30 && r[0][1] == 2, "GET_STATS packets"); }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
