#include <iostream>
#include <unordered_map>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

int main() {
    using namespace httplib;
    std::string privkey = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,0203607604493E86

3ShcmguxrFBLjM6/W/pkGb1/im4nfxiBFwdneXh7Den9ZX3EVrkzpfI3BySACP4h
z11+5m9fCVdKp7lbirns5BHj6/JHoxabtc1u0rX2UgMHDNwhOrpdlvocKt00GTHg
lG+lq3Q0ikwV47yUcif7HlNOQqrv9I2OYCDV0kF5wYGugkELNk9oDqRUeN2ADe0q
V8kwjWEyl7ZL+oTFpQ8xgSOQR7OWDa5PA43gb1068AcdVSIKhcgx+cZIoOY6lUvu
reXpjp+bGmEX8n/1en51tXvRwQuwVj9Y0QD/ZeaZT0yVvGPFAlKZFBBmD+IBXq3J
9ecQxCKs19zgwHa0V/WdA7bl2Ebap8dhYo4ny6aC7NWEo3t8bEr3KMEEir6MNrU9
TzKQQF8WH2xLzAHiuraIDKzhBW3dHk/tmU6GBzpnwkD5pnrO/jTtGWu3Sm1FD6A6
xSHpSqcSJGITPp5OniDuhOUFNc3lxeitWApcZ51zg3gZwLGpD4twBtalTCNVuwpe
yvrgNlf8qCLTISCmveV0pKRoJK9QVm+WtOtEonhNx/eqKLliho2lMM8tYsabNpRy
CCffur8P4RtopwL7rUBrv4dIAHhrNBiAK3OIS5zX2nfBN9xTQE20wk2Ei9AzE6qo
6DvXHKfGU23mIzusdi3mDqYJo0vDEoknNTWSTbAWrpk0N1X536BiNRzaPKSnbLNL
4wSbvcukHcqg9XTQODEVOxpHS5OR9Kuf9FDsnE9ObuC/S0iHdZ75C1DYsLomX6y1
bCVLdi0LfzJ2TvVxk9vLD0Uy8NT/QAAloSkYorc0yrlVh1mWdY0rUB4MAbzsLyRL
mPBmp8E5RfgQPNekhHlJrODOqrvvU2Xc93Nf7uomET6SWZOxQdK3r41nfIsK1hZU
G5vSPUjYvXEHT1wLobJgv1WawwkDoUwpCORmAFpS2lpWvQQ5EzN7NlyNJq+lYoL+
ZzMVDONF+KYqJsMlDzHdfd2vPz7tonq+xoMky10AH5FBBH0wH5DSWYpwbQka/ugi
gDipH3Zt94Syqj1Mix4T0IG9M9beGBfC5kh+jS5xJX8Aoj8ff76GaliK0kU2SA2J
jOkDBZknJma6kxlGtzHWhilFHtO2nGvfzfHCm/zKG61pPUdSNpQj0rmuTGV4pLeG
WQQoRquYfJAHfn35YzGRg4+0rkLoPY4CSCWQWEREzHw1B4Q712hOcdqs8+3lsRBQ
q9yBfwlDvP8jjZBjktfOJhlfQ9OefrvDBnrlwPZq5BEQaBLPvo8g3AVdkOCeCBpc
kfAEpZHDrKoDp+u9/CGaje42aDAPhCH1Uy5RNNgcXUFQPhr/rNaAsB0pxgfgBDmq
LER1J4GLjtWyUMXROxpoYe8M/bYXS+xXz8pbNgXwULGe6M9cvTPC+32h6YyPrXNh
EnpgxleQYyWC+DCa7SYfIwT8cN5k5N9oUIRYGK8InAkdW12WfigvplyDa6znQxhp
IfBH+vsAJHrxiaC9Zi7+v2DMIKTZkXgxn7WJYCHsN0AafEC7g5/WEByxb+7f8A0q
wJGoEcQ2X942ZoOIc+DZZGTm8mF538qyuoxSHdaEHPSMB21AxM0Zg6TSVdAXndCM
-----END RSA PRIVATE KEY-----
"
    std::string pubkey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx+KHNRb2cDJTQKN+Hofa
OAGIZrDZMB8eH6Z5gUwgWAazBS2/6ntteXOv5kTngVY1H6zYQBjQhMZ1r3HgO118
rNnPBchSFeUQrlKBJAFKxV2pVw4JZA/694FUnHM96xdp2/OueZH4S1zokFCYfWVA
uY6FI0deGU9FgtfF5C25CPQ06vCbiZcMorqIC1/fcYOhjVqVGKME8+NunYryE6qB
C8L2i+plLUESnG0vnpeTkKtMYkfBPAUDICSqosILBG5D9Q0Ga875u3y8i6x8qmve
LHimFmmdzkfUD5KFJ+ezfiJ2qfLAar4XOsaRdtp8802ftcngmAnj0Ofc5ul3idTO
dwIDAQAB
-----END PUBLIC KEY-----
"
    unordered_map<std::string, std::string> umap;
    Server server;
    server.Get(R"/auth/*", [](const Request& req, Response& res) {
        auto token = jwt::create()
					 .set_issuer("auth0")
					 .set_type("JWT")
					 .set_id("rsa-create")
					 .set_issued_at(std::chrono::system_clock::now())
					 .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{86400})
					 .set_payload_claim("sample", jwt::claim(std::string{"sub=<username>"}))
					 .sign(jwt::algorithm::rs256("", privkey, "", ""));
        res.set_content(pubkey, "text/plain");
    }
    server.Get("/verify", [](const Request& req, Response& res) {
        auto verify = jwt::verify().allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", "")).with_issuer("auth0");
    }
    }
    return 0;
}