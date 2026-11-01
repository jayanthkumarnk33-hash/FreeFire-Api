# Game client release identification.
#
# RELEASEVERSION is the OB build the client reports. It must be sent both as the
# "ReleaseVersion" header and as "X-GA-RV" on the MajorLogin request; the two
# values are the same string on the wire.
#
# Verified live against loginbp.ggpolarbear.com on 2026-11-01 with the IND guest
# account: RELEASEVERSION "OB55" (and the plain "1.134.1" form) both complete
# MajorLogin, while a request sent without the X-GA-RV / X-GA-SV pair is rejected
# with HTTP 400 "SignError1".
RELEASEVERSION = "OB55"

# APK evidence for this build (base/AndroidManifest.xml, libil2cpp metadata):
#   package        cct.com.garena.game.ffi
#   versionName    1.134.1
#   releasechannel FFO_OB55_PRELive_1.134.1_2019121269_4653253_gp-india_unity2022_aab_sidekick_extend
#   Unity          2022.3.47f1
GAME_VERSION = "1.134.1"
UNITY_VERSION = "2022.3.47f1"

# MajorLogin edge-signature headers. All three are required: X-GA alone returns
# HTTP 400 "SignError1". X-GA-RV carries the release version, X-GA-SV the
# signature scheme version.
X_GA = "v1 1"
X_GA_RV = RELEASEVERSION
X_GA_SV = "1"

MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"

# 'GenerateNickname' is a separate RPC in the APK's method table (next to
# MajorLogin/MajorRegister), served from the same login host. The client calls it
# during first login to obtain a name before finishing registration. Confirmed
# live: HTTP 200 with a plain protobuf body whose field 1 is the nickname.
GENERATE_NICKNAME_URL = "https://loginbp.ggpolarbear.com/GenerateNickname"

GARENA_TOKEN_URL = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"

# Garena MSDK host. Every path below is taken from the shipped APK's endpoint
# table (com.beetalk.sdk.A0), not from a third-party implementation.
GARENA_CONNECT_URL = "https://connect.garena.com"

# A0 line 222: R() + "/oauth/user/info/get". Takes access_token, returns the
# account's uid, open_id, platform and main_active_platform. This is the only
# route that proves the OAuth credential is still valid, because it answers 200
# with real account data rather than an auth error.
GARENA_USER_INFO_URL = GARENA_CONNECT_URL + "/oauth/user/info/get"

# A0 line 256: R() + "/bind/app/platform/info/get". Takes access_token + app_id
# (com.beetalk.sdk.networking.service.j.f). Returns bounded_accounts and
# available_platforms, which is how the client learns whether a platform
# account has been linked yet.
GARENA_BIND_INFO_URL = GARENA_CONNECT_URL + "/bind/app/platform/info/get"

# Garena MSDK application credentials (public client constants, also present in
# the shipped APK).
GARENA_CLIENT_ID = "100067"
GARENA_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# Network timeout (connect, read) applied to every upstream request.
REQUEST_TIMEOUT = (10, 25)

# Debug logging. Never enable against real accounts: upstream responses contain
# bearer tokens, open_ids and refresh tokens.
DEBUG = False
