KEYS_AVB = (
    "vbmeta",
    "boot",
    "dtbo",
    "init_boot",
    "recovery",
    "system",
    "system_other",
    "vendor",
    "vbmeta_system",
    "vbmeta_vendor",
)

KEYS_OTHER = ("ota",)

KEYS_CORE = (
    "build/make/target/product/security/testkey",
    "build/make/target/product/security/media",
    "build/make/target/product/security/shared",
    "build/make/target/product/security/platform",
    "build/make/target/product/security/networkstack",
    "build/make/target/product/security/bluetooth",
    "build/make/target/product/security/sdk_sandbox",
    "build/make/target/product/security/nfc",
)

KEYS_APEX = (
    "com.android.adbd",
    "com.android.adservices",
    "com.android.runtime",
)

KEYS_APEX_APK = (
    "packages/modules/Connectivity/service/ServiceConnectivityResources/resources-certs/com.android.connectivity.resources",
    "packages/modules/Wifi/OsuLogin/certs/com.android.hotspot2.osulogin",
)

KEYS_APP = (
    "prebuilts/calyx/microg/certs/microg",
    "external/calyx/chromium/certs/chromium",
    "com.google.android.apps.photos",
    "prebuilts/calyx/lupin/updater/certs/org.calyxos.lupin.updater",
)

KEYS_REPO = ("updater",)

KEY_TYPES = (
    "avb",
    "apex_payload",
    "other",
    "core",
    "apex_container",
    "apex_apk",
    "app",
    "repo",
)

KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "other": "keys_other",
    "core": "keys_core",
    "apex_container": "keys_apex",
    "apex_payload": "keys_apex",
    "apex_apk": "keys_apex_apk",
    "app": "keys_app",
    "repo": "keys_repo",
}

MAPPED_KEY_TYPES = (
    "core",
    "apex_apk",
    "app",
)

ALL_DEVICES = (
    "bramble",
    "redfin",
    "barbet",
    "oriole",
    "raven",
    "FP4",
    "bluejay",
    "cheetah",
    "panther",
    "lynx",
    "devon",
    "hawao",
    "rhode",
    "tangorpro",
    "felix",
    "husky",
    "shiba",
    "FP5",
    "akita",
    "caiman",
    "comet",
    "komodo",
    "tokay",
    "otter",
    "bangkk",
    "fogo",
    "fogos",
    "tegu",
    "FP6",
    "stallion",
)
