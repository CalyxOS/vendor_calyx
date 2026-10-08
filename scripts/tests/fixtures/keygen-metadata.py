KEYS_AVB = ("vbmeta",)
KEYS_OTHER = ("ota",)
KEYS_CORE = ("build/make/target/product/security/testkey",)
KEYS_APEX = ("com.android.test",)
KEYS_APEX_APK = ()
KEYS_APP = ()
KEYS_REPO = ()
KEY_TYPES = ("avb", "apex_payload", "other", "core", "apex_container")
MAPPED_KEY_TYPES = ("core",)
ALL_DEVICES = ("bramble",)
KEY_TYPE_TO_ARRAY = {
    "avb": "keys_avb",
    "apex_payload": "keys_apex",
    "other": "keys_other",
    "core": "keys_core",
    "apex_container": "keys_apex",
}
