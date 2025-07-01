#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$0")";pwd -P)
scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
source "$pkcs11_scriptpath/keygen.include.sh" || exit $?
# $scriptpath/vendor.softhsm.include.sh is included later, in initialize_pre_metadata()

_default_softhsm_token_dir=$HOME/.local/share/softhsm/tokens/

initialize_pre_metadata() {
  source "$pkcs11_scriptpath/vendor.softhsm.include.sh" || exit $?
  initialize_pre_metadata_pkcs11 "$@" || return $?
  export SOFTHSM2_CONF=${SOFTHSM2_CONF:-$HOME/.config/softhsm/softhsm2.conf}
  local token_dir=${SOFTHSM_TOKEN_DIR:-$_default_softhsm_token_dir}
  if [ ! -e "$SOFTHSM2_CONF" ]; then
    mkdir -p "$(dirname "$SOFTHSM2_CONF")"
    _generate_softhsm_config "$token_dir" > "$SOFTHSM2_CONF" || return $?
  fi
  if grep -Fqx "directories.tokendir = $token_dir" "$SOFTHSM2_CONF"; then
    if [ ! -d "$token_dir" ]; then
      if ! mkdir -p "$token_dir"; then
        echo "ERROR: Failed to create '$token_dir' directory for SoftHSM." >&2
        echo "       Please edit '$SOFTHSM2_CONF' to point directories.tokendir" >&2
        echo "       wherever you'd like, or set SOFTHSM2_CONF to your own config file." >&2
        exit 1
      fi
    fi
  fi
}

initialize_post_metadata() {
  initialize_post_metadata_pkcs11 "$@" || return $?
  maybe_initialize_token_pkcs11 || return $?
}

generate_keypair() {
  generate_keypair_pkcs11 "$@" || return $?
}

generate_cert() {
  generate_cert_pkcs11 "$@" || return $?
}

does_key_exist_yn() {
  does_key_exist_yn_pkcs11 "$@" || return $?
}

does_cert_exist_yn() {
  does_cert_exist_yn_pkcs11 "$@" || return $?
}

get_key_id_is_exportable_yn() {
  # Everything exportable.
  echo y
}

_generate_softhsm_config() {
  local token_dir=$1

  cat <<EOF || return $?
# SoftHSM v2 configuration file

directories.tokendir = $token_dir
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
#log.level = DEBUG
log.level = INFO

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = true

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
EOF
}

keygen_main "$@" || exit $?
