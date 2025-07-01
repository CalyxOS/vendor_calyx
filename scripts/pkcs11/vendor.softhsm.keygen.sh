#!/bin/bash
set -euo pipefail

scriptpath=$(cd "$(dirname "$0")/..";pwd -P)
source "$scriptpath/keygen.include.sh" || exit $?

_default_softhsm_token_dir=$HOME/.local/share/softhsm/tokens/

initialize_pre_metadata() {
  initialize_pre_metadata_pkcs11 "$@" || return $?
  case "${PKCS11_MODULE:-}" in
    ""|*softhsm*)
      export SOFTHSM2_CONF=$HOME/.config/softhsm/softhsm2.conf
      if [ ! -e "$SOFTHSM2_CONF" ]; then
        mkdir -p "$(dirname "$SOFTHSM2_CONF")"
        generate_softhsm_config > "$SOFTHSM2_CONF" || return $?
      fi
      export SOFTHSM2_CONF=~/.config/softhsm/softhsm2.conf
      ;;
  esac
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

ensure_key_not_exist() {
  ensure_key_not_exist_pkcs11 "$@" || return $?
}

find_pkcs11_module() {
  [ -z "${PKCS11_MODULE:-}" ] || return 0
  # There's got to be a better way.
  local -a possible_module_paths=(
    /usr/local/lib64/pkcs11/libsofthsm2.so
    /usr/local/lib64/libsofthsm2.so
    /usr/local/lib/pkcs11/libsofthsm2.so
    /usr/local/lib/libsofthsm2.so
    /usr/lib64/pkcs11/libsofthsm2.so
    /usr/lib64/libsofthsm2.so
    /usr/lib/pkcs11/libsofthsm2.so
    /usr/lib/libsofthsm2.so
  )
  local module_path; for module_path in "${possible_module_paths[@]}"; do
    if [ -e "$module_path" ]; then
      PKCS11_MODULE=$module_path
      return 0
    fi
  done
  echo "Please install the SoftHSM pkcs#11 module, or set PKCS11_MODULE to its path." >&2
  return 1
}

_generate_softhsm_config() {
  local token_dir=${SOFTHSM_TOKEN_DIR:-$_default_softhsm_token_dir}
  if [ ! -d "$token_dir" ]; then
    if ! mkdir -p "$token_dir"; then
      echo "ERROR: Failed to create '$token_dir' directory for SoftHSM." >&2
      echo "       Please edit '$SOFTHSM2_CONF' to point directories.tokendir" >&2
      echo "       wherever you'd like, or set SOFTHSM2_CONF to your own config file." >&2
      exit 1
    fi
  fi

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
