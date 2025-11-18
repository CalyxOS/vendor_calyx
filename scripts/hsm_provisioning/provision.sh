#!/usr/bin/env bash

set -euo pipefail

script_relpath=vendor/calyx/scripts
pkcs11_relpath=$script_relpath/hsm_provisioning
manifest_filename=prepare.package.manifest.tsv
shipped_manifest_relpath=$manifest_filename

declare -g KEEP_PATH

main() {
  if [ -z "${SOURCE_DIRECTORY:-}" ]; then
    echo "This script must be run from extract of ceremony.zip produced by create.ceremony.sh"
    return 1
  fi

  trap cleanup EXIT
  KEEP_PATH=${KEEP_PATH:-/dev/shm/keep}
  basepath=$SOURCE_DIRECTORY
  manifest_path=${manifest_path:-$basepath/$shipped_manifest_relpath}

  extract_tools
  maybe_install_tools
  maybe_start_yubihsm_connector_service

  ask_authkey_passwords_if_needed
  provision_hsm

  finish
}

extract_tools() {
  mkdir -p -m0700 "$SOURCE_DIRECTORY/sdk_packages" || return $?
  local file
  for file in "$SOURCE_DIRECTORY/sdk"/yubihsm2-sdk-*.tar.gz; do
    if [ ! -e "$file" ]; then
      echo "Could not find YubiHSM SDK in '$SOURCE_DIRECTORY/sdk'." >&2
      return 1
    fi
    tar -xf "$file" -C "$SOURCE_DIRECTORY/sdk_packages" || return $?
    # Don't want or need the development package.
    rm -f "$SOURCE_DIRECTORY/sdk_packages/yubihsm2-sdk/"libyubihsm-dev*.deb || true
    break
  done
}

maybe_install_tools() {
  echo
  echo "This step uses administrator privileges via sudo to install the packages required to provision YubiHSM 2."
  echo "You may be required to enter your administrator password."
  if ! confirm "Would you like to install these tools?"; then
    return 0
  fi

  sudo dpkg -i "$SOURCE_DIRECTORY/packages/"*.deb "$SOURCE_DIRECTORY/sdk_packages/yubihsm2-sdk/"*.deb || return $?
}

maybe_start_yubihsm_connector_service() {
  echo
  echo "This step uses administrator privileges via sudo to start the YubiHSM connector."
  echo "You may be required to enter your administrator password."
  if ! confirm "Would you like to start the YubiHSM connector?"; then
    return 0
  fi
  sudo systemctl start yubihsm-connector || return $?
}

ask_authkey_passwords_if_needed() {
  if [ -n "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ] && \
     [ -n "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ] && \
     [ -n "${YUBIHSM_ADMIN_AUTHKEY_PASSWORD:-}" ]; then
     return 0
  fi
  echo
  echo "Your HSM will have different authentication keys: signing, audit, and admin."
  echo "The signing key is used for most operations. Audit is used of course for auditing."
  echo "The admin key is able to create new authentication keys if needed in the future"
  echo "and has more capabilities than the others, but still lacks the ability to create"
  echo "or import any new wrap keys to ensure that the key shares are required for this."
  echo
  echo "Each key will have its own password. Please choose these passwords now."
  if [ -z "${YUBIHSM_SIGNING_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_SIGNING_AUTHKEY_PASSWORD "signing authkey password" || return $?
  fi
  if [ -z "${YUBIHSM_AUDIT_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_AUDIT_AUTHKEY_PASSWORD "audit authkey password" || return $?
  fi
  if [ -z "${YUBIHSM_ADMIN_AUTHKEY_PASSWORD:-}" ]; then
    read_password YUBIHSM_ADMIN_AUTHKEY_PASSWORD "admin authkey password" || return $?
  fi
}

provision_hsm() {
  (
    export YUBIHSM_ADMIN_AUTHKEY_PASSWORD=$YUBIHSM_ADMIN_AUTHKEY_PASSWORD
    export YUBIHSM_SIGNING_AUTHKEY_PASSWORD=$YUBIHSM_SIGNING_AUTHKEY_PASSWORD
    export YUBIHSM_AUDIT_AUTHKEY_PASSWORD=$YUBIHSM_AUDIT_AUTHKEY_PASSWORD
    # shellcheck disable=SC2030
    export KEEP_PATH=$KEEP_PATH
    "$basepath/$pkcs11_relpath/vendor.yubihsm.setup.py" || return $?
  ) || return $?
}

finish() {
  echo "Provisioning completed successfully!"
  echo "IMPORTANT: Do not forget to save the contents of:"
  printf "%s\n" "$KEEP_PATH"
}

cleanup() {
  echo
}

paths_exist_and_are_equal() {
  local path1
  local path2
  path1=$(realpath -e --no-symlinks "$1" 2>/dev/null) || return $?
  path2=$(realpath -e --no-symlinks "$2" 2>/dev/null) || return $?
  [ "$path1" = "$path2" ]
}

confirm() {
  while true; do
    printf "%s" "$1 (Y/N) "
    local response
    read -r response
    case "$response" in
      Y|y)
        break ;;
      N|n)
        return 1 ;;
      *)
        echo "Please enter Y or N." >&2 ;;
    esac
  done
}

read_password() {
  local variable=$1
  local prompt=$2
  local confirm=${3:-y}
  while true; do
    local try1
    local try2
    printf "Enter %s: " "$prompt"
    read -r -s try1
    echo
    if [ "$confirm" = "y" ]; then
      printf "Confirm %s: " "$prompt"
      read -r -s try2
      echo
      if [ -z "$try1" ] && [ -z "$try2" ]; then
        return 1
      fi
    else
      try2=$try1
    fi
    if [ "$try1" = "$try2" ]; then
      declare -g "$variable=$try1"
      return 0
    else
      echo "Passwords do not match." >&2
    fi
  done
}

main "$@"
