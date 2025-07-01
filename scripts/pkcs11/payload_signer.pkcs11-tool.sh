#!/bin/bash
set -euo pipefail

pkcs11_scriptpath=$(cd "$(dirname "$0")";pwd -P)
source "$pkcs11_scriptpath/include.sh" || exit $?

_default_payload_signature_size=256  # 2048-bit

main() {
  unset skip_padding
  # Handle arguments.
  args=()
  declare -g input_file
  declare -g output_file
  declare -g key_file
  while [ $# -gt 0 ]; do
    case "$1" in
      "-in")
        input_file=$2
        shift 1
        ;;
      "-out")
        output_file=$2
        shift 1
        ;;
      "-inkey")
        key_file=$2
        shift 1
        ;;
      *)
        break
        ;;
    esac
    shift 1
  done

  local key=$(_get_key_name "$key_file")

  # Workaround for the fact that pkcs11-tool ignores --label during a --sign operation.
  local id_and_rsa_key_size
  id_and_rsa_key_size=$(_get_id_and_rsa_key_size_for_key "$key")
  local id=${id_and_rsa_key_size%%;*}
  local rsa_key_size=${id_and_rsa_key_size#*;}

  if [ -z "$id" ]; then
    echo "Could not found find key with label '$key'" >&2
    return 1
  fi

  if [ -n "${rsa_key_size:-}" ]; then
    PAYLOAD_SIGNATURE_SIZE=$(($rsa_key_size / 8))
  fi

  local -a args
  if [ "${SIGNING_USES_SO_PIN:-}" = "y" ]; then
    args=("${pkcs11_tool_args_so_pin[@]}")
  else
    args=("${pkcs11_tool_args[@]}")
  fi

  "$PKCS11_TOOL_BIN" --sign -m RSA-PKCS --id "$id" \
    --input-file <(skip_padding=y _pkcs1-v1_5-encode-prehashed "$input_file") \
    --output-file "$output_file" \
    "${args[@]}" || return $?
}

_pkcs1-v1_5-encode-prehashed() {
  local input_size=$(wc -c < "$input_file")
  # SHA-256 DigestInfo prefix is 19 bytes.
  local digest_prefix_length=19
  # Payload signature size in bytes (256=2048-bit, 512=4096-bit)
  local payload_signature_size=${PAYLOAD_SIGNATURE_SIZE:-$_default_payload_signature_size}
  # See: https://www.rfc-editor.org/rfc/rfc3447#section-9.2
  # BEGIN EM
    local tLen=$(($input_size+$digest_prefix_length))
    local emLen=$payload_signature_size
    if [ "${skip_padding:-n}" = "n" ]; then
      printf "\x00\x01"
      # BEGIN PS
        for i in `seq $(($emLen-$tLen-3))`; do
          printf "\xff"
        done
        printf "\00"
      # END PS
    fi
    # BEGIN T: DigestInfo: SHA-256
      printf "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
      cat "$input_file"
    # END T: DigestInfo: SHA-256
  # END EM
}

main "$@" || exit $?

if [ "${DEBUG_PAYLOAD_SIGNER:-y}" = "y" ]; then
  # Performs payload signing using both pkcs11-tool and openssl,
  # stores the output in a temporary folder, and looks for differences.
  # If there are differences, fails.
  dtstmp=$(date +%Y%m%d-%H%M%S.%N)
  outdir=/dev/shm/payload_signer_debug/$dtstmp/
  mkdir -p -m0700 "$outdir"
  cat "$input_file" > "$outdir/input.bin"
  cat "$output_file" > "$outdir/output-pkcs11-tool.bin"
  printf "%s\n" "$@" > "$outdir/arguments.txt"
  if [ -e "$key_file" ]; then
    cat "$key_file" > "$outdir/$(basename "$key_file")"
  fi
  "$pkcs11_scriptpath/payload_signer.openssl.sh" "$@" || exit $?
  cat "$output_file" > "$outdir/output-openssl.bin"

  if ! diff -q "$outdir/output-pkcs11-tool.bin" "$outdir/output-openssl.bin"; then
    echo "Problem: $outdir" >> /dev/shm/payload_signer_debug/problems.txt
    echo broken > "$outdir/broken.txt"
    exit 1
  fi

  cat "$outdir/output-pkcs11-tool.bin" > "$output_file"
fi
