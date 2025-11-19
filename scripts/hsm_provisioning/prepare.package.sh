#!/usr/bin/env bash

set -euo pipefail

our_path=$(cd "$(dirname "$0")";pwd -P)
PROVISIONING_PATH=${PROVISIONING_PATH:-/dev/shm/hsmp}
manifest_filename=manifest.tsv
# tmp_dir will get removed in cleanup()
tmp_dir=

main() {
  trap cleanup EXIT
  if [ -z "${SOURCE_DIRECTORY:-}" ]; then
    # Update this if this script's relative path changes!
    SOURCE_DIRECTORY=${our_path%vendor/calyx/*}
    SOURCE_DIRECTORY=${SOURCE_DIRECTORY%/}
  fi
  basepath=${basepath:-$SOURCE_DIRECTORY}

  tmp_dir=$(mktemp -d)
  output_directory="$tmp_dir/ceremony"
  zip_file="$(pwd)/ceremony.zip"
  echo "We will now prepare $zip_file with the files needed for provisioning."
  echo
  if [ ! -d "$output_directory" ]; then
    mkdir -p "$output_directory" || return $?
  fi
  generate_start_script > "$output_directory/start.sh" || return $?
  chmod +x "$output_directory/start.sh" || true # If this does not work, oh well.
  # copy files over to output dir
  prepare_manifest_and_files "$output_directory" || return $?
  # verify copied files
  verify_files "$output_directory/$manifest_filename" "$output_directory" || return $?
  # delete manifest as we won't need it anymore
  rm "$output_directory/$manifest_filename"
  # move scripts to a more sane location
  mv "$output_directory/vendor/calyx/scripts/hsm_provisioning" "$output_directory/scripts"
  # create a zip file
  rm "$zip_file" 2> /dev/null || true
  (
    cd $tmp_dir && \
    zip -r "$zip_file" ceremony
  )
  # print out zip file name and hash
  echo "$zip_file"
  sha256sum "$zip_file"
}

generate_start_script() {
  cat <<EOF
#!/bin/bash
our_path=\$(cd "\$(dirname "\$0")";pwd -P)
SOURCE_DIRECTORY="\$our_path" exec "\$our_path/scripts/provision.py" "\$@"
EOF
}

prepare_manifest_and_files() {
  local output_directory
  output_directory=$(realpath --no-symlinks "$1")
  local -a manifest_lines
  local -a new_manifest_lines=($'filename\tsha256sum\tfilesize\tlink')
  mapfile -t manifest_lines < "$our_path/$manifest_filename" \
    || return $?
  local line
  local header_done=
  for line in "${manifest_lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    if [ -z "$header_done" ]; then
      header_done=y
      if [ "$1" = "filename" ]; then
        # skip header
        continue
      fi
    fi
    local filename=${1:-}
    local sha256sum=${2:-}
    local file_size=${3:-}
    local link=${4:-}
    local dest_file=$output_directory/$filename
    local output_path
    output_path=$(realpath -m --no-symlinks "$dest_file")
    case "$output_path" in
      "$output_directory"/*)
        true ;; # Expected, no weird path traversal
      *)
        echo "Unacceptable path traversal in $filename" >&2
        return 1 ;;
    esac

    # Make the directories needed by this file.
    mkdir -p "$(dirname "$dest_file")" || return $?

    if [ -n "$link" ]; then
      # Download the file if it does not already exist or does not match the sha256sum.
      if [ -e "$dest_file" ]; then
        if [ "$(sha256sum "$dest_file" | cut -d' ' -f1)" != "$sha256sum" ]; then
          printf "%s does not match expected sha256sum. Deleting and re-downloading..." \
            "$dest_file" >&2
          rm -f "$dest_file" || return $?
        fi
      fi
      if [ ! -e "$dest_file" ]; then
        echo "Downloading $dest_file..."
        (ulimit -f "$file_size" || true; wget -O "$dest_file" "$link") || return $?
      fi
    else
      # Copy the file.
      local source_file=
      local we_generated=
      case "$filename" in
        start.sh)
          # We generate it, so no need to copy, etc.
          we_generated=y ;;
        *)
          source_file=$SOURCE_DIRECTORY/$filename ;;
      esac
      if [ "$we_generated" != "y" ] && [ ! -e "$source_file" ]; then
        echo "Cannot find $filename." >&2
        echo "Run this script from a lunch'd Android build environment, or run it from" >&2
        echo "an extracted otatools-keys.zip directory:" >&2
        echo "  unzip otatools-keys.zip -d otatools-keys" >&2
        echo "  cd otatools-keys" >&2
        echo "  $our_path/prepare.package.sh" >&2
        echo "(otatools-keys.zip is built with: m otatools-keys-package)" >&2
        return 1
      fi
      if [ -n "$sha256sum" ] && [ "$(sha256sum "$dest_file" | cut -d' ' -f1)" != "$sha256sum" ];
      then
        printf "%s does not match expected sha256sum and no link provided!" \
          "$dest_file" >&2
      fi
      if [ "$we_generated" != "y" ]; then
        file_size=$(stat -c%s "$source_file") || return $?
        cp -p "$source_file" "$dest_file" || return $?
      else
        file_size=$(stat -c%s "$dest_file") || return $?
      fi
    fi
    if [ -z "$sha256sum" ]; then
      sha256sum=$(sha256sum "$dest_file" | cut -d' ' -f1) || return $?
    fi
    new_manifest_lines+=("$filename"$'\t'"$sha256sum"$'\t'"$file_size"$'\t'"$link")
  done
  mkdir -p "$(dirname "$output_directory/$manifest_filename")" || return $?
  printf "%s\n" "${new_manifest_lines[@]}" > "$output_directory/$manifest_filename" || return $?
}

verify_files() {
  local manifest_path=$1
  local check_directory=$2
  local check_for_extra_files=${3:-}
  local -a manifest_lines
  mapfile -t manifest_lines < "$manifest_path" || return $?
  local line
  local header_done=
  local -a failed_files=()
  local -a mismatched_files=()
  local -a successful_files=()
  local -A manifest_files=()
  for line in "${manifest_lines[@]}"; do
    local oldIFS=$IFS
    IFS=$'\t'; set -- $line; IFS=$oldIFS
    if [ -z "$header_done" ]; then
      header_done=y
      if [ "$1" = "filename" ]; then
        # skip header
        continue
      fi
    fi
    local filename=$1
    manifest_files[$filename]=1
    local sha256sum=$2
    local actual_sum
    actual_sum=$(cd "$check_directory" && sha256sum "$filename" | cut -d' ' -f1) || true
    if [ -z "$actual_sum" ]; then
      failed_files+=("$filename")
    elif [ "$actual_sum" != "$sha256sum" ]; then
      mismatched_files+=("$filename")
    else
      successful_files+=("$filename")
    fi
  done
  local returnval=0
  if [ "${#failed_files[@]}" -eq 0 ] && [ "${#mismatched_files[@]}" -eq 0 ]; then
    echo "All files verified successfully."
  else
    echo >&2
    if [ "${#failed_files[@]}" -gt 0 ]; then
      echo "The following files were missing or sha256sum failed to run:" >&2
      printf "  %s\n" "${failed_files[@]}" >&2
    fi
    if [ "${#mismatched_files[@]}" -gt 0 ]; then
      echo "The following files FAILED sha256sum verification:" >&2
      printf "  %s\n" "${mismatched_files[@]}" >&2
    fi
    returnval=1
  fi
  if [ "${check_for_extra_files:-}" = "y" ]; then
    # This won't result in an error, just informational.
    local -a all_actual_files=()
    mapfile -t -d '' all_actual_files < <(cd "$check_directory"; find -type f -print0 | sort -z)
    local actual_file
    local -a extra_files=()
    for actual_file in "${all_actual_files[@]}"; do
      actual_file=${actual_file#./}
      case "$manifest_path" in
        *$actual_file)
          # The manifest cannot contain an entry for itself.
          continue ;;
      esac
      if [ "${manifest_files[$actual_file]:-}" != "1" ]; then
        extra_files+=("$actual_file")
      fi
    done
    if [ "${#extra_files[@]}" -gt 0 ]; then
      echo "The following extra files were found:" >&2
      printf "  %s\n" "${extra_files[@]}" >&2
    fi
  fi
  return $returnval
}

cleanup() {
  rm -rf "$tmp_dir"
}

main "$@"
