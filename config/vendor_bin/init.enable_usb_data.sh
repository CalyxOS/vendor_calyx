#!/vendor/bin/sh
# Helper script for enabling USB data based on the current type-C role

syntax() {
    echo "Syntax: $0 [usb-data-enabled-path] [value] [type-c-data-partner-path] [type-c-data-role-path] [find-for-host] ([other-path-to-change] [value-for-host-role] [value-for-other])..."
    echo
    echo "For example: $0 usb_data_enabled 1 partner role [host] mode host peripheral"
    echo "This first writes the value '1' is to the file 'usb_data_enabled' regardless of the role or whether a device is connected."
    echo "Then, we check to see if the path 'partner' exists, and if not, stop processing and exit, assuming that there is no USB device connected."
    echo "Next, we check the file 'role' for the contents '[host]', in which case the device is considered to be in USB host mode."
    echo "Finally, the file 'mode' has the value 'host' written to it if in USB host mode, or 'peripheral' if not."
    echo "The arguments can be expanded to modify as many files as necessary."
}

main() {
    case "$*" in
        --help|-h|"")
            syntax
            return 0
        ;;
    esac

    local data_enabled_path="$1"
    local data_enabled_value="$2"

    # Enable USB data.
    printf "%s" "$data_enabled_value" > "$data_enabled_path"

    local partner_path="$3"
    # Stop if no device connected.
    if [ ! -e "$partner_path" ]; then
        return 0
    fi

    local data_role_path="$4"
    local data_role_find_for_host="$5"
    shift 5

    local is_host_role=
    if grep -Fq "$data_role_find_for_host" "$data_role_path"; then
        is_host_role=1
    fi

    # Modify all provided files according to the current USB data role.
    while [ "$#" -ge 3 ]; do
        if [ -n "$is_host_role" ]; then
            printf "%s" "$2" > "$1"
        else
            printf "%s" "$3" > "$1"
        fi
        shift 3
    done
}

main "$@"
