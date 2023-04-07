#!/vendor/bin/sh
# Helper script for enabling USB data based on the current type-C role

syntax() {
    echo "Syntax: $0 [type-c-data-role-path] [find-for-host] ([path-to-change] [value-for-host-role] [value-for-other])..."
    echo
    echo "For example: $0 role [host] usb_data_enabled 1 1 mode host peripheral"
    echo "This checks the file 'role' for the contents '[host]', in which case the device is considered to be in USB host mode."
    echo "Next, the value '1' is written to the file 'usb_data_enabled' regardless of the role, as it is specified for both conditions."
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

    local data_role_path="$1"
    local data_role_find_for_host="$2"
    shift 2

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
