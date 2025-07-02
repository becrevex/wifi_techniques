#!/bin/bash

FILE="WIFI_TECHNIQUES.md"

declare -A techniques
declare -A categories
declare -A index_to_block

load_techniques() {
    local idx=1
    local current_cat=""
    local block=""
    local title=""
    local in_block=0

    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" =~ ^\*\*Category:\*\* ]]; then
            current_cat=$(echo "$line" | sed 's/\*\*Category:\*\* //')
            continue
        fi

        if [[ "$line" =~ ^##+ ]]; then
            if [ -n "$block" ]; then
                techniques["$title"]="$block"
                index_to_block["$idx"]="$title"
                categories["$title"]="$current_cat"
                idx=$((idx + 1))
            fi
            title=$(echo "$line" | sed 's/^##\+\s*//')
            block="$title"
            continue
        fi

        if [ -n "$title" ]; then
            block="$block"$'\n'"$line"
        fi
    done < "$FILE"

    # Save last block
    if [ -n "$block" ]; then
        techniques["$title"]="$block"
        index_to_block["$idx"]="$title"
        categories["$title"]="$current_cat"
    fi
}

list_titles_by_category() {
    echo "Technique Titles Organized by Category:"
    local declared_categories=("ENCRYPTION FLAWS" "ATTACKING THE CLIENT" "ATTACKS ON THE WLAN" "ATTACKING WPA AND FREE RADIUS" "ADVANCED WLAN TECHNIQUES")
    local idx
    for cat in "${declared_categories[@]}"; do
        echo -e "\n$cat:"
        for idx in "${!index_to_block[@]}"; do
            title="${index_to_block[$idx]}"
            if [ "${categories[$title]}" == "$cat" ]; then
                echo "  [$idx] $title"
            fi
        done
    done
}

show_technique_by_number() {
    local num="$1"
    local title="${index_to_block[$num]}"
    if [ -z "$title" ]; then
        echo "Invalid technique number."
        return
    fi
    echo -e "\n=== Technique [$num]: $title ==="
    echo "${techniques[$title]}"
}

menu_system() {
    load_techniques
    list_titles_by_category
    echo ""
    read -p "Enter the technique number to view details (or 'q' to quit): " choice
    while [ "$choice" != "q" ]; do
        show_technique_by_number "$choice"
        echo ""
        read -p "Enter another number (or 'q' to quit): " choice
    done
}

usage() {
    echo "Usage: $0 [option]"
    echo "Options:"
    echo "  --menu                        Interactive menu to explore techniques"
    echo "  --titles                      Show all technique titles organized by category"
    echo "  --show <number>               Show technique details by number"
    exit 1
}

case "$1" in
    --menu)
        menu_system
        ;;
    --titles)
        load_techniques
        list_titles_by_category
        ;;
    --show)
        load_techniques
        show_technique_by_number "$2"
        ;;
    *)
        usage
        ;;
esac
