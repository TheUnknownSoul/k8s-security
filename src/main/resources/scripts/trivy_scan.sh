#!/bin/bash

trivy=$(trivy)
purple_color='\033[35m'
green_color='\033[32m'
red_color='\033[31m'
reset_color='\033[0m'

function check_is_trivy_installed(){
    if [ "$(dpkg-query -W -f='${Status}' trivy 2>/dev/null | grep -c "ok installed")" -eq 0 ]; then
        echo -e "${red_color}Trivy not installed. Install it first.${reset_color}"
        exit 1
    fi
}
function escalate_privileges() {
    if [[ $EUID -ne 0 ]]; then
      echo  -e "${purple_color}Root rights required ${reset_color}"
      exec sudo "$0" "$@"
    fi
}

function check_arguments(){
    if [ -z "$1" ]; then
        echo "Enter path to the folder with images."
        exit 1
    fi
}

function pull_images_and_scan(){
    while IFS= read -r container; do
        if [[ -z "$container" ]]; then
    	    continue #skip empty lines
        fi

        output_file="scan_results_${container}//[:v]/_}.txt"

        echo -e "${purple_color}Scanning container: ${container} ${reset_color}"

        # Run Trivy scan and save result to a file
        $trivy image "$container" --quit > "$output_file"

        # Check if Trivy exited with error
        if [[ $? -ne 0 ]]; then
    	    echo -e "${red_color}Error scanning $container. Skipping to the next container... ${reset_color}"
        else
            echo -e "${green_color}Scan completed for $container. Results saved to ${reset_color} $output_file"
        fi
    done < "$1"

    echo -e "${green_color}All scan completed. ${reset_color}"
}

check_is_trivy_installed
escalate_privileges "$0"
check_arguments "$@"
pull_images_and_scan "$1"