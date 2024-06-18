#!/bin/bash

# Function to check that required tools are installed and mapped
check_tools(){
    # Check if tools are installed
    if ! command -v xterm &> /dev/null ; then echo -e "\e[31m[+] ERROR: xterm not found. run 'apt install xterm'\e[0m"; exit 1; fi
    if ! command -v gowitness &> /dev/null ; then echo -e "\e[31m[+] - gowitness not found. run 'apt install -y gowitness'\e[0m"; exit 1; fi
    if ! command -v netexec &> /dev/null ; then echo -e "\e[31m[+] - netexec not found. Install netexec\e[0m"; exit 1; fi
}

# Function to create folder structure
create_folder_structure() {
    echo "Checking folder structure..."
    local folder_structure=("scans/nmap/" "scans/masscan" "scans/parsed/port-lists" "scans/parsed/port-files" "web/gowitness/screenshots" "targets" "logs")
    local folders_exist=true

    for folder in "${folder_structure[@]}"; do
        if [ ! -d "$folder" ]; then
            folders_exist=false
            break
        fi
    done

    if [ "$folders_exist" = true ]; then
        read -p "Folders already exist. Do you want to continue? (Y/n): " response
        case "$response" in
            [Yy]* )
                echo -e "Skipping folder creation.\n"
                ;;
            [Nn]* )
                echo -e "Aborting script.\n"
                exit 1
                ;;
            * )
                echo -e "Invalid response. Aborting script."
                exit 1
                ;;
        esac
    else
        echo "Creating folder structure..."
        for folder in "${folder_structure[@]}"; do
            mkdir -p "$folder"
        done
        echo -e "Folder structure created.\n"
    fi
    
    ## Create a log file specific to this run
    touch $log_file
}

# Function to create target files
run_target_gen() {
    echo -e "$(get_time): Starting Target Generation" >> $log_file
    
    echo "Creating target files..."
    local targets_file="$1"
    local exclude_file="$2"
    
    if [ -z "$targets_file" ]; then
	    echo "An input file is required. Use -i to specify the in scope ranges or IPs file."
	    exit 1
    fi

    if [ -n "$exclude_file" ]; then
	    nmap -iL $targets_file -sL -n --excludefile $exclude_file 2> targets/errors.txt |  grep report |  awk '{print $5}' > targets/targets_all.txt
    else
	    nmap -iL $targets_file -sL -n 2> targets/errors.txt | grep report | awk '{print $5}' > targets/targets_all.txt
    fi
    
    # Logic to check if we were given an invalid IP
    if [ -s targets/errors.txt ]; then
        echo -e "\e[31m[+] ERROR: The input file provided has invalid or unresolvable hosts.\e[0m"
        awk '{print $4}' targets/errors.txt | tr -d '"'
        rm targets/errors.txt
        read -p "Do you want to ignore these hosts and continue testing? (Y/n): " response
        case "$response" in
	    [Yy]* )
		echo -e "Continuing...\n"
		;;
	    [Nn]* )
		echo -e "Aborting script.\n"
		exit 1
		;;
	    * )
		echo -e "Invalid response. Aborting script.\n"
		exit 1
		;;
	esac
    else
        rm targets/errors.txt
    fi

    # Logic to ensure that IPs are privite addresses and throw a warning if its now 
    external_ip_count=0
    while read ip; do
	    [[ -z "$ip" ]] && continue
	    if [[ ! "$ip" =~ ^10\..* ]] &&  [[ ! "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] && [[ ! "$ip" =~ ^192\.168\..* ]] && [[ ! "$ip" = ^127\..* ]]; then
		echo -e "\e[33m[+] WARNING: Your targets include external IP addresses, please validate $ip is in scope.\e[0m"
		((external_ip_count++))
	    fi
    done < targets/targets_all.txt

    if [[ $external_ip_count > 0 ]]; then
	    read -p "You have $external_ip_count external IPs. Do you wish to continue? (Y/n): " response
	    case "$response" in
		    [Yy]* )
			    echo -e "Continuing...\n"
			    ;;
		    [Nn]* )
			    echo -e "Aborting script.\n"
			    exit 1
			    ;;
		    * )
			    echo -e "Invalid response. Aborting script.\n"
			    exit 1
			    ;;
	    esac
    else
        echo -e "Target files have been generated and saved in the targets folder.\n"
        echo -e "$(get_time): Finished Target Generation" >> $log_file
    fi
}

# Function to run masscan for discovery
run_discovery_scan() {
    echo -e "$(get_time): Starting Discovery Scans" >> $log_file

    # This needs root - need to adjust or set sticky bit
    sudo masscan --open -Pn -n -iL targets/targets_all.txt --top-ports 100 --rate 1500 -oG scans/masscan/discovery.gnmap
    echo -e "Discovery scans complete.\n"
    echo -e "Parsing discovery scans..."
    grep -v ^# scans/masscan/discovery.gnmap | awk '{print $4}' | sort -u > targets/discovered_hosts.txt
    living_host_count=$(cat targets/discovered_hosts.txt | wc | awk '{print $1}')
    echo -e "There are $living_host_count discovered hosts. The list is in targets folder.\n"
   
    echo -e "$(get_time): Finished Discovery Scans" >> $log_file
}

# Function to run nmap script and service scan on all TCP ports for discovered hosts
run_full_tcp_scan() {
    echo -e "$(get_time): Starting TCP Scans" >> $log_file
    
    # This is also defined in the run_discovery_scan function and should be pulled out to a global variable
    living_host_count=$(cat targets/discovered_hosts.txt | wc | awk '{print $1}')
    if [[ $living_host_count -lt 2500 ]]; then
        nmap -sT -sV -sC --open -p- -iL targets/discovered_hosts.txt -oA scans/nmap/full_tcp
    	echo -e "TCP service and script scans complete.\n"
    	echo -e "$(get_time): Finished TCP Scans" >> $log_file
    else
    	echo -e "\e[33m[+] WARNING: You have more than 2500 hosts. A top 1000 port scan will be performed before running a full scan in the background.\e[0m"
    	nmap -sT -sV -sC --open -iL targets/discovered_hosts.txt -oA scans/nmap/top_1000_tcp
    	echo -e "Service and script scans complete.\n"
    	echo -e "$(get_time): Finished TCP Quick Scan" >> $log_file
    	echo -e "$(get_time): Starting TCP Full Scan" >> $log_file
        echo -e "Opening xterm and performing a full TCP scan in the background.\n"
        ## Logic needs check here - can't use defined variables since xterm won't know them. Have it writing to all log files which could dirty things.
        $(xterm -e 'nmap -sT -sV -sC --open -p- -iL targets/discovered_hosts.txt -oA scans/nmap/full'; echo -e "$(date +%m-%d-%Y_%H:%M.%S_%p_%Z): Finished TCP Full Scan" >> logs/*.log) &
    fi 
}

# Function to run nmap for top 100 UDP ports
run_top_100_udp_scan() {
    echo -e "$(get_time): Starting UDP Scans" >> $log_file

    # Needs sudo here as well
    sudo nmap -sU -F --open -iL targets/discovered_hosts.txt -oA scans/nmap/top_100_udp
    echo -e "\nUDP scans complete.\n"
    
    echo -e "$(get_time): Finished UDP Scans" >> $log_file
}

# Function to parse the script results - stolen from gnmap-parser
parse_scans() {
    echo -e "$(get_time): Starting Target Parsing" >> $log_file

    local ipsorter='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'
      
    # Build TCP Port List
    cat scans/nmap/*.gnmap | grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/udp|filtered/'|cut -d"/" -f 1|sort -n -u > scans/parsed/port-lists/TCP-Ports-List.txt
    # Build UDP Port List
    cat scans/nmap/*.gnmap | grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/tcp|filtered/'|cut -d"/" -f 1|sort -n -u > scans/parsed/port-lists/UDP-Ports-List.txt
    # Build TCP Port Files
    echo -e "Building TCP Port Files...\n"
    while read i; do
        cat scans/nmap/*gnmap | grep "$i/open/tcp" | sed -e 's/Host: //g' -e 's/ (.*//g'| ${ipsorter} > scans/parsed/port-files/TCP-$i.txt
    done < scans/parsed/port-lists/TCP-Ports-List.txt
    # Build UDP Port Files
    echo -e "Building UDP Port Files...\n"
    while read i; do
        cat scans/nmap/*gnmap | grep "$i/open/udp" | sed -e 's/Host: //g' -e 's/ (.*//g'| ${ipsorter} > scans/parsed/port-files/UDP-$i.txt
    done < scans/parsed/port-lists/UDP-Ports-List.txt
    echo -e "Nmap scans have been parsed and are stored in scans/parsed.\n"
    
    echo -e "$(get_time): Finished Target Parsing" >> $log_file
}

# Function to kick off gowitness
run_gowitness(){
    echo -e "$(get_time): Starting GoWitness" >> $log_file
    
    gowitness nmap -f $nmapDirectory/*.xml --open --service-contains http --db-location sqlite://$gowitnessDatabase --screenshot-path "$gowitnessScreenshotsDirectory/"
    
    echo -e "$(get_time): Finished GoWitness" >> $log_file
}

# Function to parse out the gowitness results
format_gowitness_results(){
    echo -e "$(get_time): Starting GoWitness Parsing" >> $log_file
    
    # Multiple rows per name
    sqlite3 -header -csv "$gowitnessDatabase" "
    WITH server_headers AS (
	SELECT url_id, value AS server
	FROM headers
	WHERE key = 'Server'
    )
    SELECT urls.url, urls.final_url, urls.response_code, urls.response_reason, urls.proto, 
	   urls.content_length, urls.title, urls.filename, urls.is_pdf, 
	   COALESCE(tls_certificate_dns_names.name, '') AS name,
	   COALESCE(server_headers.server, '') AS server
    FROM urls
    LEFT JOIN tls ON urls.id = tls.url_id
    LEFT JOIN tls_certificates ON tls.id = tls_certificates.tls_id
    LEFT JOIN tls_certificate_dns_names ON tls_certificates.id = tls_certificate_dns_names.tls_certificate_id
    LEFT JOIN server_headers ON urls.id = server_headers.url_id
    ORDER BY urls.response_code;" > $gowitnessDirectory/gowitness-output-1-multiple-rows-per-name.csv

    # Multiple names in one cell
    sqlite3 -header -csv "$gowitnessDatabase" "
    WITH headers_cte AS (
	SELECT url_id,
	    MAX(CASE WHEN key = 'Expires' THEN value END) AS expires,
	    MAX(CASE WHEN key = 'Last-Modified' THEN value END) AS last_modified,
	    MAX(CASE WHEN key = 'Server' THEN value END) AS server,
	    MAX(CASE WHEN key = 'Content-Type' THEN value END) AS content_type,
	    MAX(CASE WHEN key = 'Content-Length' THEN value END) AS content_length_header
	FROM headers
	GROUP BY url_id
    ),
    names_aggregated AS (
	SELECT tls_certificates.tls_id AS url_id,
	    GROUP_CONCAT(tls_certificate_dns_names.name, ', ') AS certificate_names
	FROM tls_certificates
	LEFT JOIN tls_certificate_dns_names ON tls_certificates.id = tls_certificate_dns_names.tls_certificate_id
	GROUP BY tls_certificates.tls_id
    )
    SELECT u.url, u.final_url, u.response_code, u.response_reason, u.proto, 
        u.content_length, u.title, u.filename, u.is_pdf, 
	COALESCE(na.certificate_names, '') AS certificate_names,
	hc.expires, hc.last_modified, hc.server, hc.content_type, hc.content_length_header
    FROM urls u
    LEFT JOIN tls t ON u.id = t.url_id
    LEFT JOIN names_aggregated na ON t.id = na.url_id
    LEFT JOIN headers_cte hc ON u.id = hc.url_id
    ORDER BY u.response_code;" > $gowitnessDirectory/gowitness-output-2-combined-names.csv

    # sqlite3 -header -csv gowitness.sqlite3 "SELECT subject_common_name FROM tls_certificates"
    # sqlite3 -header -csv gowitness.sqlite3 "SELECT name FROM tls_certificate_dns_names"
    sqlite3 -csv $gowitnessDatabase "
    SELECT subject_common_name AS name
    FROM tls_certificates
    WHERE subject_common_name NOT LIKE '% %'
    UNION
    SELECT name
    FROM tls_certificate_dns_names
    WHERE name NOT LIKE '% %'
    ORDER BY name COLLATE NOCASE;" > $gowitnessDirectory/gowitness-output-3-fqdns-and-names.txt

    sqlite3 -header -csv "$gowitnessDatabase" "
    SELECT urls.url,
        COALESCE(tls_certificate_dns_names.name, '') AS name
    FROM urls
    LEFT JOIN tls ON urls.id = tls.url_id
    LEFT JOIN tls_certificates ON tls.id = tls_certificates.tls_id
    LEFT JOIN tls_certificate_dns_names ON tls_certificates.id = tls_certificate_dns_names.tls_certificate_id;" > $gowitnessDirectory/gowitness-output-4-urls-and-names.csv
    cat $gowitnessDirectory/gowitness-output-4-urls-and-names.csv | sed 's/http.*:\/\///g' | awk -F'[:,]' '{print $1 "," $3}' | sort -Vu | grep -v \"\" | grep -v "url," > $gowitnessDirectory/gowitness-output-4-urls-and-names.csv 

    # Sort the screenshots
    sqlite3 -separator ' ' -list $gowitnessDatabase "SELECT response_code, filename FROM urls;" | while read -r response_code filename; do

	# Create destination directory based on response_code
	dest_path="$gowitnessScreenshotsDirectory/$response_code/"
	mkdir -p "$dest_path"

	# Move file to destination directory
	source_path="$gowitnessScreenshotsDirectory/$filename"
	if [ -f "$source_path" ]; then
	    cp "$source_path" "$dest_path"
	else
	    echo "File not found: $source_path"
	fi
    done
    echo -e "$(get_time): Finished GoWitness Parsing" >> $log_file
}

# Function to handle exits
cleanup() {
    wait
    echo -e "$(get_time): Script Execution Stopped" >> $log_file
}

# Function to handle exits via sigint
cleanup_sigint() {
    echo -e "$(get_time): Caught SIGINT" >> $log_file
    kill $(jobs -p) 2>/dev/null
    exit 1
}

# Function to get the time for logs
get_time() {
    echo $(date +'%m-%d-%Y %I:%M:%S %p %Z')
}

# Main script execution

echo " _   _    ___     _____ "
echo "| \ | |  / \ \   / /_ _|"
echo "|  \| | / _ \ \ / / | | "
echo "| |\  |/ ___ \ V /  | | "
echo "|_| \_/_/   \_\_/  |___|"
echo "                        "
echo -e "Network Assessment and Vulnerability Insights\n"

trap 'cleanup' EXIT
trap 'cleanup_sigint' SIGINT

if [ "$#" -eq 0 ]; then
	echo "Useage: script.sh -i targets_file [-e exclude_file]"
	exit 1
fi 

while getopts ":i:e:" opt; do
    case ${opt} in
        i )
            targets_file=$OPTARG
            ;;
        e )
            exclude_file=$OPTARG
            ;;
        \? )
            echo "Usage: script.sh -i targets_file [-e exclude_file]"
            exit 1
            ;;
    esac
done

## Global Variables - code needs refactoring to bring more paths here.
start_time=$(date +%m-%d-%Y_%H%M)
log_file=logs/${start_time}.log
scanDirectory=scans
webDirectory=web
nmapDirectory="$scanDirectory/nmap"
masscanDirectory="$scanDirectory/masscan"
gowitnessDirectory="$webDirectory/gowitness"
gowitnessDatabase="$gowitnessDirectory/gowitness.sqlite3"
gowitnessScreenshotsDirectory="$gowitnessDirectory/screenshots"

check_tools
create_folder_structure
run_target_gen "$targets_file" "$exclude_file"
run_discovery_scan
run_full_tcp_scan
run_top_100_udp_scan
parse_scans
run_gowitness
format_gowitness_results
