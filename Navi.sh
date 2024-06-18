#!/bin/bash

# Function to create folder structure
create_folder_structure() {
    echo "Checking folder structure..."
    local folder_structure=("scans/nmap/" "scans/masscan" "scans/parsed/port-lists" "scans/parsed/port-files" "web/gowitness" "targets" "logs")
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
    echo $(date +%m-%d-%Y %H:%M.%S %p %Z)
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

## Stage Logging
start_time=$(date +%m-%d-%Y_%H%M)
log_file=logs/${start_time}.log

create_folder_structure
run_target_gen "$targets_file" "$exclude_file"
run_discovery_scan
run_full_tcp_scan
run_top_100_udp_scan
parse_scans
