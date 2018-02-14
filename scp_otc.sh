#!/bin/bash
# Little helper to scp into VMs
#
# (c) Kurt Garloff <t-systems@garloff.de>, 1/2018, CC-BY-SA 3.0

usage()
{
	echo "Usage: scp_otc.sh [options] SRC DST"
	echo "Remote SRC or DST may be specified by UUID"
	echo "IF the parser sees something that looks like a UUID, the IP address"
	echo " will be substituted and -i ~/.ssh/KEYNAME.pem and username will be inserted"
	exit 2
}

if test -z "$1"; then usage; fi

OTC_TENANT=${OTC_TENANT:-210}
SSHKEY=~/SSHkey-$OTC_TENANT.pem

NORM="\e[0;0m"
YELLOW="\e[0;33m"
RED="\e[0;31m"

is_uuid() { echo "$1" | grep '^[0-9a-f]\{8\}\-[0-9a-f]\{4\}\-[0-9a-f]\{4\}\-[0-9a-f]\{4\}\-[0-9a-f]\{12\}$' >/dev/null 2>&1; }
is_ip() { echo "$1" | grep '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' >/dev/null 2>&1; }
getVPC()
{
	# By convention, VMs are normally tagged with the VPC in OTC
	firsttag=$(echo "$VMINFO" | jq '.tags[0]' | tr -d '"')
	# If not, then look for router ports
	if is_uuid $firsttag; then echo $firsttag; return 0; fi
	NET=$(echo "$VMINFO" | jq  '.interfaceAttachments[].net_id' | tr -d '"')
	VPC=$(otc.sh custom GET "\$NEUTRON_URL/v2.0/ports.json?device_owner=network\:router_interface_distributed\&network_id=$NET" | jq '.ports[].device_id' | tr -d '"')
	if is_uuid $VPC; then echo $VPC; return 0; fi
	return 1
}

getvm()
{
	VM=$1
	if ! is_uuid $VM; then
		#echo "Looking up VM \"$VM\" ... " 1>&2
		VM=$(otc.sh vm list name=$VM | head -n1 | awk '{ print $1; }')
		if ! is_uuid $VM; then echo "No such VM \"$1\"" 1>&2 ; exit 2; fi
	fi

	VMINFO=$(otc.sh vm show $VM) || { echo "No such VM \"$VM\"" 1>&2; exit 2; }
	IP=$(echo "$VMINFO" | jq '.interfaceAttachments[].fixed_ips[].ip_address' | tr -d '"' | head -n1)
	NAME=$(echo "$VMINFO" | jq '.server.name' | tr -d '"')
	FLAVOR=$(echo "$VMINFO" | jq '.server.flavor.id' | tr -d '"')
	IMGID=$(echo "$VMINFO" | jq '.server.image.id' | tr -d '"')
	KEYNAME=$(echo "$VMINFO" | jq '.server.key_name' | tr -d '"')

	IMGINFO=$(otc.sh image show $IMGID 2>/dev/null)
	if test $? != 0 -o -z "$IMGINFO"; then 
		if test -z "$OSVER"; then OSVER=UNKNOWN; fi
		IMGNAME="?"
	else 
		IMGNAME=$(echo "$IMGINFO" | jq '.name' | tr -d '"')
		OSVER=$(echo "$IMGINFO" | jq '.__os_version' | tr -d '"')
	fi
	if [[ "$OSVER" = "Ubuntu"* ]] && [ "$USER" == "linux" ]; then USER=ubuntu; fi
	echo -e "${YELLOW}#VM Info: $VM $NAME $FLAVOR $IMGNAME $OSVER${NORM}" 1>%2

	# Check VPC and use EIP if present and needed
	MYVPC=$(otc.sh mds meta_data 2>/dev/null | jq .meta.vpc_id | tr -d '"')
	if test -z "$MYVPC" -o "$MYVPC" == "null" || test "$(getVPC)" != "$MYVPC"; then
		PORT=$(echo "$VMINFO" | jq .interfaceAttachments[].port_id | head -n1 | tr -d '"')
		EIP=$(otc.sh eip list | grep " $IP " | awk '{ print $2; }')
		if test -n "$EIP"; then
			echo "#Using EIP $EIP instead of IP $IP" 1>&2
			IP=$EIP
		fi
	fi
}

getSSHkey()
{
	if test -n "$SSH_AUTH_SOCK"; then
		KEYS=$(ssh-add -l)
		if echo "$KEYS" | grep "$KEYNAME" >/dev/null 2>&1; then return; fi
	fi
	
	SSHKEY=~/.ssh/"$KEYNAME.pem"
	test -r $SSHKEY || SSHKEY=~/"$KEYNAME.pem"
	if ! test -r $SSHKEY; then 
		echo -e "#${RED}Need ~/.ssh/$KEYNAME.pem${NORM}" 1>&2
		unset SSHKEY
	else 
		SSHKEY="-i $SSHKEY"
	fi
}

unset VM
declare -a ARGS=("$@")

for no in $(seq 0 ${#ARGS[@]}); do
	opt="${ARGS[$no]}"
	if [[ "$opt" == "-i"* ]]; then ISET=1; continue; fi
	if [[ "$opt" == *:* ]]; then
		USER="${opt%%@*}"
		if [ "$USER" == "$opt" ]; then USER=linux; fi
		opt="${opt#*@}"
		ARGS[$no]="${USER}@$opt"
		VM=${opt#*@}; VM=${VM%:*}
		if is_ip $VM; then continue; fi
		if getent hosts $VM >/dev/null 2>&1; then continue; fi
		getvm $VM
		ARGS[$no]="${USER}@$IP:${opt##*:}"
		continue
	fi
done		

if test "$ISET" != 1; then getSSHkey; fi

echo "scp ${SSHKEY}${ARGS[@]}"
	
exec scp $SSHKEY "${ARGS[@]}"
