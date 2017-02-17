# == Module: Open Telekom Cloud Cli Interface Configuration 0.6.x
#
# Store OTC Command Line Configuration
#
# Zsolt Nagy <Z.Nagy@t-systems.com>
#
# === Copyright
#
# Copyright 2016 T-Systems International GmbH
#
# USER SPECIFIC SETTINGS #################################################################

# NEEDED FOR TOKEN AUTH
# If you are using the otc tool along with native openstack client tools
# just put the normal OS_ variables in novarc or .ostackrc and you're good to go
# The recommendation is thus NOT to use .otc_env.sh at all!

OLD_OS_PASSWORD="$OS_PASSWORD"

# === Parameters
#
# Note: You CAN set the OpenStack and S3 environment variable here.
# However, it is reocmmended to NOT do this here, but rather leave it
# for the otc script to read and parse the normal OpenStack environment
# settings files ~/.ostackrc or ~/.novarc or ~/novarc.

# These variables are in openstack environment format ...
#export OS_USERNAME="NUMBER OTC000....."
#export OS_PASSWORD="your generated API key"
#export OS_PROJECT_NAME=eu-de
#export OS_USER_DOMAIN_NAME="${OS_USERNAME##* }"

#export S3_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXXXXX
#export S3_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#export S3_HOSTNAME=obs.otc.t-systems.com

# Optionally use a proxy for s3 and curl
#export HTTPS_PROXY=
# And in case you don't have the root CA certs on your system
#export OS_CACERT=/etc/ssl/OTC-API-GW-CA-Bundle.pem

# ===

# And display warning for common scenario
if test -n "$OLD_OS_PASSWORD" -a "$OLD_OS_PASSWORD" != "$OS_PASSWORD"; then
	echo "Note: OS_ environment overriden by ~/.otc_env.sh"
fi
# === Defaults ( override from command line )

# Default VOLUMETYPE: SATA, SAS or SSD
export VOLUMETYPE="SATA"
# Leave AZ empty to derive from subnet's AZ (recommended)
#export AZ="eu-de-01"

# Set defaults if you always use the same settings ...
export SECUGROUPNAME="default"
export VPCNAME="vpc-0"
export SUBNETNAME="subnet-1"
export IMAGENAME="Standard_openSUSE_42.1_JeOS_latest"
#export NUMCOUNT=1
export INSTANCE_TYPE="computev1-1"
export INSTANCE_NAME="otcVM-$$"

# Password to inject or (better) SSH keypair name for user linux
#export ADMINPASS="start"`date +%m%d`"!"
#export KEYNAME="SSHkey-XYZ"
# Only if you want non-default root disk size (in GB), ensure it's larger 
# than the minimum required by the  image you are using
#export ROOTDISKSIZE=8

# Don't allocate and assign a public IP by default
export CREATE_ECS_WITH_PUBLIC_IP="false"
# Adjust bandwidth of created public IP
#export BANDWIDTH=25

# Hard reboot/delete ...
export ECSACTIONTYPE="HARD"
# Wait for long actions (such as ECS creation) to complete
export WAIT_CREATE="true"
##########################################################################################

