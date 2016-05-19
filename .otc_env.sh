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

test -e ~/novarc && source ~/novarc
test -e ~/.novarc && source ~/.novarc
test -e ~/.ostackrc && source ~/.ostackrc

# === Parameters
#
# HAVE TO CHANGE! ######

# If you have not set the parameters via the openStack RC files, you can do it here
## You don't need any of the below if you have your environment set up using
# the standard OpenStack environment variables in novarc or .ostackrc.
# Just defaults, IF you want.

#export OS_PROJECT_NAME=eu-de
#export OS_USERNAME="NUMBER OTC000....."
#export OS_CACERT=/path/to/cacrt.pem
#export PASSWORD="your generated API key"
#export S3_ACCESS_KEY_ID=S3 KEY
#export S3_SECRET_ACCESS_KEY=S3 SECRET

# These variables are in openstack environment format ...
#export OS_USERNAME="$OS_USERNAME"
#export OS_PASSWORD="$OS_PASSWORD"
# Those two don't change for OTC in Europe region ...
export OS_USER_DOMAIN_NAME="${OS_USERNAME##* }"
export OS_PROJECT_NAME="eu-de"

#export S3_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXXXXX
#export S3_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# export S3_HOSTNAME=obs.otc.t-systems.com

# Optionally use a proxy for s3 and curl
#export HTTPS_PROXY=
#export OS_CACERT=/etc/ssl/OTC-API-GW-CA-Bundle.pem

# HAVE TO CHANGE END ######

# Defaults ( override from command line )

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

# Password to inject (only works with some images) or SSH keypair name
#export ADMINPASS="start"`date +%m%d`"!"
#export KEYNAME=""
# Only if you want non-default root disk size (in GB)
#export ROOTDISKSIZE=8

export CREATE_ECS_WITH_PUBLIC_IP="false"

export ECSACTIONTYPE="HARD"
export WAIT_CREATE="true"
#export BANDWIDTH=25
##########################################################################################

