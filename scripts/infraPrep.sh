#!/bin/bash
echo $(date) " - Starting Node Prep Script"

export USERNAME_ORG=$1
export PASSWORD_ACT_KEY="$2"
export POOL_ID=$3

# Remove RHUI

rm -f /etc/yum.repos.d/rh-cloud.repo
sleep 10

# Register Host with Cloud Access Subscription
echo $(date) " - Register host with Cloud Access Subscription"

subscription-manager register --force --username="$USERNAME_ORG" --password="$PASSWORD_ACT_KEY" || subscription-manager register --force --activationkey="$PASSWORD_ACT_KEY" --org="$USERNAME_ORG"
RETCODE=$?

if [ $RETCODE -eq 0 ]
then
    echo "Subscribed successfully"
elif [ $RETCODE -eq 64 ]
then
    echo "This system is already registered."
else
    sleep 5
	subscription-manager register --force --username="$USERNAME_ORG" --password="$PASSWORD_ACT_KEY" || subscription-manager register --force --activationkey="$PASSWORD_ACT_KEY" --org="$USERNAME_ORG"
	RETCODE2=$?
	if [ $RETCODE2 -eq 0 ]
	then
		echo "Subscribed successfully"
	elif [ $RETCODE2 -eq 64 ]
	then
		echo "This system is already registered."
	else
		echo "Incorrect Username / Password or Organization ID / Activation Key specified. Unregistering system from RHSM"
		subscription-manager unregister
		exit 3
	fi
fi

subscription-manager attach --pool=$POOL_ID > attach.log
if [ $? -eq 0 ]
then
    echo "Pool attached successfully"
else
    grep attached attach.log
    if [ $? -eq 0 ]
    then
        echo "Pool $POOL_ID was already attached and was not attached again."
    else
        echo "Incorrect Pool ID or no entitlements available"
        exit 4
    fi
fi

# Disable all repositories and enable only the required ones
echo $(date) " - Disabling all repositories and enabling only the required repos"

subscription-manager repos --disable="*"

subscription-manager repos \
    --enable="rhel-7-server-rpms" \
    --enable="rhel-7-server-extras-rpms" \
    --enable="rhel-7-server-ose-3.11-rpms" \
    --enable="rhel-7-server-ansible-2.6-rpms" \
    --enable="rhel-7-fast-datapath-rpms" \
    --enable="rh-gluster-3-client-for-rhel-7-server-rpms"

# Install base packages and update system to latest packages
echo $(date) " - Install base packages and update system to latest packages"

yum -y install wget git net-tools bind-utils iptables-services bridge-utils bash-completion kexec-tools sos psacct
yum -y install cloud-utils-growpart.noarch
yum -y install ansible
yum -y update glusterfs-fuse
yum -y update --exclude=WALinuxAgent
echo $(date) " - Base package insallation and updates complete"

# Grow Root File System

echo $(date) " - Grow Root FS"

rootdev=`findmnt --target / -o SOURCE -n`
rootdrivename=`lsblk -no pkname $rootdev`
rootdrive="/dev/"$rootdrivename
name=`lsblk  $rootdev -o NAME | tail -1`
part_number=${name#*${rootdrivename}}

growpart $rootdrive $part_number -u on
xfs_growfs $rootdev

if [ $? -eq 0 ]
then
    echo "Root partition expanded"
else
    echo "Root partition failed to expand"
    exit 6
fi

# Install Docker
echo $(date) " - Installing Docker"
yum -y install docker

# Update docker config for insecure registry
echo "
# Adding insecure-registry option required by OpenShift
OPTIONS=\"\$OPTIONS --insecure-registry 172.30.0.0/16\"
" >> /etc/sysconfig/docker

# Create thin pool logical volume for Docker

echo $(date) " - Creating thin pool logical volume for Docker and starting service"

DOCKERVG=$( parted -m /dev/sdc print all 2>/dev/null | grep /dev/sd | cut -d':' -f1 | head -n1 )

echo "
# Adding OpenShift data disk for docker
STORAGE_DRIVER=overlay2
CONTAINER_ROOT_LV_NAME=dockerlv
CONTAINER_ROOT_LV_SIZE=100%FREE
CONTAINER_ROOT_LV_MOUNT_PATH=/var/lib/docker
DEVS=${DOCKERVG}
VG=docker-vg
EXTRA_STORAGE_OPTIONS='--storage-opt overlay2.size=3G'
" >> /etc/sysconfig/docker-storage-setup

# Running setup for docker storage

docker-storage-setup
if [ $? -eq 0 ]
then
    echo "Docker thin pool logical volume created successfully"
else
    echo "Error creating logical volume for Docker"
    exit 5
fi

# Enable and start Docker services

systemctl enable docker
systemctl start docker

echo $(date) " - Script Complete"

