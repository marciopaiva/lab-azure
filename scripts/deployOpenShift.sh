#!/bin/bash

echo $(date) " - Starting Script"

set -e

export SUDOUSER=$1
export PASSWORD="$2"
export MASTER=$3
export MASTERPUBLICIPHOSTNAME=$4
export MASTERPUBLICIPADDRESS=$5
export INFRA=$6
export NODE=$7
export NODECOUNT=$8
export INFRACOUNT=$9
export MASTERCOUNT=${10}
export ROUTING=${11}
export REGISTRYSA=${12}
export ACCOUNTKEY="${13}"
export METRICS=${14}
export LOGGING=${15}
export TENANTID=${16}
export SUBSCRIPTIONID=${17}
export AADCLIENTID=${18}
export AADCLIENTSECRET="${19}"
export RESOURCEGROUP=${20}
export LOCATION=${21}
export AZURE=${22}
export STORAGEKIND=${23}
export ENABLECNS=${24}
export CNS=${25}
export CNSCOUNT=${26}
export VNETNAME=${27}
export NODENSG=${28}
export NODEAVAILIBILITYSET=${29}
export MASTERCLUSTERTYPE=${30}
export PRIVATEIP=${31}
export PRIVATEDNS=${32}
export MASTERPIPNAME=${33}
export ROUTERCLUSTERTYPE=${34}
export INFRAPIPNAME=${35}
export CUSTOMROUTINGCERTTYPE=${36}
export CUSTOMMASTERCERTTYPE=${37}
export MINORVERSION=${38}
export BASTION=$(hostname)

# Set CNS to default storage type.  Will be overridden later if Azure is true
export CNS_DEFAULT_STORAGE=true

# Setting DOMAIN variable
export DOMAIN=`domainname -d`

# Determine if Commercial Azure or Azure Government
CLOUD=$( curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-04-02&format=text" | cut -c 1-2 )
export CLOUD=${CLOUD^^}

export MASTERLOOP=$((MASTERCOUNT - 1))
export INFRALOOP=$((INFRACOUNT - 1))
export NODELOOP=$((NODECOUNT - 1))

echo $(date) " - Configuring SSH ControlPath to use shorter path name"

sed -i -e "s/^# control_path = %(directory)s\/%%h-%%r/control_path = %(directory)s\/%%h-%%r/" /etc/ansible/ansible.cfg
sed -i -e "s/^#host_key_checking = False/host_key_checking = False/" /etc/ansible/ansible.cfg
sed -i -e "s/^#pty=False/pty=False/" /etc/ansible/ansible.cfg
sed -i -e "s/^#stdout_callback = skippy/stdout_callback = skippy/" /etc/ansible/ansible.cfg
sed -i -e "s/^#pipelining = False/pipelining = True/" /etc/ansible/ansible.cfg

# echo $(date) " - Modifying sudoers"
sed -i -e "s/Defaults    requiretty/# Defaults    requiretty/" /etc/sudoers
sed -i -e '/Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"/aDefaults    env_keep += "PATH"' /etc/sudoers

# Create docker registry config based on Commercial Azure or Azure Government
if [[ $CLOUD == "US" ]]
then
    export DOCKERREGISTRYREALM=core.usgovcloudapi.net
	export CLOUDNAME="AzureUSGovernmentCloud"
else
	export DOCKERREGISTRYREALM=core.windows.net
	export CLOUDNAME="AzurePublicCloud"
fi

# Setting the default openshift_cloudprovider_kind if Azure enabled
if [[ $AZURE == "true" ]]
then
    CLOUDKIND="openshift_cloudprovider_kind=azure
openshift_cloudprovider_azure_client_id=$AADCLIENTID
openshift_cloudprovider_azure_client_secret=$AADCLIENTSECRET
openshift_cloudprovider_azure_tenant_id=$TENANTID
openshift_cloudprovider_azure_subscription_id=$SUBSCRIPTIONID
openshift_cloudprovider_azure_cloud=$CLOUDNAME
openshift_cloudprovider_azure_vnet_name=$VNETNAME
openshift_cloudprovider_azure_security_group_name=$NODENSG
openshift_cloudprovider_azure_availability_set_name=$NODEAVAILIBILITYSET
openshift_cloudprovider_azure_resource_group=$RESOURCEGROUP
openshift_cloudprovider_azure_location=$LOCATION"
	CNS_DEFAULT_STORAGE=false
	if [[ $STORAGEKIND == "managed" ]]
	then
		SCKIND="openshift_storageclass_parameters={'kind': 'managed', 'storageaccounttype': 'Premium_LRS'}"
	else
		SCKIND="openshift_storageclass_parameters={'kind': 'shared', 'storageaccounttype': 'Premium_LRS'}"
	fi
fi

# Cloning Ansible playbook repository

echo $(date) " - Cloning Ansible playbook repository"

((cd /home/$SUDOUSER && git clone https://github.com/Microsoft/openshift-container-platform-playbooks.git) || (cd /home/$SUDOUSER/openshift-container-platform-playbooks && git pull))

if [ -d /home/${SUDOUSER}/openshift-container-platform-playbooks ]
then
    echo " - Retrieved playbooks successfully"
else
    echo " - Retrieval of playbooks failed"
    exit 7
fi

# Configure custom routing certificate
echo $(date) " - Create variable for routing certificate based on certificate type"
if [[ $CUSTOMROUTINGCERTTYPE == "custom" ]]
then
	ROUTINGCERTIFICATE="openshift_hosted_router_certificate={\"cafile\": \"/tmp/routingca.pem\", \"certfile\": \"/tmp/routingcert.pem\", \"keyfile\": \"/tmp/routingkey.pem\"}"
else
	ROUTINGCERTIFICATE=""
fi

# Configure custom master API certificate
echo $(date) " - Create variable for master api certificate based on certificate type"
if [[ $CUSTOMMASTERCERTTYPE == "custom" ]]
then
	MASTERCERTIFICATE="openshift_master_overwrite_named_certificates=true
openshift_master_named_certificates=[{\"names\": [\"$MASTERPUBLICIPHOSTNAME\"], \"cafile\": \"/tmp/masterca.pem\", \"certfile\": \"/tmp/mastercert.pem\", \"keyfile\": \"/tmp/masterkey.pem\"}]"
else
	MASTERCERTIFICATE=""
fi

# Configure master cluster address information based on Cluster type (private or public)
echo $(date) " - Create variable for master cluster address based on cluster type"
if [[ $MASTERCLUSTERTYPE == "private" ]]
then
	MASTERCLUSTERADDRESS="openshift_master_cluster_hostname=$MASTER01
openshift_master_cluster_public_hostname=$PRIVATEDNS
openshift_master_cluster_public_vip=$PRIVATEIP"
else
	MASTERCLUSTERADDRESS="openshift_master_cluster_hostname=$MASTERPUBLICIPHOSTNAME
openshift_master_cluster_public_hostname=$MASTERPUBLICIPHOSTNAME
openshift_master_cluster_public_vip=$MASTERPUBLICIPADDRESS"
fi

# Create Master nodes grouping
echo $(date) " - Creating Master nodes grouping"
MASTERLIST="0$MASTERCOUNT"
for (( c=1; c<=$MASTERCOUNT; c++ ))
do
    mastergroup="$mastergroup
${MASTER}0$c openshift_node_group_name='node-config-master' openshift_node_problem_detector_install=true"
done

# Create Infra nodes grouping 
echo $(date) " - Creating Infra nodes grouping"
if [ $INFRACOUNT -gt 9 ]
then
    for (( c=1; c<=9; c++ ))
	do
		infragroup="$infragroup
${INFRA}0$c openshift_node_group_name='node-config-infra' openshift_node_problem_detector_install=true"
	done

	for (( c=10; c<=$INFRACOUNT; c++ ))
    do
		infragroup="$infragroup
${INFRA}$c openshift_node_group_name='node-config-infra' openshift_node_problem_detector_install=true"
	done
else
	for (( c=1; c<=$INFRACOUNT; c++ ))
	do
		infragroup="$infragroup
${INFRA}0$c openshift_node_group_name='node-config-infra' openshift_node_problem_detector_install=true"
	done
fi

# Create Nodes grouping
echo $(date) " - Creating Nodes grouping"
if [ $NODECOUNT -gt 9 ]
then
	# If more than 10 compute nodes need to create groups 01 - 09 separately than 10 and higher
	for (( c=1; c<=9; c++ ))
	do
		nodegroup="$nodegroup
${NODE}0$c openshift_node_group_name='node-config-compute' openshift_node_problem_detector_install=true"
	done

	for (( c=10; c<=$NODECOUNT; c++ ))
	do
		nodegroup="$nodegroup
${NODE}$c openshift_node_group_name='node-config-compute' openshift_node_problem_detector_install=true"
	done
else
	# If less than 10 compout nodes
	for (( c=1; c<=$NODECOUNT; c++ ))
	do
		nodegroup="$nodegroup
${NODE}0$c openshift_node_group_name='node-config-compute' openshift_node_problem_detector_install=true"
	done
fi

# Create CNS nodes grouping if CNS is enabled
if [[ $ENABLECNS == "true" ]]
then
    echo $(date) " - Creating CNS nodes grouping"

    for (( c=1; c<=$CNSCOUNT; c++ ))
    do
        cnsgroup="$cnsgroup
${CNS}0$c openshift_node_group_name='node-config-compute' openshift_node_problem_detector_install=true"
    done
fi

# Setting the HA Mode if more than one master
if [ $MASTERCOUNT != 1 ]
then
	echo $(date) " - Enabling HA mode for masters"
    export HAMODE="openshift_master_cluster_method=native"
fi

# Create Temp Ansible Hosts File
echo $(date) " - Create Ansible Hosts file"

cat > /etc/ansible/hosts <<EOF
[tempnodes]
$mastergroup
$infragroup
$nodegroup
$cnsgroup
EOF

# Run a loop playbook to ensure DNS Hostname resolution is working prior to continuing with script
echo $(date) " - Running DNS Hostname resolution check"
runuser -l $SUDOUSER -c "ansible-playbook ~/openshift-container-platform-playbooks/check-dns-host-name-resolution.yaml"

# Create glusterfs configuration if CNS is enabled
if [[ $ENABLECNS == "true" ]]
then
    echo $(date) " - Creating glusterfs configuration"

	# Ensuring selinux is configured properly
    echo $(date) " - Setting selinux to allow gluster-fuse access"
    runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -a 'sudo setsebool -P virt_sandbox_use_fusefs on'" || true
	runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -a 'sudo setsebool -P virt_use_fusefs on'" || true

    for (( c=1; c<=$CNSCOUNT; c++ ))
    do
        runuser $SUDOUSER -c "ssh-keyscan -H ${CNS}0$c >> ~/.ssh/known_hosts"
        drive=$(runuser $SUDOUSER -c "ssh ${CNS}0$c 'sudo /usr/sbin/fdisk -l'" | awk '$1 == "Disk" && $2 ~ /^\// && ! /mapper/ {if (drive) print drive; drive = $2; sub(":", "", drive);} drive && /^\// {drive = ""} END {if (drive) print drive;}')
        drive1=$(echo $drive | cut -d ' ' -f 1)
        drive2=$(echo $drive | cut -d ' ' -f 2)
        drive3=$(echo $drive | cut -d ' ' -f 3)
        cnsglusterinfo="$cnsglusterinfo
${CNS}0$c glusterfs_devices='[ \"${drive1}\", \"${drive2}\", \"${drive3}\" ]'"
    done
fi

# Create Ansible Hosts File
echo $(date) " - Create Ansible Hosts file"

cat > /etc/ansible/hosts <<EOF
###############################################################################
#                         OPENSHIFT 3.11 - ALL-IN-ON                          #
###############################################################################
# host group for masters
[masters]
${MASTER}[01:${MASTERLIST}]

# host group for etcd
[etcd]
${MASTER}[01:${MASTERLIST}]

[master0]
${MASTER}01

# Only populated when CNS is enabled
[glusterfs]
$cnsglusterinfo

# host group for nodes
[nodes]
$mastergroup 
$infragroup
$nodegroup
$cnsgroup

# host group for adding new nodes
[new_nodes]

##############################################################################
# OSEv3 group that contains the masters and nodes groups                     #
##############################################################################
[OSEv3:children]
masters
nodes
etcd
master0
glusterfs
new_nodes

##############################################################################
# Common / Required configuration variables                                  #
##############################################################################
[OSEv3:vars]
ansible_ssh_user=$SUDOUSER
ansible_become=yes

openshift_release=v3.11
openshift_image_tag=v3.11.${MINORVERSION}
openshift_pkg_version=-3.11.${MINORVERSION}
debug_level=2

openshift_deployment_type=openshift-enterprise
openshift_disable_check=memory_availability,docker_image_availability,disk_availability

# NOTE: Specify default wildcard domain for apps
openshift_master_default_subdomain=$ROUTING

# NOTE: If using different internal & external FQDN (ie. using LB)
# set external cluster FQDN here
# Addresses for connecting to the OpenShift master nodes
$MASTERCLUSTERADDRESS
# Type of clustering being used by OCP
$HAMODE
openshift_master_api_port=443
openshift_master_console_port=443

openshift_master_dynamic_provisioning_enabled=true

$MASTERCERTIFICATE

openshift_clock_enabled=true
openshift_use_dnsmasq=true
openshift_install_examples=true
openshift_override_hostname_check=true
dynamic_volumes_check=false

# Network 
os_sdn_network_plugin_name='redhat/openshift-ovs-multitenant'

# Audit log
openshift_master_audit_config={"enabled": true, "auditFilePath": "/var/lib/origin/audit-ocp.log", "maximumFileRetentionDays": 7, "maximumFileSizeMegabytes": 10, "maximumRetainedFiles": 3}

##############################################################################
# Additional configuration variables follow                                  #
##############################################################################

##############################################################################
#
# Azure Config
#
$CLOUDKIND
$SCKIND

##############################################################################
#
# Service Catalog
#
openshift_enable_service_catalog=false

##############################################################################
#
# Service Broker
#
ansible_service_broker_install=false
template_service_broker_install=false
template_service_broker_selector={"type":"infra-apps"}

##############################################################################
#
# Docker
#
docker_version="1.13.1"
docker_udev_workaround=true
openshift_docker_options='--log-driver=json-file --signature-verification=False --selinux-enabled --log-opt max-size=1M --log-opt max-file=3 -l warn --ipv6=false --insecure-registry 172.30.0.0/16'

##############################################################################
#
# Auth Provider
#
openshift_master_identity_providers=[{'name': 'htpasswd_auth', 'login': 'true', 'challenge': 'true', 'kind': 'HTPasswdPasswordIdentityProvider'}]

# For embeddng the initial users in the configuration file use this syntax
# Note: user==password for this example
openshift_master_htpasswd_users={'ocpadmin':'$apr1$ZuJlQr.Y$6abuePAhKG0iY8QDNWoq80','developer':'$apr1$QE2hKzLx$4ZeptR1hHNP538zRh/Pew.'}

##############################################################################
#
# Enable Cockpit
#
osm_use_cockpit=true
osm_cockpit_plugins=['cockpit-kubernetes']
osm_default_node_selector='node-role.kubernetes.io/compute=true'

##############################################################################
#
# OpenShift Labels
#

openshift_node_groups=[{'name': 'node-config-master',  'labels': ['node-role.kubernetes.io/master=true' ],'edits': [{ 'key': 'kubeletArguments.kube-reserved','value': ['cpu=100m,memory=128M']}, { 'key': 'kubeletArguments.system-reserved','value': ['cpu=100m,memory=256M']}, { 'key': 'kubeletArguments.pods-per-core','value': ['10']},{ 'key': 'kubeletArguments.max-pods','value': ['160']}, { 'key': 'kubeletArguments.maximum-dead-containers','value': ['5']}, { 'key': 'kubeletArguments.maximum-dead-containers-per-container','value': ['1']}, { 'key': 'kubeletArguments.image-gc-high-threshold','value': ['80']}, { 'key': 'kubeletArguments.image-gc-low-threshold','value': ['60']}]}, {'name': 'node-config-infra',   'labels': ['node-role.kubernetes.io/infra=true','type=infra-router'], 'edits':[{ 'key': 'kubeletArguments.kube-reserved','value': ['cpu=100m,memory=128M']}, { 'key': 'kubeletArguments.system-reserved','value': ['cpu=100m,memory=256M']}, { 'key': 'kubeletArguments.pods-per-core','value': ['10']}, { 'key': 'kubeletArguments.max-pods','value': ['160']}, { 'key': 'kubeletArguments.maximum-dead-containers','value': ['5']}, { 'key': 'kubeletArguments.maximum-dead-containers-per-container','value': ['1']}, { 'key': 'kubeletArguments.image-gc-high-threshold','value': ['80']}, { 'key': 'kubeletArguments.image-gc-low-threshold','value': ['60']}]}, {'name': 'node-config-compute', 'labels': ['node-role.kubernetes.io/compute=true'], 'edits':[{ 'key': 'kubeletArguments.kube-reserved','value': ['cpu=100m,memory=128M']}, { 'key': 'kubeletArguments.system-reserved','value': ['cpu=100m,memory=256M']}, { 'key': 'kubeletArguments.pods-per-core','value': ['10']}, { 'key': 'kubeletArguments.max-pods','value': ['160']}, { 'key': 'kubeletArguments.maximum-dead-containers','value': ['5']}, { 'key': 'kubeletArguments.maximum-dead-containers-per-container','value': ['1']}, { 'key': 'kubeletArguments.image-gc-high-threshold','value': ['80']}, { 'key': 'kubeletArguments.image-gc-low-threshold','value': ['60']}]}, {'name': 'node-config-all-in-one',  'labels': ['node-role.kubernetes.io/infra=true', 'node-role.kubernetes.io/master=true' ,'node-role.kubernetes.io/compute=true' ]}]

##############################################################################
#
# Red Hat Registry
#
# Workaround for docker image failure
# https://access.redhat.com/solutions/3480921
oreg_url=registry.access.redhat.com/openshift3/ose-\${component}:\${version}
openshift_examples_modify_imagestreams=true

##############################################################################
#
# Container images
#
openshift_storage_glusterfs_image=registry.access.redhat.com/rhgs3/rhgs-server-rhel7:v3.11
openshift_storage_glusterfs_block_image=registry.access.redhat.com/rhgs3/rhgs-gluster-block-prov-rhel7:v3.11
openshift_storage_glusterfs_s3_image=registry.access.redhat.com/rhgs3/rhgs-s3-server-rhel7:v3.11
openshift_storage_glusterfs_heketi_image=registry.access.redhat.com/rhgs3/rhgs-volmanager-rhel7:v3.11

##############################################################################
#
# OpenShift Router Options
#

openshift_hosted_router_extended_validation=true
$ROUTINGCERTIFICATE

##############################################################################
#
# Openshift Registry Options
#

openshift_hosted_registry_routehost="registry.{{ openshift_master_default_subdomain }}"
openshift_hosted_registry_selector="node-role.kubernetes.io/infra=true"

openshift_hosted_registry_replicas=1
openshift_hosted_registry_pullthrough=true
openshift_hosted_registry_acceptschema2=true
openshift_hosted_registry_enforcequota=true

openshift_hosted_registry_storage_kind=object
openshift_hosted_registry_storage_provider=azure_blob
openshift_hosted_registry_storage_azure_blob_accountname=$REGISTRYSA
openshift_hosted_registry_storage_azure_blob_accountkey=$ACCOUNTKEY
openshift_hosted_registry_storage_azure_blob_container=registry
openshift_hosted_registry_storage_azure_blob_realm=$DOCKERREGISTRYREALM
openshift_hosted_registry_storage_volume_size=100Gi

##############################################################################
#
# Cluster Prometheus Monitoring
#

openshift_cluster_monitoring_operator_install=true
openshift_cluster_monitoring_operator_node_selector={"kubernetes.io/hostname":"ocpmec-infra01"}

openshift_cluster_monitoring_operator_prometheus_storage_enabled=true
openshift_cluster_monitoring_operator_alertmanager_storage_enabled=true
openshift_cluster_monitoring_operator_prometheus_storage_capacity=300Gi
openshift_cluster_monitoring_operator_alertmanager_storage_capacity=50Gi

# Suggested Quotas and limits for Prometheus components
openshift_prometheus_memory_requests=2Gi
openshift_prometheus_cpu_requests=750m
openshift_prometheus_memory_limit=2Gi
openshift_prometheus_cpu_limit=750m
openshift_prometheus_alertmanager_memory_requests=300Mi
openshift_prometheus_alertmanager_cpu_requests=200m
openshift_prometheus_alertmanager_memory_limit=300Mi
openshift_prometheus_alertmanager_cpu_limit=200m
openshift_prometheus_alertbuffer_memory_requests=300Mi
openshift_prometheus_alertbuffer_cpu_requests=200m
openshift_prometheus_alertbuffer_memory_limit=300Mi
openshift_prometheus_alertbuffer_cpu_limit=200m

##############################################################################
#
# Metrics deployment
#

openshift_metrics_install_metrics=false

# Start metrics cluster after deploying the components
openshift_metrics_start_cluster=true

# Store Metrics for 1 days
openshift_metrics_duration=30

# cassandra 
openshift_metrics_cassandra_storage_type=dynamic
openshift_metrics_cassandra_pvc_size=300Gi
openshift_metrics_cassandra_limits_memory=2Gi
openshift_metrics_cassandra_limits_cpu=800m
openshift_metrics_cassandra_nodeselector={"kubernetes.io/hostname":"ocpmec-infra02"}

# hawkular
openshift_metrics_hawkular_limits_memory=2Gi
openshift_metrics_hawkular_limits_cpu=800m
openshift_metrics_hawkular_nodeselector={"kubernetes.io/hostname":"ocpmec-infra02"}

# heapster
openshift_metrics_heapster_limits_memory=2Gi
openshift_metrics_heapster_limits_cpu=800m
openshift_metrics_heapster_nodeselector={"kubernetes.io/hostname":"ocpmec-infra02"}

##############################################################################
#
# Logging deployment
#

openshift_logging_install_logging=false

openshift_logging_master_public_url=https://{{ openshift_master_cluster_public_hostname }}:{{ openshift_master_console_port }}

# logging curator
openshift_logging_curator_default_days=10
openshift_logging_curator_cpu_limit=500m
openshift_logging_curator_memory_limit=1Gi
openshift_logging_curator_nodeselector={"kubernetes.io/hostname":"ocpmec-infra03"}

# Configure a second ES+Kibana cluster for operations logs
# Fluend splits the logs accordingly
openshift_logging_use_ops=true

# Fluentd
openshift_logging_fluentd_cpu_limit=500m
openshift_logging_fluentd_memory_limit=1Gi
# collect audit.log to ES
openshift_logging_fluentd_audit_container_engine=true
openshift_logging_fluentd_nodeselector={"logging":"true"}

# eventrouter
openshift_logging_install_eventrouter=true
openshift_logging_eventrouter_nodeselector={"kubernetes.io/hostname":"ocpmec-infra03"}

# Elasticsearch (ES)
# ES cluster size (HA ES >= 3)
openshift_logging_es_cluster_size=1
# replicas per shard
#openshift_logging_es_number_of_replicas=1
# shards per index
#openshift_logging_es_number_of_shards=1
openshift_logging_es_cpu_limit=500m
openshift_logging_es_memory_limit=1Gi
# PVC size omitted == ephemeral vols are used
openshift_logging_es_pvc_size=300Gi
openshift_logging_es_pvc_dynamic=true
openshift_logging_es_nodeselector={"kubernetes.io/hostname":"ocpmec-infra03"}
openshift_logging_es_ops_nodeselector={"kubernetes.io/hostname":"ocpmec-infra03"}

# Kibana
openshift_logging_kibana_cpu_limit=500m
openshift_logging_kibana_memory_limit=1Gi
openshift_logging_kibana_replica_count=1
# expose ES? (default false)
#openshift_logging_es_allow_external=false
openshift_logging_kibana_nodeselector={"kubernetes.io/hostname":"ocpmec-infra03"}

#####################################################################################
$CUSTOMCSS
$PROXY

EOF

# Update WALinuxAgent
echo $(date) " - Updating WALinuxAgent on all cluster nodes"
runuser $SUDOUSER -c "ansible all -f 30 -b -m yum -a 'name=WALinuxAgent state=latest'"

# Setup NetworkManager to manage eth0
echo $(date) " - Running NetworkManager playbook"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-node/network_manager.yml"

# Configure DNS so it always has the domain name
echo $(date) " - Adding $DOMAIN to search for resolv.conf"
runuser $SUDOUSER -c "ansible all -o -f 30 -b -m lineinfile -a 'dest=/etc/sysconfig/network-scripts/ifcfg-eth0 line=\"DOMAIN=$DOMAIN\"'"

# Configure resolv.conf on all hosts through NetworkManager
echo $(date) " - Restarting NetworkManager"
runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -m service -a \"name=NetworkManager state=restarted\""
echo $(date) " - NetworkManager configuration complete"

# Restarting things so everything is clean before continuing with installation
echo $(date) " - Rebooting cluster to complete installation"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/reboot-master.yaml"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/reboot-nodes.yaml"
sleep 20

# Run OpenShift Container Platform prerequisites playbook
# echo $(date) " - Running Prerequisites via Ansible Playbook"
# runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/prerequisites.yml"
# echo $(date) " - Prerequisites check complete"

# Initiating installation of OpenShift Container Platform using Ansible Playbook
# echo $(date) " - Installing OpenShift Container Platform via Ansible Playbook"
# runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/deploy_cluster.yml"
# if [ $? -eq 0 ]
# then
# echo $(date) " - OpenShift Cluster installed successfully"
# else
#     echo $(date) " - OpenShift Cluster failed to install"
#     exit 6
# fi

# Install OpenShift Atomic Client
# cd /root
# mkdir .kube
# runuser ${SUDOUSER} -c "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${SUDOUSER}@${MASTER}01:~/.kube/config /tmp/kube-config"
# cp /tmp/kube-config /root/.kube/config
# mkdir /home/${SUDOUSER}/.kube
# cp /tmp/kube-config /home/${SUDOUSER}/.kube/config
# chown --recursive ${SUDOUSER} /home/${SUDOUSER}/.kube
# rm -f /tmp/kube-config
yum -y install atomic-openshift-clients

# Adding user to OpenShift authentication file
# echo $(date) " - Adding OpenShift user"
# runuser $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/addocpuser.yaml"

# Assigning cluster admin rights to OpenShift user
# echo $(date) " - Assigning cluster admin rights to user"
# runuser $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/assignclusteradminrights.yaml"

# Installing Service Catalog, Ansible Service Broker and Template Service Broker
# if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
# then
#     runuser -l $SUDOUSER -c "ansible-playbook -e openshift_enable_service_catalog=true -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-service-catalog/config.yml"
# fi

# Adding Open Sevice Broker for Azaure (requires service catalog)
# Disabling deployment of OSBA
# if [[ $AZURE == "true" ]]
# then
    # oc new-project osba
    # oc process -f https://raw.githubusercontent.com/Azure/open-service-broker-azure/master/contrib/openshift/osba-os-template.yaml  \
        # -p ENVIRONMENT=AzurePublicCloud \
        # -p AZURE_SUBSCRIPTION_ID=$SUBSCRIPTIONID \
        # -p AZURE_TENANT_ID=$TENANTID \
        # -p AZURE_CLIENT_ID=$AADCLIENTID \
        # -p AZURE_CLIENT_SECRET=$AADCLIENTSECRET \
        # | oc create -f -
# fi

# Configure Metrics
# if [[ $METRICS == "true" ]]
# then
#     sleep 30
#     echo $(date) "- Deploying Metrics"
#     if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
#     then
#         runuser -l $SUDOUSER -c "ansible-playbook -e openshift_metrics_install_metrics=True -e openshift_metrics_cassandra_storage_type=dynamic -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-metrics/config.yml"
#     else
#         runuser -l $SUDOUSER -c "ansible-playbook -e openshift_metrics_install_metrics=True /usr/share/ansible/openshift-ansible/playbooks/openshift-metrics/config.yml"
#     fi
#     if [ $? -eq 0 ]
#     then
#         echo $(date) " - Metrics configuration completed successfully"
#     else
#         echo $(date) " - Metrics configuration failed"
#         exit 11
#     fi
# fi

# Configure Logging

# if [[ $LOGGING == "true" ]]
# then
#     sleep 60
#     echo $(date) "- Deploying Logging"
#     if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
#     then
#         runuser -l $SUDOUSER -c "ansible-playbook -e openshift_logging_install_logging=True -e openshift_logging_es_pvc_dynamic=true -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-logging/config.yml"
#     else
#         runuser -l $SUDOUSER -c "ansible-playbook -e openshift_logging_install_logging=True -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-logging/config.yml"
#     fi
#     if [ $? -eq 0 ]
#     then
#         echo $(date) " - Logging configuration completed successfully"
#     else
#         echo $(date) " - Logging configuration failed"
#         exit 12
#     fi
# fi

# Creating variables file for private master and Azure AD configuration playbook
echo $(date) " - Creating variables file for future playbooks"
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/vars.yaml <<EOF
admin_user: $SUDOUSER
master_lb_private_dns: $PRIVATEDNS
domain: $DOMAIN
EOF

# Configure cluster for private masters
if [[ $MASTERCLUSTERTYPE == "private" ]]
then
	echo $(date) " - Configure cluster for private masters"
	runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/activate-private-lb-fqdn.31x.yaml"
fi

# Delete yaml files
echo $(date) " - Deleting unecessary files"
rm -rf /home/${SUDOUSER}/openshift-container-platform-playbooks

# Delete pem files
# echo $(date) " - Delete pem files"
# rm -rf /tmp/*.pem

echo $(date) " - Sleep for 15 seconds"
sleep 15

echo $(date) " - Script complete"
