# Security
- [Container Security](#Container-Security)
- [Linux Security](#Linux-Security)

# Container Security 
Important Terms:
- Host: Physical or virtual system that hte containers run on
- Daemon: the software process that manages the container and the isolation between the containers and the host and between each other 
- image: container the configuration amd the content; eg the installed packages and installed services that define containers
- Base Image : The OS pacage that your containerized service runs on top of.
- Container: the actual virtual devices that the daemon deploys from and image
- Orchestration: Layer that sits on top of the containers that manages many containers and hosts which provides service such as automatic load balanceing , addding a removeing containers as needed , health checking 
- Immutability that a container should stay unchanged, and if not it should be easily replaced by another container of the same image.

" You need the lowere layers secured first otherwise its all for nothing", butthey all need protecting ultimately, Host/Daemon, Images, Containers Orchestration Layer.

### TLDR - Container Security
- Defense in depth -Principle of least privledge
- Patch and keep things up to date.
- Don't run as Root
- Use Audit logging 
- in Docker files use COPY instead of ADD.

### Where most fall down when it comes to Container Security
- Missing default network policies 
    - No policies defined OR policies that allow broad communication between all pods in a namespace
    - Missing egress controls

- Pod-to-pod communication weaknesses: 
    - Missing encryption and/or authentication/authorization

- Improper Secrets Management 
    - Hard coded or non-unique secrets
    - Secrets not injected securely at run/deploy time
    - Improper storage of secrets
    
- Insufficient scanning of final container images – Configuration vulnerabilities, OpenSourceVulnerabilities, Secrets in image

- Missing/insufficient logging –Generation of application and/or data related security events,  Analysis/alerting of relevant security events

- Insufficient processes to rapidly refresh running containers or update workers/masters in the event of a critical vulnerability

### Secureing the Host and the Daemon
- Harden the same as a critical system 
 - minimal packages
This is the same as secureing a VM
 - minimal permission
 - strong passwords
 - strong passwords that are changed regularly
 - restrict Access to the host AND Docker 
 - No root-level users, principle of least privledge

### Enable Auditing
This will allow you to go back and see who did what; when and where.
- At the host level Use auditd (a native Linux feature) to monitor system calls, file access etc. Enables detection of unauthorized changes. These logs will need to be sent out of the containers. (A: ??HOW?? - see [How to guide for auditd on Docker](https://www.digitalocean.com/community/tutorials/how-to-audit-docker-host-security-with-docker-bench-for-security-on-ubuntu-16-04)) 

### Configure Docker Daemon directly
The daemon.json file contains various directive for configuring the daemon.
```json
{
    "icc":false,
    "log-driver":"syslog",
    "userland-proxy":false,
    "no-new-privleges": true
}
```
- Disable ICC (Inter-Container Communication): When enabled allows containers to comunicate to each other as if they are on the same LAN. IF disabled , you will have to intentionally expose ports and allow traffic between two containers.

- Disable Userland Proxy: Allows the use of the hairpin NAT and iptables. Being kernel mode features, they are more reliable and robust than the userland Proxy that comes wit hDocker. 

- Enable `non-new-privledges` : Prevents privledge escalation from inside a container. SUID/GUID binary will be prevented.
- Enable Syslog: to send out the logs to the SIEM and alert
- USe SIEM to scan and alert

## Images
- Only use images you trust. Even if they are popular, but you never know. Look at the links in the git hub repo if available, otherwise spin up the contain in a sandbox to check it. 

- Popular official images from official Docker Hub can e safe but should be carefully reviewed 
- Enable `Docker Content Trust`
    - Image publishers must sign their images and image consumers can ensure the imagesthey pull are signed. This feature will check those signatures. 

- host your own container registry
- Always check signatures/hashes/digests. Long but the last lin of defense.
- signatures/hashes/digests must come from a trusted source. Long but the last lin of defense.

### Base Images
Start with Minimal Base Images
- required functionality only
- remove all unnecessary features, user accounts and packages from both the image and you application.
- add only what is needeed
- pre-packaged minimal images (eg Alpine or Red Hat UBI-minimal) are a good choice. 
- check signatures/hashes/digests

### Image Building Recomendations
- As always ... **Easier/Cheaper to design security up front** 
- Run containers with a non-root user
- **use COPY instead of ADD**: ADD allows you to pull things from a remote URL. At build time it could be different from what you believe. COPY will only pull somthing from the local file system.
- verify packages/dependeneices
- update base OS and packages at **build-time**. Don't want to be deploying out dated containers at build time. 
- No secrets in images (passwords, API keys etc). PAss these in fro ma secure location at run time. 
- Tag images thoughtfully. If you have a good structure with names and versions ,it will make it wasier to use and manage things.

## Containers

### Container Isolation

- Restrict container's limits to memory and CPU via runtime options.
- Restrict container's access tp network (e.g other containers, internet, etc)
    - A databased container does not need to be accessible via internet, for example Default deny ( both ingress and egress) 
    - Selectively allow/active (Istio, Calico, and minimizing open ports by processes)
- Run containers read-only or tempfs where possible. This supports immutability.
- Do not break the isolation intentionally (or otherwise)
- Continue authenticating requests/calls even if they are coming internally. (Think Capital1)

## MAKE SURE YOU STILL PATCH
- The host, Images and the containers
- Containerization, Think the Ship of Theseus
- HAve a patching plan, for short term and long term incidents.
- Log the patch activities - both manual or automatic.

## Tools for Container security
- Docker Bench : A script that checks for dozens fo common best-practices around deploying Docker containers in production. Based on the CIS benchmarks. 
Also 
- Clair, Twistlock, Snyk

# Orchestration 

Orchestration is automated configuration management of coordinated computer systems, applications and services. 

Cluster Components 
- Infrastructure/Control Plane: Comprises the API server, Etcd, Scheduler and Controller managers, which are the components that manage and operate the cluster.
- Nodes: Worker Machines (Physical or Virtual) that each contain a kubelet which ensure a container is running to spec otherwise it takes remedial action. Kubeproxy is the network proxy. 
- Container runtime eg: Docker, ContainerD, RunC etc.
- Pods: Group of one or more containers with shared storage and network resources
- Etcd: Important cluster data storage to be kept highly available.

High level recomendations
- API Server
    - DO NOT MAKE PUBLIC - This is what happend to Tesla. HAve an allow list rather than a block list
    - Restictaccess to known IPs/ranges if possible

- Nodes
    - DO NOT MAKE PUBLIC - Same as above. 
    - Accept connection from control plane only, on specific ports, only services of type NodePort and LoadBalancer. 

- Etcd
    - Use TLS for authentication - For hte connection and the authentication
    - Allow access only from control plane/API only
    - Encrypt etcd data while at rest

- Cluster 
    - Use Namspaces: These can simplify management with a well defined schema
    - use etcd to manage Kubernetes secrets and encrypt secrets at rest
    - USe RBAC to control API access 
    - Set network policies
    - Configure Pod Security Policies
    - Use Open Policy Agent (OPA)
    - Require TLS for ingress and API traffic
    - Enable Audit Logging
- Pods
    - Do not allow privledged pods (`Privledged: false`) yaml
    - DO not allow process privilege escalation (`allowPrivilegeEscalation: false`) yaml
    - Limit abilities of useres and service accounts. **Do not run pods as root**. They could break out to the pod host system.
    - Enable read only root file system if possible
    - Use SELinux, AppArmour, etc if feasible or block unneeded kernel modules. Harder to retro fit
    - Set resource quotas and limit ranges. You dont want one pod chokeing the resource node. 
    - Use client certificate or webhook authentication on the kublet
    - Enable authorization on the kublet which give fine grain control of who can do what. [See here](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/)
    - If running on a cloud platform, use network policies to restrict access to metadata APIs. Capital One attackers used the metadata API's to figure iut where the crown jules were.

    - [Cloud Native Security Overview](https://kubernetes.io/docs/concepts/security/overview/)
    - [Sysdig's Kubernetes Security Guide](https://sysdig.com/wp-content/uploads/2019/01/kubernetes-security-guide.pdf)

# Linux Security

## MAC( Mandatory access Control) and DAC ( Discretionary Access Control )

Discretionary access Controls is a means of restricting access to objects based on the identity of the subject and the groups with which they belong. The discretion is from subjects that have certain permissions, being capable to pass permissions on to other subjects. Thats what users,groups and permission are all doing. 

In Linux, two DAC mechanism are used
- Owner-based permission together with file modes
- Capability Systems 

Owner-based permission : UGO ( User , Group and Others). Every file has an owner and every entity that is UGO has user group permissions applied to it. 

permissions include: Read, Write and execute. 

There are also some specials to meet specific needs

- SUID (Set User ID): only has a meaning on a file. It allows a user to run a file as the owner of the file and not as them selves, so SUID == root will alow a user to be the root of the system while that file is running .

- SGID (Set Group ID ): same as above but for the group ownership. 

- StickyBit: only has effect on directories and if it is set on a file or directory only allows the deletion of that object by the owner of the item ( file , directory).

- ACL ( Access controls Lists) : Created for setting default permissions and to specify multiple owners.

- Attributes: These are properties that an admin can set on a file. 

# Capabilities

Capabilities are settings which give a files and software different access controls for the task they need to do.  

### MAC

The big difference MAC is the operating system enforces, and there is nothing the user can do about it; and thats why MAC is stringer than DAC on Linux.

This is implemented in the way the operating system constrains the ability of a subject or initiator to access or generally preform some sort of operation on an object or target. Subjects are typically users, processes or threads. Targets are typically files, directories, network ports , shared memory segments, IO devices. The subjects as well as the targets have a set of security attributes. Based on these authorization rules, the OS kernel can examine the attributes and decide if access is allowed by a subject to a target or not. 

The leading standard of MAC solutions on Linux is SELinux. SELinux originates from Red HAt, currently available of most distributions and co-developed with the NSA (apparently) but still open source. 

Smack is a MAC solutions set up for embedded systems. 

In SELinux...
setenforce permissive # Allows everything but still logs it all
setenforce Enforcing # turns SELinux back on for 


```sh
su           # The switch user command , without any arguments will ask for the root password and then switch you to the root user. 
su -         # Same as above but wil open a new shell with the root environment variables
sudo -i      # opens a rot shell
ssh-copy-id 
w           # Not a typo, type w to see who is logged in on the system
```

To configure the sudoers for the system , use the command ```sudo visudo``` .

## Working with Users and groups

groupadd (create groups)

adduser (Ubuntu) & useradd (CentOS)

```sh
adduser  bob                # add bob as a user ( UBUNTU only)
usermod --help              # Lots of options including locking and unlocking accounts
groupadd <GROUP_NAME>
userdel bob                 # delete bob as a user
useradd - D                 # displays the default setting for new user adds
/etc/skell                  # Contents is copied to use home directory upon user creation
/etc/login.defs             # used as the default configuration so changing this file will change the defaults. Such as password length, GRoup id, home dir
passwd -l <USER>            # Locks the password
passwd -u <USER>            # UNLOCKS the password
passwd -S <USER>            # Returns the status of the password
chage <USER>                # will load up the process to set password lifetime settings - Useful for admins
find / -perm /2000 # find files that have SGID
find / -perm /1000 # find files that have Sticky bit
find / -perm /4000 # find files that have SUID
```

There are four files for configuring centralised group and user information
/etc/shadow
/etc/group
/etc/gshadow
/etc/passwd

`/etc/passwd` - this is historically the file tha Unix has used to store user information. As this file is normally set to read for all users, the passwords are no longer stored in here. Instead they are encrypted and stored in hte `/etc/shadow`. Groups are stored in `/etc/group` . `/etc/gshadow` is not used anymore but it is a legacy file to set passwords for groups. You can modify the users and groups the safest way is to use `vipw` which will open a temporary file of `/etc/passwd` in VI. This will prevent cases where other users aer in `useradd`. OT do the same for `/etc/shadow`, use `vipw -s`. `vigr` will let you edit groups.

/etc/login.defs


# Linux Operating System Security

## Keeping up-to-date
CentOS `yum updateinfo` - this will run an update on the packages
RHEL `yum updateinfo` - the same command on RHEL will just give the info with an advisor code "RHSA-2016:0176"

### UBUNTU 
Ubuntu `apt-get -s dist-upgrade` - shows a list of all the updates that are available for a system

 `apt-get -s dist-upgrade | grep "^inst" | awk -F " " '{print $2}' | xargs apt-get install` this will list all the packages that are installers, get the names of them and then ppe them to the installer.

 `unattended-upgrades` will command will run a hands off use to upgrade good for "domestic" use but this is not good in cooporate environments as the updates need to be tested etc. 

 ### Validateing packages

On RHEL type distros the simplest way to validate all packages is with the rpm package managere. Use the command `rpm -Va` will verify.

On Ubuntu `apt install debsums` will insall the right package to check the hashsums of the packages.
firstly generae a list of packages checksums with the command `debsums -l` and then run a check on those with the comand `debsums -c` to check.

### <ins>AIDE (Advanced Intrusion Detection Environment)</ins>

Aide is for scanning the static parts of your server/file system as it will look for changes. Don't use it on places where things change a lot as it will raise lots of false positives. 

To install on RHEL run `yum install -y aide`. 

Configuration file `vim /etc/aide.conf`. In this file the `database` ( which the contens of scan targets set in the configuration) can be changed on the place on where to look.

In the configuration, after the options you will see profiles such as 
```
# NORMAL = R+sha512
NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha512
```
This line has many options separated by the '+' sign.

further on there a lots of listed locations for different targets to go into the database. 

To run **AIDE**
```
aide --init
```
After a few minutes yor scan will produce this report file `/var/lib/aide/aide.db.new.gz`.
The next time the scan runs it wil create another file with exactly the same name so the best thing to do is to **move this report to external storage and rename it with a unique date time.**

Once we have made our first scan and perhaps made some trivial change to the system like add a new user, you can run a comparison check with `aide --check` which is also the default command if you just type `aide`.

## Manageing file system security properties

### Createing encrypted block devices

`Luks` si the Linux encryption layer.

You need an empty device, for example `/dev/sdb1`. 
Format the device
Luks open will create a new luks device that you are going ot work with. Within this new luks device is where you make the new file system. Once it has been created this now luks device can be mounted. 

`cryptsetup` is the tool to set up a luks encryption. if you run `cryptesetup --help` you can see many different actions to take with the tool.

To run a luks encryptions run `cryptsetup luksFormat <Device>`. The prompt will ask for confirmation. Next choose the passphrase. 

TO use the device `cryptsetup luksOpen <Device> <Name-to-use>`. You should be able to see the device mapper directory `/dev/mapper`.

Mounting the device run `mount /dev/mapper/<Name-to-use> /<Location-to-mount>`.
TO close the device , first umount the device `umount /dev/mapper/<Name-to-use>` and then run `cryptsetup luksClose /dev/mapper/<Name-to-use>`. 
TO verify that the device has gone, go to the directory that the device lives in and run and `ls`. 

### Mounting devices persistently

A key will need to be created so you canuse your device persistently when loging on ot your machine. HAving the mounted device on your machine you an make life simpler by having hte key loaded on a removeable USB or similar. this way the mount can persist but the access will not. 

For an automatic mount luks open will need to be automated. The mount will also need to be automated. 


For an example You can create a random key of stuff with the command 
`dd if=/dev/urandom of=/root/luksey bs=4096 count=1`
Give the key root provledges `chmod 600` and then add the key to the encrypted device with `cryptsetup luksAddKey <Device-location> <Key-Location>`. You will be asked to set up a passphrase for the key. 
Next create the file `vim /etc/crypttab`. In this new file provide he name of the device, the underlaying device and then the name of the key. Then modify the `/etc/fstab` to include the <Device-name-and-location> and the location of where yu want to mount it.For example a line like
```
/dev/mapper/MyNewsecureFileSystem          /Desktop    ext4 defaults 1 2 
```
To check if this has worked you will need to reboot the system. 

### Security Related Mount options 

 `nodev`  Do not interpret character or block special devices on the file system.
 `nosuid` Do not allow set-user-ID or set-group-ID bits to take effect.
 `noexec` Do not permit direct execution of any binaries on the mounted filesystem.

 ```
 mount -o remount,noexec <address-of-the-file-system>
 ```

 ## <ins>Securing Server Access</ins>

 ### Secureing the GRUB boot loader

 When you turn the powere on the machine will run a POST (Power On Self Test). IT will then look for a bootable device. Once this is found , it will look for the `Bootloader`, normally `GRUB2`. GRUB2 will load the `Kernel` and the `initramfs`. After the service start we will be able to get a `shell`. 

Although we cannot prevent an attacker putting a physical thumbdrive in o the device, the first place we can protect before the Linux Kernel is loaded is the GRUB2 boot loader. This allows users to put in boot arguments. Controlling these will protect the system.

GRUB2 has two password types
- the global password : Makes it impossible to enter no matter what is on the prompt.
- OS specific password: Secures juts one specific OS started from GRUB.


To protect the password on GRUB2 you will need to make 2 input files with the following input:
- `/etc/grub.d/01_users`
```
set superusers="bob"
password bob somesecretepassword
password alice adifferentsecretpassword
```
- `/etc/grub.d/40_custom` defines verbatim menu entries for the GRUB2 menu, way before the shell.
```
#!/bin/sh
exec tail -n +3 $0
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.
menuentry 'CentOS Linux (3.10.0-327.13.1.el7.x86_64) 7 (Core)' --users bob {
set root=(hd0, msdos1)
linux16 /vmlinuz-3.10.0-327.13.el7/x86_64
}
```
**These files will need to be written to** `/boot/grub2/grub.cfg`.

In GRUB1 things were much easier. You would just need to specify `password` `<secret>`.

### Modifying text Console Settings

The login process uses 

- `/etc/issue `- this a file that will displays before login. It might have some config in the first few lines.
- `/etc/motd` - after login there is  the `message of the day`.
- `/.hushlogin` in the home of a user, contents of the motd will ot be shown

### <ins>Modifying Graphical Console Settings<ins/>

`cd /etc/gconf` is where the configuration will be kept
`gconftool-2 --help` has lots of sub help catagories 


# <ins> Securing Linux Infrastructure </ins>

### Sniffing and port scanning 

In modern networks we prefer `Switches` over `hubs`. Thisis because they have a MAC address table so the packets will only be advertised to the target port and none other.

 TO use tcpdump you need to understand your network cards. To do this run the command `ip link show`.

 **tcpdump** needs to be running as root because only rot can capture packets from the network.
 the manadory argument is hte network card you want to be listening on ther efore you would run something like the following `tcpdump -i eth0`. The out put will contain things that are structure as 

 `<TIMESTAMP>  <PROTOCOL> <INVOLVED MACHINE INFORAMTION>`

 ```
 07:29:26.769165 STP 802.1w, Rapid STP, Flags [Learn, Forward], bridge-id 89c5.70:70:8b:20:77:0f.80d9, length 42
07:29:26.777079 ARP, Request who-has 10.51.9.64 tell 10.51.0.1, length 42
07:29:26.798437 ARP, Request who-has 10.51.11.85 tell 10.51.11.84, length 42
```

**tcpdump** and wire shark bot handle `packet capture` files aka `.pcap` files. 

`tcpdump -i eth0 -w $(date +%d-%m-%Y).pcap` This will write the output of the tcpdump to a pcap file with the date in the title of the file.


`tcpdump -n -i eth0` will not show the host names and instead p addresses
`tcpdump -w ssh.pcap -i eth0 dst 192.168.4.10 and port 22` # filter on particular ips and ports , and write t oa certain file

```sh
nmap -sn <Network_IP+SubnetMask>        # scans the entire network
nmap -v -A <Network_IP+SubnetMask>      # agressive verbose network scan
nmap -PN <Ip_Address>                   # pierces through the fire wall apparently ???
nmap -O <Ip_Address>                    # scans for the operating system
nmap -PA                                # tcp AK scan ( 2nd half handshake )
```

### Tripwire

Tripwire has two versions open source and commercial
- open source version: HIDS ( Host Intrusion Detection System)
- Commercial version: NIDS ( Network Intrusion Detection System)

NIDS is more complicated that works with profiles that are part of the paid updates. An alternative is Snort but this also has a cost. An alternative to the opensource versions Aide is a good alternative. 


# Configureing Linux Logs

There is no standardizations in Linux Logging solutions. 
Logging is done by `Services`, `Syslog`, `Systmed-journald` and if everything is going ok these will all be sent to the `/var/log`.

syslog is loggin by using `facilities` such as `news` , `cron` , `kern` etc. This was based around a previous time when there were not so many services as there are now and so now services have started to make there own logging method. 

Syslog has become the defacto standard logging. The syslog service used facilities, priorities and sending it on to a destination. As more service s have been added syslog need a more advanced log service was needes, enter `syslog-ng`(next generation). 

`rsyslog` has replace syslog-ng as this can work with modules to make the logging more flexible. IT provides complete backward compatability and privides modules for extra features, for example for handling IO/OP directions.

The main place to configure rsyslog is the `/etc/rsyslog.conf`. `im` is for input modules and `om` is for output modules. 

`*.* @@remote-host:514` means every facility and every priority is sent via tcp to remote host on poirt 514.

journald is a volatile logging message platform that you can browse through the messages using the command `journalctl`. 

## Configureing remote logging

Today, secure remote logging will use `tls`. 
Requirements will include
- time sync . without this it will be pointless
- tls certs need setting up. (for now cirttool will sort this)
- tcp port 6514 neeeds to be accessible for the log server. 
- GTLS driver needs to be configured.

It is recommended to install the `rsyslog-doc` for all the documentation.

As part of the RHEL exam, it will involve getting the `native tls encryptions for syslog`. 

1. `systemctl status chronyd` - Check this time service on RHEL7+ ( else NPTD)
2. if `certtool` is not installed run `yum install gnutls-utils` to get it. 
3. Run `certtool --generate-privkey --outfile ca-key.pem `
4. give the ca-key.pem readable permission with `chmod 400 ca-key.pem`
5. Create a public key from the private key you have just made with `certtool --generate-self-signed --load-privkey ca-key.pem --outfile ca.pem`
6. Choose the settings you would like for your cert includeing.
    - Does the certificate belong to an authority? y
    - set no constraint on the path length.
    - the dnsName of the subject will be the will be the server name.
    - the URI,Ip and email of the subject do not apply.
    - No to: sign code, OCSP requests, time stamping.

7. next to genreate a private key.  
`certtool --genrate-privkey --outfile server1-key.pem --bits 2048`
8. Generate a signer request to get the CA.
`certtool --generate-request --load-privkey server-key.pem --outfile server1-request.pem`.
9. After chooseing all the options from the above command it will generate the pem files for the server. To make the key materiel for the rsyslog client `certtool --generate-certificate --load-request server1-request.pem --outfile server-cert.pem --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem` . This will make sure that server1 is trusted by all involved. 

### Setting up the log server
once the certs are created for hte CA and the server.
1. On server1 make a dir `/etc/rsyslog-keys`
2. Using `scp` (or similar) , copy the keys over to the server1 dir `scp server*.pem <IP_Addr_OF_MAchine>:/etc/rsyslog-keys` 
3. Add the ip addresses and dns names of workstation and server to your `/etc/hosts` file.
4. Configure the syslog on server1 for reception on port 6514 by going to `/etc/rsyslog.d` and adding 
```sh
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/rsyslog-keys/ca.pem
$DefaultNetstreamDriverCAFile /etc/rsyslog-keys/server1-cert.pem
$DefaultNetstreamDriverCAFile /etc/rsyslog-keys/server1-key.pem

$Modload imtcp

$InputTCPServerStreamDriverMode 1
$InputTCPServerStreamDriverAuthMode anon
$InputTCPServerRun 6514
```
5. restart the syslog service. You may need to install some packages if this complains and run again.
6. Configureing the client requires a directory `mkdir /etc/rsyslog-keys`.
7. Copy the `ca.pem` into there. 
8. Create a configuration file. The name is not as important as the content. IT should inlcude 
```sh
$DefaultNetStreamDriverCAFile /etc/rsyslog-keys/ca.pem

$DefaultNetStreamDriver gtls            # this package may need to be installed. Maybe "gnutls: 
$ActionSendStreamDriverMode 1           # this requires rsyslog to use tls
$ActionSendStreamDriverAuthMode anon    
*.*     @@(o)server1.example.com:6514   
```
9. install any packages that are needed for this and then restart the rsyslog server with systmectl.

### Manageing Log rotation

The solution to have a long range rotation so you can have a larger log window going back months or years is to compress logs after some time and store then off your device.

Look in the file `/etc/cron.daily/logrotate`. This will probably be referenceing the `/etc/logrotate.conf`. these will contain the configuration options for the log rotation. There is also `logrotate.d` for other files. In addition logrotate will incorporate the default parameters from the different logging engines, for example the settings in syslog.

### journald persistence

`journald` is part of systmed and may eventually replace syslog. For example Linux SUZE has not syslog as default.  journald send its logs to the `/run/log/journal` file. There is a parameter for configuring the rotation file size. Some Linux distros currently have only summary logs from journald go to syslog; just enough for an admin but no more. 
To get persistence with more comprehensive journald logs just make a certain directory and then restart the service with
```sh
 mkdir -p /var/log/journal
 systemctl restart systemd-journald
 ```
Just be carful for the rotation size. 
The takeaway here is that rsyslog offerers remote logging where as journald doesn't so, try and hold on to rsyslog as long as you can. 

### Useing logwatch for log analysis

One of the solutions for log analysis is logwatch. logwatch runs from a cronjob. OS you can see it in the cron.daily. Configurations setting are set in a `logwatch.conf` file. You can run an up to date log with `logwatch --range all` which will include todays messages. 


## Threat Modeling 

### STRIDE and DREAD
**STRIDE**  is  a  threat  modeling  methodology  that  is  performed  in  the  design  phase  of  software  development  in  which  threats  are  grouped  and  categorized  into the following six categories.■Spoofing – Impersonating another user or process
- Tampering – Unauthorized alterations that impact integrity
- Repudiation – Cannot prove the action; deniability of claim
- Information Disclosure – Exposure of information to unauthorized user or process that impact confidentiality
- Denial of Service – Service interruption that impacts availability
- Elevation  of  privilege  –  Unauthorized  increase  of  user  or  process  rights 

**DREAD**  is  a  risk  calculation  or  rating  methodology  that  is  often  used  in  conjunction with STRIDE, but does not need to be. To overcome inconsistencies and  qualitative  risk  ratings  (such  as  High,  Medium  and  Low),  the  DREAD  methodology aims to arrive at rating the identified (and categorized) threats by applying the following five dimensions.
- Damage potential – What will be the impact upon exploitability?
- Reproducibility – What is the ease of recreating the attack/exploit?
- Exploitability – What minimum skill level is necessary to launch the attack/exploit?
- Affected  users  –  How  many  users  will  be  potentially  impacted  upon a successful attack/exploit?
- Discoverability – What is the ease of finding the vulnerability that yields the threat?