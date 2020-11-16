# Security
- [Container Security](#Container-Security)

## Container Security 

Important Terms:
- Host: Physical or virtual system that hte containers run on
- Daemon: the software process that manages the container and the isolation between the containers and the host and between each other 
- image: container the configuration amd the content; eg the installed packages and installed services that define containers
- Base Image : The OS pacage that your containerized service runs on top of.
- Container: the actual virtual devices that the daemon deploys from and image
- Orchestration: Layer that sits on top of the containers that manages many containers and hosts which provides service such as automatic load balanceing , addding a removeing containers as needed , health checking 
- Immutability that a container should stay unchanged, and if not it should be easily replaced by another container of the same image.

" You need the lowere layers secured first otherwise its all for nothing" 

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
- Clair, Twistlock, Snyk.


