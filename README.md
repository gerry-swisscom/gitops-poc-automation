# gitops-poc-automation
This is the repo of the CLI automation tool for bootstrapping the EKS cluster (with ArgoCD and Crossplan) and installing different infrastructure components the GitOps.

It is based on the CLI python framework Click (https://click.palletsprojects.com/en/8.0.x/).

## Installation
Use the build.sh script to install an executable which points to the <code>create_cluster.py</code> script. When you call the exec, it will alway delegate to the current version of <code>create_cluster.py</code> (later changes will be considered).

## Preconditions
* Set up an environment Git repo (as of now only github repos are supported). The Git repo must contain a folder called <code>clusters</code> as a starting point for the initial app-of-apps
* Set up SSH keys for the Git client on the Cloud9 machine
* Create a personal access token for accessing the env repo and store the token in an environment variable called <code>GITHUB_TOKEN</code>
> The script doesn't check if the current context points to the right cluster !!!

## Commands
By calling the executable with <code>--help</code> flag you get the approriate documentation (all commands and options of the base command, option of the asked command)

### Recommended sequence
In order to get to a EKS cluster with GitOps & Crossplane enbaled you need to perform the sequence below:
* bootstrap
* boostrap-cluster
* install-argo
* install-crossplane
* configure-sa-and-aws-provider
* install infrastructure or other reusable templates (e.g. install-alb-controller)

### bootstrap
This command you need to call once and to provide the initial context information (e.g.). This information will be stored in the <code>ctx-home</code> folder. All subsequent commands assume that the bootstrap happened previously, if not they will throw an exception.

### bootstrap-cluster
This command installs the EKS cluster. It assumes that the VPC and subnets are already present and properly configured. It searches for the subnets based on the following convention:
* all subnets need to have the tag <code>EKS-Cluster</code> with the value equal cluster name
* public routable subnets need to have the tag <code>Subnet=public-routable</code>
* private routable subnets need to have the tag <code>Subnet=private-routable</code>
* private non-routable subnets need to have the tag <code>Subnet=private-nonroutable</code>

This command will create a KMS key for encryption and the cluster with a node group with 3 instances, oidc provider and some predefined add on policies. Only the control plane, ingress, etc. will be deployed in the routable subnets, everything else (e.g. pods) will be deployed in the non routable one.

### install-argo
This command installs the ArgoCD operator using the appropriate Helm chart, as well and configures the environment git repo (as of now github based) and the bootstrap app of apps called <code>cluster</code>. 

### install-crossplane
This command installs the crossplane Helm chart chart using the GitOps flow. 
> Due to the limitations in the profile B account, the script doesn't force the sync of this app. You need to to this manually!

### configure-sa-and-aws-provider
This command creates the necessary AWS role with bound to the OIDC broker of the cluster and provider-aws service account, and installs the provider-aws package and config (with the injected identity). It also commits the manifest in the env repo.

### install-alb-controller
This command creates the ALB controller policy (if missing) and installs the manifest for AWS role and service account creation in the env repo, as well as the Helm chart for <code>cert-manager</code> and <code>alb-controller</code>. In pushes all 3 ArgoCD apps as a transaction, and lets ArgoCD ensure the sequence according to the specified <code>sync waves</code>

### oidc-provider
This is a convenience command for retrieving the OIDC provider of the cluster
