import os
import posixpath
import sys
from pathlib import Path
import subprocess
from contextlib import contextmanager
import yaml
import boto3
import botocore
import click
import time
import base64
from datetime import datetime

def create_folder(folder_path, raise_ex_if_present=False):
    Path(folder_path).mkdir(parents=True, exist_ok=not raise_ex_if_present)
    


def exec_command(cmd, suppress_error_logs=False):
    try:
        click.echo(cmd)
        out_bytes = subprocess.check_output(cmd, shell=True)
        out_text = out_bytes.decode('utf-8')
        click.echo(out_text)
        return out_text
    except subprocess.CalledProcessError as e:
        out_bytes = e.output       # Output generated before error
        code      = e.returncode   # Return code
        if not suppress_error_logs:
            click.echo(f"an error occured (error_code: {code})")
            out_text = out_bytes.decode('utf-8')
            click.echo(out_text)
        raise e
 
def echo_comment(msg):
    click.echo(f"# {msg}")
        

class Context:
    def __init__(self, home):
        self.home = home
        #self.config = {}
        self._createHomeIfMissing()
        self.initial_ctx_yaml = os.path.join(self.home, "initial_ctx.yaml")
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.create_cluster_dir = os.path.join(self.home, "create_cluster")
        self.path_to_create_cluster_yaml = os.path.join(self.create_cluster_dir, "create_cluster.yaml")
        self.argocd_dir = os.path.join(self.home, "argo_cd")
        permissions_dir = os.path.join(self.home, "permissions")
        create_folder(permissions_dir)
        self.path_to_aws_auth_yaml = os.path.join(permissions_dir, "aws-auth.yaml")
        
        
    def persist_initial_ctx(self, cluster_name, github_username):
        if os.path.isfile(self.initial_ctx_yaml):
            raise Exception("initial_ctx.yaml found, bootstrap did already occure")
            
        init_ctx = {"cluster_name": cluster_name, "github_username": github_username}
        with open(self.initial_ctx_yaml, 'wt') as f:
            yaml.dump(init_ctx, f)
          
            
    def ensure_initial_ctx(self):
        if not os.path.isfile(self.initial_ctx_yaml): 
            raise Exception("initial context missing, please bootstrap first")
        with open(self.initial_ctx_yaml) as f:
            init_ctx = yaml.full_load(f.read())
            
            self.cluster_name = init_ctx["cluster_name"]
            self.github_username = init_ctx["github_username"]
            self.https_repo_url = f"https://github.com/{self.github_username}/{self.cluster_name}.git"
            self.ssh_repo_url = f"git@github.com:{self.github_username}/{self.cluster_name}.git"
            
        echo_comment(f"initial context: {self}")
        
                
    def ensure_current_ctx_matches(self):
        current_k8s_ctx = exec_command("kubectl config current-context")
        if self.cluster_name not in current_k8s_ctx:
            raise Exception("Panic: kubectl config current-context answers another cluster than the one in the initial context")
            
        
                

    def _createHomeIfMissing(self):
        create_folder(self.home)
        
    def is_cluster_created(self):
        return os.path.isfile(self.path_to_create_cluster_yaml)

    def __repr__(self):
        return f"<Context home={self.home}, cluster_name={self.cluster_name}, github_username={self.github_username}>"
 
        
pass_ctx = click.make_pass_decorator(Context)


@click.group()
@click.option("--ctx_home", envvar="CTX_HOME", default=".ctx", help="Changes the context folder location.")
@click.version_option("1.0")
@click.pass_context
def cli(ctx, ctx_home):
    ctx.obj = Context(os.path.abspath(ctx_home))
    echo_comment(ctx.invoked_subcommand)
    if ctx.invoked_subcommand != "bootstrap":
        ctx.obj.ensure_initial_ctx()
        
    if ctx.invoked_subcommand not in ["bootstrap", "bootstrap-cluster"]:
        ctx.obj.ensure_current_ctx_matches()
        

@cli.command()
@click.option("--cluster_name", prompt="enter cluster name")
@click.option("--github_username", prompt="enter github username")
@pass_ctx
def bootstrap(ctx, cluster_name, github_username):
    ctx.persist_initial_ctx(cluster_name, github_username)
    

@cli.command()
@pass_ctx
def bootstrap_cluster(ctx):
    now = datetime.now()
    echo_comment(f'STARTING AT {now}')
    
    cluster_name = ctx.cluster_name
    ensure_encryption_key(cluster_name)
    key_arn = exec_command(f"aws kms describe-key --key-id {key_alias_name(cluster_name)} --query KeyMetadata.Arn --output text")
    echo_comment(f'key arn: {key_arn}')
    
    create_folder(ctx.create_cluster_dir, raise_ex_if_present=False)
    echo_comment('create the eksctl manifest ...')
    fn = Path(__file__).parent / 'res' / 'create_eks_cluster_template.yaml'
    with open(fn) as f:
        data = f.read()
    
    data = data.replace("<cluster-name>", cluster_name)
    data = data.replace("<key-arn>", key_arn)
    
    data = enrich_subnets(ctx, data)
        
    with open(ctx.path_to_create_cluster_yaml, 'wt') as f:
        f.write(data)
     
    eksctl_create_cmd = f"eksctl create cluster -f '{ctx.path_to_create_cluster_yaml}'"
    exec_command(eksctl_create_cmd)

def enrich_subnets(ctx, yaml_str):
    routable, non_routable, is_private_routable = read_subnets(ctx)
    yaml_obj = yaml.full_load(yaml_str)
    
    routable_items = [(f"routable-{idx}", {"id": subnet_id}) for idx, subnet_id in enumerate(routable)]
    non_routable_items =  [(f"non-routable-{idx}", {"id": subnet_id}) for idx, subnet_id in enumerate(non_routable)]
    if is_private_routable:
        private_subnets = dict(routable_items + non_routable_items)
        yaml_obj["vpc"]["subnets"]["private"] = private_subnets
    else:
        yaml_obj["vpc"]["subnets"]["public"] = dict(routable_items)
        yaml_obj["vpc"]["subnets"]["private"] = dict(non_routable_items)
        
    # yaml_obj["nodeGroups"][0]["subnets"] = non_routable
    
    return yaml.dump(yaml_obj)
        
    
def read_subnets(ctx):
    ec2_client = boto3.client("ec2")
    
    is_private_routable = True
    filter_criteria_routable = [ 
            {'Name': 'tag:Subnet', 'Values': ['private-routable'] },
            {'Name': 'tag:EKS-Cluster', 'Values': [ctx.cluster_name] }
        ]
    routable_items = ec2_client.describe_subnets(Filters =filter_criteria_routable)['Subnets'] 
    if len(routable_items) == 0:
        is_private_routable = False
        filter_criteria_routable = [ 
                {'Name': 'tag:Subnet', 'Values': ['public-routable'] },
                {'Name': 'tag:EKS-Cluster', 'Values': [ctx.cluster_name] }
            ]
        routable_items = ec2_client.describe_subnets(Filters =filter_criteria_routable)['Subnets'] 
        if len(routable_items) == 0:
            raise Exception("no routable subnets found")
        
    routable_subnet_ids =  [item['SubnetId'] for item in routable_items]
    
    filter_criteria_non_routable = [ 
            {'Name': 'tag:Subnet', 'Values': ['private-nonroutable'] },
            {'Name': 'tag:EKS-Cluster', 'Values': [ctx.cluster_name] }
        ]
    non_routable_items = ec2_client.describe_subnets(Filters = filter_criteria_non_routable)['Subnets'] 
    if len(non_routable_items) == 0:
        raise Exception("no non-routable subnets found")
    non_routable_subnet_ids = [item['SubnetId'] for item in non_routable_items]
    
    #we expect exactly 3 subnets, one for each AZ
    #assert(len(routable_subnet_ids) == 3)
    #assert(len(non_routable_subnet_ids) == 3)
    
    return routable_subnet_ids, non_routable_subnet_ids, is_private_routable
    
        
def key_alias_name(cluster_name):
    return f'alias/eks_key_{cluster_name}'

def ensure_encryption_key(cluster_name):
    iam_client = boto3.resource('iam')

    kms_client = boto3.client('kms')
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    
    key_arn = f"arn:aws:kms:eu-central-1:{account_id}:{key_alias_name(cluster_name)}"

    try:
        kms_client.describe_key(KeyId=key_arn)
        echo_comment("key found, nothing to do ...")
    # Catching exceptions through ClientError and parsing for error codes is still the best way to catch all service-side exceptions and errors.
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NotFoundException':
            echo_comment("create encryption key for EKS")
            response = kms_client.create_key(
                Description=f'key for secrets encryption in eks cluster {cluster_name}',
                KeyUsage='ENCRYPT_DECRYPT',
                KeySpec='SYMMETRIC_DEFAULT',
                Origin='AWS_KMS',
                BypassPolicyLockoutSafetyCheck=False,
                Tags=[
                    {
                        'TagKey': 'EKS cluster',
                        'TagValue': cluster_name
                    },
                ],
                MultiRegion=False
            )
            arn = response['KeyMetadata']['KeyId']
        
            kms_client.create_alias(
                AliasName=key_alias_name(cluster_name),
                TargetKeyId=arn
            )
    

@cli.command()
@pass_ctx
def install_crossplane(ctx):   
    ensure_env_repo(ctx)
    exec_command("kubectl create namespace crossplane-system")
    install_helm_app(ctx, "crossplane", "crossplane-system", "crossplane", "crossplane", "https://charts.crossplane.io/stable", "1.6.4")
    
    
def ensure_env_repo(ctx):
    cluster_name = ctx.cluster_name
    if cluster_name not in os.listdir('.'):
        exec_command(f"git clone {ctx.ssh_repo_url}")
    
    install_argo_app(ctx, "infra", "argocd", ctx.https_repo_url, "clusters")
    create_folder(os.path.join(cluster_name, "clusters", "infra"))
    
    
def install_helm_app(ctx, name, target_namespace, chart, release_name, repo_url, target_revision, path_to_app="clusters/infra", params=None, sync_wave=None, auto_commit=True):
    cluster_name = ctx.cluster_name
    fn = Path(__file__).parent / 'res' / 'argocd' / 'templates' / 'helm-app-template.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<name>", name)
    data = data.replace("<target-namespace>", target_namespace)
    data = data.replace("<chart>", chart)
    data = data.replace("<release-name>", release_name)
    data = data.replace("<helm-repo-url>", repo_url)
    data = data.replace("<target-revision>",  target_revision)
    
    if params:
        data = enrich_params(data, params)
    
    if sync_wave:
        data = add_sync_wave_annotation(data, sync_wave)
    
    path_to_yaml = path_to_yaml = f"{cluster_name}/{path_to_app}/{name}.yaml"
    with open(path_to_yaml, 'wt') as f:
        f.write(data)
    
    if auto_commit:
        commit_and_push_env_repo_changes(ctx, f"install argo helm app {name}")
    
    
def install_argo_app(ctx, name, target_namespace, repo_url, path, path_to_app="clusters/infra", sync_wave=None):
    cluster_name = ctx.cluster_name
    fn = Path(__file__).parent / 'res' / 'argocd' / 'templates' / 'app-template.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<name>", name)
    data = data.replace("<repo-url>", repo_url)
    data = data.replace("<path>", path)
    data = data.replace("<target-namespace>", target_namespace)
    
    if sync_wave:
        data = add_sync_wave_annotation(data, sync_wave)
    
    path_to_yaml = f"{cluster_name}/{path_to_app}/{name}.yaml"
    with open(path_to_yaml, 'wt') as f:
        f.write(data)
    
def enrich_params(yaml_data, params):
    yaml_obj = yaml.full_load(yaml_data)
    enriched_params = [{"name": item[0], "value": item[1]} for item in params]
    helm = yaml_obj["spec"]["source"]["helm"]
    helm["parameters"] = enriched_params
    yaml_obj["spec"]["source"]["helm"] = helm
    return yaml.dump(yaml_obj)
    
def add_sync_wave_annotation(yaml_data, sync_wave):
    yaml_obj = yaml.full_load(yaml_data)
    metadata = yaml_obj['metadata']
    metadata['annotations'] = {"argocd.argoproj.io/sync-wave": sync_wave}
    yaml_obj['metadata'] = metadata
    return yaml.dump(yaml_obj)
    
def commit_and_push_env_repo_changes(ctx, message):
    cluster_name = ctx.cluster_name
    exec_command(f'cd {cluster_name} && git add . && git commit -m "{message}" && git push')
    

@cli.command()
@pass_ctx
def configure_sa_and_aws_provider(ctx):
    https_repo_url = ctx.https_repo_url
    cluster_name = ctx.cluster_name
    role_name = f"crossplane_provider_aws_{cluster_name}"
    ensure_role_for_crossplane_provider(ctx, role_name)
    
    fn = Path(__file__).parent / 'res' / 'crossplane' / 'provider-config_1.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<account-id>", ctx.account_id)
    data = data.replace("<iam-role>", role_name)
    
    path_to_dir = os.path.join(cluster_name, "infra", "aws-provider-config")
    create_folder(path_to_dir)
    path_to_yaml = os.path.join(path_to_dir, "manifest.yaml")
    if os.path.isfile(path_to_yaml): 
        os.remove(path_to_yaml)
    with open(path_to_yaml, 'wt') as f:
        f.write(data)
        
    exec_command(f"kubectl apply -f {path_to_yaml}")
    #exec_command("kubectl -n crossplane-system wait --for condition=established --timeout=60s crd/providerconfigs.aws.crossplane.io")
    time.sleep(30)
        
    fn = Path(__file__).parent / 'res' / 'crossplane' / 'provider-config_2.yaml'
    with open(fn) as f:
        data = f.read()
    
    with open(path_to_yaml, 'at') as f:
        f.write(data)
        
    exec_command(f"kubectl apply -f {path_to_yaml}")
    
    app_name = "aws-provider-config"
    install_argo_app(ctx, app_name, "default",  https_repo_url, "infra/aws-provider-config")
    commit_and_push_env_repo_changes(ctx, f"install argo app {app_name}")
    
def ensure_role_for_crossplane_provider(ctx, role_name):
    cluster_name = ctx.cluster_name
    oidc_provider = do_query_oidc_provider(ctx)
    
    account_id = ctx.account_id
    crossplance_ns = "crossplane-system"
    trust_relationship = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringLike": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:provider-aws-*"
        }
      }
    }
  ]
}""".replace("${AWS_ACCOUNT_ID}", account_id).replace("${OIDC_PROVIDER}", oidc_provider).replace("${SERVICE_ACCOUNT_NAMESPACE}", crossplance_ns)
    
    iam = boto3.resource('iam')
    role = iam.Role(role_name)
    try:
        role.load()
        echo_comment(f"found {role.arn}")
        echo_comment("nothing to do")
    # Catching exceptions through ClientError and parsing for error codes is still the best way to catch all service-side exceptions and errors.
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            echo_comment("create role for service account")
            echo_comment(f"create role with trust relationship: {trust_relationship}")
            role = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_relationship,
                Description="IAM role for provider-aws",
                Tags=[
                    {
                        'Key': 'cluster',
                        'Value': cluster_name
                    },
                ]
            )
            role.attach_policy(
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
            

@cli.command()
@pass_ctx
def install_alb_controller(ctx):
    cluster_name = ctx.cluster_name
    https_repo_url = ctx.https_repo_url
    policy_name, policy_arn = ensure_alb_controller_policy(ctx)
    
    app_name = "alb-controller-service-account"
    install_argo_app(ctx, app_name, "kube-system",  https_repo_url, f"infra/{app_name}", sync_wave="-1")
    
    fn = Path(__file__).parent / 'res' / 'alb_controller' / 'service_account_and_role_template.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<account-id>", ctx.account_id)
    data = data.replace("<role-name>", f"AmazonEKSLoadBalancerControllerRole-{cluster_name}".lower())
    data = data.replace("<oidc-provider>", do_query_oidc_provider(ctx))
    data = data.replace("<policy-arn>", policy_arn)
    
    
    path_to_folder = f"{cluster_name}/infra/{app_name}"
    create_folder(path_to_folder)
    path_to_manifest = os.path.join(path_to_folder, "manifest.yaml")
    
    with open(path_to_manifest, 'wt') as f:
        f.write(data)
        
    install_helm_app(ctx, "cert-manager", "cert-manager", "cert-manager", "cert-manager", "https://charts.jetstack.io", "v1.7.1", sync_wave="-1", params=[("installCRDs", "true")], auto_commit=False)
    
    alb_controller_params = [
        ("image.repository", "602401143452.dkr.ecr.eu-central-1.amazonaws.com/amazon/aws-load-balancer-controller"),
        ("clusterName", cluster_name),
        ("serviceAccount.create", "false"),
        ("serviceAccount.name", "aws-load-balancer-controller")
    ]
    install_helm_app(ctx, "aws-load-balancer-controller", "kube-system", "aws-load-balancer-controller", "aws-load-balancer-controller", "https://aws.github.io/eks-charts", "1.3.3", params=alb_controller_params, auto_commit=False)
    
    commit_and_push_env_repo_changes(ctx, f"install argo app {app_name}")
    

def ensure_alb_controller_policy(ctx):
    policy_name = "AWSLoadBalancerControllerIAMPolicy"
    account_id = ctx.account_id
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    iam = boto3.resource('iam')
    policy = iam.Policy(policy_arn)
    try:
        policy.load()
        echo_comment("policy found, nothing to do ...")
    # Catching exceptions through ClientError and parsing for error codes is still the best way to catch all service-side exceptions and errors.
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            echo_comment("create policy for alb controller service account role")
            fn = Path(__file__).parent / 'res' / 'alb_controller' / 'iam_policy.json'
            with open(fn) as f:
                policy_spec = f.read()
            policy = iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_spec,
                Description='policy for alb controller service account role'
            )
            echo_comment(f"created policy with arn: {policy.arn}")
        
    return (policy_name, policy_arn)
    
    


@cli.command()
@click.option('--user_arn', default='arn:aws:iam::259363168031:user/tgdkige1', prompt='enter user arn')
@click.option('--user_name', default='tgdkige1', prompt='enter user name')
@pass_ctx
def X_grant_browse_permissions(ctx, user_arn, user_name):
    cmd = f"kubectl get configmap aws-auth -n kube-system -o yaml > {ctx.path_to_aws_auth_yaml}"
    click.echo(cmd)
    exec_command(cmd)
    
    click.echo(f"- add user {user_arn} to mapUsers")
    with open(ctx.path_to_aws_auth_yaml) as f:
        aws_auth = yaml.full_load(f)
        map_users = f"- groups:\n  - system:masters\n  userarn: {user_arn}\n  username: {user_name}\n"
        aws_auth['data']['mapUsers'] = map_users
        
    with open(ctx.path_to_aws_auth_yaml, 'w') as f:
        yaml.dump(aws_auth, f)
    
    cmd = f"kubectl patch configmap/aws-auth -n kube-system --patch \"$(cat {ctx.path_to_aws_auth_yaml})\""
    click.echo(cmd)
    exec_command(cmd)
    


@cli.command()
@pass_ctx
def install_argo(ctx):
    exec_command("kubectl create namespace argocd")
    exec_command("kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
    
    time.sleep(30)
    
    https_repo_url = ctx.https_repo_url
    
    create_folder(ctx.argocd_dir)
    cluster_cfg = os.path.join(ctx.argocd_dir, "cluster.yaml")
    cluster_cfg_template    = Path(__file__).parent / 'res' / 'argocd' / 'cluster-template.yaml'
    cluster_cfg_params = {
        "<repo-url>": https_repo_url
    }
    load_template_and_replace_placeholder(cluster_cfg_template, cluster_cfg, cluster_cfg_params)
    exec_command(f"kubectl apply -f {cluster_cfg}")
    
    repo_cfg = os.path.join(ctx.argocd_dir, "repo.yaml")
    repo_cfg_template = Path(__file__).parent / 'res' / 'argocd' / 'repo-template.yaml'
    repo_cfg_params = {
        "<cluster-name>":   ctx.cluster_name,
        "<repo-url>":       https_repo_url,
        "<github-token>":   os.environ['GITHUB_TOKEN']
    }
    load_template_and_replace_placeholder(repo_cfg_template, repo_cfg, repo_cfg_params)
    exec_command(f"kubectl apply -f {repo_cfg}")
    
    # https://argo-cd.readthedocs.io/en/stable/operator-manual/health/#argocd-app
    cm_patch_yaml = Path(__file__).parent / 'res' / 'argocd' / 'cm-synch-waves-patch.yaml'
    exec_command(f"kubectl apply -f {cm_patch_yaml}")
    
    
def load_template_and_replace_placeholder(src, dest, placeholder_dict):
    with open(src) as f:
        content = f.read()
        
    with open(dest, 'w') as f:
        for key, value in placeholder_dict.items():
            content = content.replace(key, value)
        f.write(content)

def base64_encode(a_string):
    message_bytes = a_string.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode('ascii')

@cli.command()
@pass_ctx
def oidc_provider(ctx):
    do_query_oidc_provider(ctx)


def do_query_oidc_provider(ctx):
    cluster_name = ctx.cluster_name
    click.echo(f"current context is {cluster_name}")
    return exec_command(f'aws eks describe-cluster --name {cluster_name} --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///"').strip()
