import os
import posixpath
import sys
from pathlib import Path
import subprocess
from contextlib import contextmanager
import yaml
import boto3
import click
import time
import base64

def create_folder(folder_path, raise_ex_if_present=False):
    Path(folder_path).mkdir(parents=False, exist_ok=not raise_ex_if_present)
    


def exec_command(cmd, suppress_error_logs=False):
    try:
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
        

class Context:
    def __init__(self, home):
        self.home = home
        self.config = {}
        self._createHomeIfMissing()
        self.verbose = False
        self.account_id = None
        self.create_cluster_dir = os.path.join(self.home, "create_cluster")
        self.path_to_create_cluster_yaml = os.path.join(self.create_cluster_dir, "create_cluster.yaml")
        self.path_to_secrets_dir = os.path.join(self.home, "secrets")
        self.path_to_sercret_file = os.path.join(self.path_to_secrets_dir, "git_source_apps_secret.yaml")
        self.gitsource_apps_secret_name = "git-source-apps"
        self.init_git_reponame_and_url()
        self.permissions_dir = os.path.join(self.home, "permissions")
        self.path_to_aws_auth_yaml = os.path.join(self.permissions_dir, "aws-auth.yaml")
        self.alb_controller_dir = os.path.join(self.home, "alb_controller")
        self.argocd_dir = os.path.join(self.home, "argo_cd")
        #self.assert_in_env_folder()
        
    def assert_in_env_folder(self):
        env_dir = "/home/ec2-user/environment/envs"
        envs = [f"{os.path.join(env_dir, name)}" for name in os.listdir(env_dir) if os.path.isdir(os.path.join(env_dir, name))] 
        if "/".join(self.home.split("/")[:-1]) not in envs:
            click.echo(f"home dir: {self.home}")
            raise Exception(f"illegal home, you must be in an env dir located here: {env_dir}")
        
        
    def init_git_reponame_and_url(self):
        if self.is_cluster_created():
            with open(self.path_to_create_cluster_yaml) as f:
                config = yaml.full_load(f)
                self.cluster_name = config['metadata']['name']
                gitops_flags = config['gitops']['flux']['flags']  
                self.gitops_repo_name = gitops_flags['repository']
                self.github_user = gitops_flags['owner']
                
            current_context = exec_command("kubectl config current-context")
            found_cluster_name = current_context.split("@")[1].split(".")[0]
            if found_cluster_name != self.cluster_name:
                raise Exception(f"current context doesn't match cluster_name ({current_context}, {self.cluster_name})")
                
            
                
                
    def gitops_repo_url(self):
        return f"git@github.com:{self.github_user}/{self.gitops_repo_name}.git"
    
    def https_repo_url(self):
        return f"https://github.com/{self.github_user}/{self.gitops_repo_name}.git"

    def _createHomeIfMissing(self):
        create_folder(self.home)
        
        
    def is_cluster_created(self):
        return os.path.isfile(self.path_to_create_cluster_yaml)
        

    def set_config(self, key, value):
        self.config[key] = value
        if self.verbose:
            click.echo(f"config[{key}] = {value}", file=sys.stderr)

    def __repr__(self):
        return f"<Context {self.home}>"
        
pass_ctx = click.make_pass_decorator(Context)


@click.group(chain=True)
@click.option(
    "--ctx_home",
    envvar="CTX_HOME",
    default=".ctx",
    help="Changes the context folder location.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enables verbose mode.")
@click.option("--account_id", default="259363168031",  envvar="AWS_ACCOUNT_ID")
@click.version_option("1.0")
@click.pass_context
def cli(ctx, ctx_home, verbose, account_id):
    ctx.obj = Context(os.path.abspath(ctx_home))
    ctx.obj.verbose = verbose
    ctx.obj.account_id = account_id



@cli.command()
@pass_ctx
@click.option("--cluster_name", prompt="enter cluster name", default="test_create_cluster")
@click.option("--github_username", prompt="enter github username", default="gerry-swisscom")
def bootstrap_cluster(ctx, cluster_name, github_username):
    #create_encryption_key(cluster_name)

    create_folder(ctx.create_cluster_dir, raise_ex_if_present=False)
    click.echo('create the eksctl manifest')
    fn = Path(__file__).parent / 'res' / 'create_eks_cluster_template.yaml'
    with open(fn) as f:
        data = f.read()

def create_encryption_key(cluster_name):
    iam_client = boto3.resource('iam')
    current_user = iam_client.CurrentUser()
    click.echo(f'current user arn: {current_user.arn}')

    user_arn = current_user.arn

    kms_client = boto3.client('kms')

    account_id = boto3.client('sts').get_caller_identity().get('Account')
    
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
        AliasName=f'alias/eks_key_{cluster_name}',
        TargetKeyId=arn
    )
    
    policy_name = 'default'
    policy = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::{account_id}:root"
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow access for Key Administrators",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "{user_arn}"
                },
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow access for ExampleUser",
                "Effect": "Allow",
                "Principal": {"AWS": "{user_arn}"},
                "Action": [
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:ReEncrypt*"
                ],
                "Resource": "*"
            }
        ]
    }""".replace("{user_arn}", user_arn).replace("{account_id}", account_id)

    response = kms_client.put_key_policy(
        KeyId=arn,
        Policy=policy,
        PolicyName=policy_name
    )



@cli.command()
@pass_ctx
@click.option("--cluster_name", prompt="enter cluster name")
@click.option("--github_username", default="gerry-swisscom")
@click.option("--key_arn", prompt="enter kms key arn", default="arn:aws:kms:eu-central-1:259363168031:key/2a7fb1cc-06ac-40d1-89e5-ef06dc6b9bf7")
def create_cluster(ctx, cluster_name, github_username, key_arn):
    
    create_folder(ctx.create_cluster_dir, raise_ex_if_present=True)
    click.echo('create the eksctl manifest')
    fn = Path(__file__).parent / 'res' / 'create_eks_cluster_template.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<cluster-name>", cluster_name)
    data = data.replace("<your GitHub Username>", github_username)
    data = data.replace("<key-arn>", key_arn)
    data = data.replace("<account-id>", ctx.account_id)
        
    with open(ctx.path_to_create_cluster_yaml, 'wt') as f:
        f.write(data)
     
    eksctl_create_cmd = f"eksctl create cluster -f '{ctx.path_to_create_cluster_yaml}'"
    click.echo(eksctl_create_cmd)    
    exec_command(eksctl_create_cmd)
    
    #in order to be able to chain subsequent commands
    ctx.init_git_reponame_and_url()


@cli.command()
@pass_ctx
def prepare_git_secret(ctx):
    
    create_folder(ctx.path_to_secrets_dir, raise_ex_if_present=False)
    click.echo("export and prepare gitsource apps secret")
    export_cmd = f"kubectl get secret -o json flux-system --namespace=flux-system | jq '.metadata.namespace |= \"default\"'  | jq '.metadata.name |= \"{ctx.gitsource_apps_secret_name}\"' > {ctx.path_to_sercret_file}"
    
    exec_command(export_cmd)
    
    exec_command(f"kubectl create -f {ctx.path_to_sercret_file}")
    
    
@cli.command()
@pass_ctx
def create_git_source_apps(ctx):
    if ctx.is_cluster_created():
        cmd = f"git clone {ctx.gitops_repo_url()}"
        click.echo(f"clone gitops repo: {ctx.gitops_repo_name}")
        exec_command(cmd)
        create_folder(f"./{ctx.gitops_repo_name}/clusters/applications")
        ssh_url = f"ssh://git@github.com/{ctx.github_user}/{ctx.gitops_repo_name}"
        app_source_yaml = f"./{ctx.gitops_repo_name}/clusters/applications/applications-source.yaml"
        git_src_apps_cmd = f"flux create source git applications --url={ssh_url} --branch=main --interval=30s --namespace=default  --secret-ref={ctx.gitsource_apps_secret_name} --export"
        click.echo(git_src_apps_cmd)
        exec_command(git_src_apps_cmd)
        
        #generate the manifest
        exec_command(f"{git_src_apps_cmd} > {app_source_yaml}")
        exec_command(f"cd {{ctx.gitops_repo_name}}")
        exec_command("git add . && git commit -m \"add git apps source config\" && git push" )


@cli.command()
@click.option('--user_arn', default='arn:aws:iam::259363168031:user/tgdkige1', prompt='enter user arn')
@click.option('--user_name', default='tgdkige1', prompt='enter user name')
@pass_ctx
def grant_browse_permissions(ctx, user_arn, user_name):
    
    create_folder(ctx.permissions_dir)
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
def configure_alb_controller(ctx):
    click.echo("check if OIDC identity provider is configured for the cluster")
    oidc_provider_url = exec_command(f"aws eks describe-cluster --name {ctx.cluster_name} --query \"cluster.identity.oidc.issuer\" --output text")
    click.echo(f"- OIDC provider url: {oidc_provider_url}")
    try:
        iam_oidc_provider_list = exec_command(f"aws iam list-open-id-connect-providers | grep {oidc_provider_url.split('/')[-1]}", suppress_error_logs=True)
        click.echo(f"- iam OIDC provider list: {iam_oidc_provider_list}")
        click.echo("- OIDC identity provider is configured, nothing to do")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1: # not found
            click.echo("- OIDC provider not found for cluster\n- creating one...")
            exec_command(f"eksctl utils associate-iam-oidc-provider --cluster {ctx.cluster_name} --approve")
        else:
            raise e
    
    policy_name = "AWSLoadBalancerControllerIAMPolicy"
    click.echo("configure AWS loadbalancer controller")
    create_folder(ctx.alb_controller_dir)
    iam_policy_json = os.path.join(ctx.alb_controller_dir, "iam_policy.json")
    cmd = f"curl -o {iam_policy_json} https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.3.0/docs/install/iam_policy.json"
    #there was some additional permissions needed?
    #policy exists already
    #exec_command(cmd)
    
    cmd = f"aws iam create-policy --policy-name {policy_name} --policy-document file://{iam_policy_json}"
    #there was some additional permissions needed?
    #policy exists already
    #exec_command(cmd)
    
    click.echo("create IAM service account")
    cmd = f"""eksctl create iamserviceaccount \
  --cluster={ctx.cluster_name} \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --attach-policy-arn=arn:aws:iam::{ctx.account_id}:policy/{policy_name} \
  --override-existing-serviceaccounts \
  --approve"""
    exec_command(cmd)
    
    try:
        exec_command("kubectl get deployment -n kube-system alb-ingress-controller", suppress_error_logs=True)
        click.echo("old controller found, remove it first")
        exec_command("kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.8/docs/examples/alb-ingress-controller.yaml")
        exec_command("kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.8/docs/examples/rbac-role.yaml")
    except subprocess.CalledProcessError as e:
        if e.returncode != 1: # return code 1 means not found
            raise e
            
    additional_iam_policy_json = os.path.join(ctx.alb_controller_dir, "iam_policy_v1_to_v2_additional.json")
    #policy exists already
    #exec_command(f"curl -o {additional_iam_policy_json} https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.3.0/docs/install/iam_policy_v1_to_v2_additional.json")
    cmd = f"""aws iam create-policy \
  --policy-name AWSLoadBalancerControllerAdditionalIAMPolicy \
  --policy-document file://{additional_iam_policy_json}"""
    #exec_command(cmd)
    
    cloudformation = boto3.resource('cloudformation')
    stack = cloudformation.Stack(f"eksctl-{ctx.cluster_name}-addon-iamserviceaccount-kube-system-aws-load-balancer-controller")
    iam_sa_role_name = list(stack.resource_summaries.all())[0].physical_resource_id
    click.echo(f"role name of iam service account: {iam_sa_role_name}")
    
    click.echo("attach role to policy")
    cmd = f"""aws iam attach-role-policy \
  --role-name {iam_sa_role_name} \
  --policy-arn arn:aws:iam::{ctx.account_id}:policy/AWSLoadBalancerControllerAdditionalIAMPolicy"""
    exec_command(cmd)
    
    click.echo("install cert manager")
    cmd = """kubectl apply \
    --validate=false \
    -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml"""
    exec_command(cmd)
    
    #TODO: check if cert manager was installed successfully
    # exec command and assume answer below $ cmctl check api
    #The cert-manager API is ready
    
    click.echo("install controller")
    alb_ctrl_json = os.path.join(ctx.alb_controller_dir, "v2_3_0_full.yaml")
    cmd = f"curl -Lo {alb_ctrl_json} https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.3.0/v2_3_0_full.yaml"
    exec_command(cmd)
    
    with open(alb_ctrl_json) as f:
        content = f.read()
        
    with open(alb_ctrl_json, 'w') as f:
        content = content.replace("your-cluster-name", ctx.cluster_name)
        f.write(content)
        
    cmd = f"kubectl apply -f {alb_ctrl_json}"
    exec_command(cmd)


@cli.command()
@pass_ctx
def install_argo(ctx):
    exec_command("flux suspend kustomization --all")
    exec_command("kubectl create namespace argocd")
    exec_command("kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
    
    time.sleep(10)
    
    create_folder(ctx.argocd_dir)
    cluster_cfg = os.path.join(ctx.argocd_dir, "cluster.yaml")
    cluster_cfg_template    = Path(__file__).parent / 'res' / 'argocd' / 'cluster-template.yaml'
    cluster_cfg_params = {
        "<repo-url>": ctx.https_repo_url()
    }
    load_template_and_replace_placeholder(cluster_cfg_template, cluster_cfg, cluster_cfg_params)
    exec_command(f"kubectl apply -f {cluster_cfg}")
    
    repo_cfg = os.path.join(ctx.argocd_dir, "repo.yaml")
    repo_cfg_template       = Path(__file__).parent / 'res' / 'argocd' / 'repo-template.yaml'
    repo_cfg_params = {
        "<cluster-name>":   ctx.cluster_name,
        "<repo-url>":       ctx.https_repo_url(),
        "<github-token>":   os.environ['GITHUB_TOKEN']
    }
    load_template_and_replace_placeholder(repo_cfg_template, repo_cfg, repo_cfg_params)
    exec_command(f"kubectl apply -f {repo_cfg}")
    
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
def oidc_broker(ctx):
    click.echo(f"current context is {ctx.cluster_name}")
    exec_command(f'aws eks describe-cluster --name {ctx.cluster_name} --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///"')

@cli.command()
@pass_ctx
def current(ctx):
    click.echo(f"current context is {ctx.cluster_name}")
    

cluster_config = {
    "dev":  "i-053c02913aa8a8eee@gitops-poc-dev.eu-central-1.eksctl.io",
    "test": "i-053c02913aa8a8eee@gitops-poc-test.eu-central-1.eksctl.io",
    "prod": "i-053c02913aa8a8eee@gitops-poc-prod.eu-central-1.eksctl.io"
}

@cli.command()
@pass_ctx
@click.option("--cluster", prompt="environment (dev, test, prod)")
def switch_cluster(ctx, cluster):
    cmd = f"kubectl config use-context {cluster_config[cluster]}"
    exec_command(cmd)
    
    
@cli.command()
@pass_ctx
def current_cluster(ctx):
    found_cluster = exec_command("kubectl config current-context")
    for env, cluster in cluster_config.items():
        if cluster == found_cluster:
            click.echo(f"current cluster context is: {env}")
            return
        
    click.echo(f"unkonwn cluster found")
    
@cli.command()
@pass_ctx
def status(ctx):
    if ctx.is_cluster_created():
        click.echo("*****************************")
        click.echo('1. cluster created')
        click.echo('   config file:')
        click.echo("*****************************")
        
        with open(ctx.path_to_create_cluster_yaml) as f:
            click.echo(f.read())
    
    
        

