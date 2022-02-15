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
                
            #current_context = exec_command("kubectl config current-context")
            #found_cluster_name = current_context.split("@")[1].split(".")[0]
            #if found_cluster_name != self.cluster_name:
            #    raise Exception(f"current context doesn't match cluster_name ({current_context}, {self.cluster_name})")
                
            

    def _createHomeIfMissing(self):
        create_folder(self.home)
        
        
    def is_cluster_created(self):
        return os.path.isfile(self.path_to_create_cluster_yaml)
        

    def set_config(self, key, value):
        self.config[key] = value
        if self.verbose:
            echo_comment(f"config[{key}] = {value}")

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
@click.version_option("1.0")
@click.pass_context
def cli(ctx, ctx_home, verbose):
    ctx.obj = Context(os.path.abspath(ctx_home))
    ctx.obj.verbose = verbose
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    ctx.obj.account_id = account_id
    
    

cluster_name = "test-create-cluster"
github_username = "gerry-swisscom"
https_repo_url = f"https://github.com/{github_username}/{cluster_name}.git"
ssh_repo_url = f"git@github.com:{github_username}/{cluster_name}.git"


@cli.command()
@pass_ctx
@click.option("--cluster_name", prompt="enter cluster name", default=cluster_name)
@click.option("--github_username", prompt="enter github username", default=github_username)
def bootstrap_cluster(ctx, cluster_name, github_username):
    ensure_encryption_key(cluster_name)
    key_arn = exec_command(f"aws kms describe-key --key-id {key_alias_name(cluster_name)} --query KeyMetadata.Arn --output text")
    echo_comment(f'key arn: {key_arn}')
    
    create_folder(ctx.create_cluster_dir, raise_ex_if_present=False)
    echo_comment('create the eksctl manifest ...')
    fn = Path(__file__).parent / 'res' / 'create_eks_cluster_template.yaml'
    with open(fn) as f:
        data = f.read()
        
    routeable_subnet_ids, non_routeable_subnet_ids = read_subnets()
    for idx, s_id in enumerate(routeable_subnet_ids):
        data = data.replace(f"<routable-{idx}>",  s_id)
        
    for idx, s_id in enumerate(non_routeable_subnet_ids):
        data = data.replace(f"<non-routable-{idx}>",  s_id)
    
    data = data.replace("<cluster-name>", cluster_name)
    data = data.replace("<key-arn>", key_arn)
        
    with open(ctx.path_to_create_cluster_yaml, 'wt') as f:
        f.write(data)
     
    eksctl_create_cmd = f"eksctl create cluster -f '{ctx.path_to_create_cluster_yaml}'"
    exec_command(eksctl_create_cmd)
    
    
def read_subnets():
    ec2_client = boto3.client("ec2")
    routeable_items = ec2_client.describe_subnets(Filters = [{'Name': 'tag:Subnet', 'Values': ['private-routable'] }])['Subnets'] 
    routable_subnet_ids =  [item['SubnetId'] for item in routeable_items]
    
    non_routeable_items = ec2_client.describe_subnets(Filters = [{'Name': 'tag:Subnet', 'Values': ['private-nonroutable'] }])['Subnets'] 
    non_routable_subnet_ids = [item['SubnetId'] for item in non_routeable_items]
    
    #we expect exactly 3 subnets, one for each AZ
    assert(len(routable_subnet_ids) == 3)
    assert(len(non_routable_subnet_ids) == 3)
    
    return (routable_subnet_ids, non_routable_subnet_ids)
    
        
def key_alias_name(cluster_name):
    return f'alias/eks_key_{cluster_name}'

def ensure_encryption_key(cluster_name):
    iam_client = boto3.resource('iam')

    kms_client = boto3.client('kms')
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    
    key_arn = f"arn:aws:kms:eu-central-1:{account_id}:alias/{key_alias_name(cluster_name)}"

    try:
        kms_client.describe_key(KeyId=key_arn)
        echo_comment("key found, nothing to do ...")
    except kms_client.meta.client.exceptions.NotFoundException as ex:
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
    #exec_command(f"git clone {ssh_repo_url}")
    exec_command("kubectl create namespace crossplane-system")
    install_helm_app("crossplane", "crossplane-system", "crossplane", "crossplane", "https://charts.crossplane.io/stable", "1.6.2")
    
    
def install_helm_app(name, target_namespace, chart, release_name, repo_url, target_revision, path_to_app="clusters/infra", params=None, sync_wave=None, auto_commit=True):
    
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
        commit_and_push_env_repo_changes(f"install argo helm app {name}")
    
    
def install_argo_app(name, target_namespace, repo_url, path, path_to_app="clusters/infra", sync_wave=None):
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
    
def commit_and_push_env_repo_changes(message):
    exec_command(f'cd {cluster_name} && git add . && git commit -m "{message}" && git push')
    

@cli.command()
@pass_ctx
def configure_sa_and_aws_provider(ctx):
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
    install_argo_app(app_name, "default",  https_repo_url, "infra/aws-provider-config")
    commit_and_push_env_repo_changes(f"install argo app {app_name}")
    
def ensure_role_for_crossplane_provider(ctx, role_name):
    oidc_provider = do_query_oidc_provider()
    
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
    except iam.meta.client.exceptions.NoSuchEntityException as ex:
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
    policy_name, policy_arn = ensure_alb_controller_policy(ctx)
    
    app_name = "alb-controller-service-account"
    install_argo_app(app_name, "kube-system",  https_repo_url, f"infra/{app_name}", sync_wave="-1")
    
    fn = Path(__file__).parent / 'res' / 'alb_controller' / 'service_account_and_role_template.yaml'
    with open(fn) as f:
        data = f.read()
        
    data = data.replace("<account-id>", ctx.account_id)
    data = data.replace("<role-name>", f"AmazonEKSLoadBalancerControllerRole-{cluster_name}".lower())
    data = data.replace("<oidc-provider>", do_query_oidc_provider())
    data = data.replace("<policy-arn>", policy_arn)
    
    
    path_to_folder = f"{cluster_name}/infra/{app_name}"
    create_folder(path_to_folder)
    path_to_manifest = os.path.join(path_to_folder, "manifest.yaml")
    
    with open(path_to_manifest, 'wt') as f:
        f.write(data)
        
    install_helm_app("cert-manager", "cert-manager", "cert-manager", "cert-manager", "https://charts.jetstack.io", "v1.7.1", sync_wave="-1", params=[("installCRDs", "true")], auto_commit=False)
    
    alb_controller_params = [
        ("image.repository", "602401143452.dkr.ecr.eu-central-1.amazonaws.com/amazon/aws-load-balancer-controller"),
        ("clusterName", cluster_name),
        ("serviceAccount.create", "false"),
        ("serviceAccount.name", "aws-load-balancer-controller")
    ]
    install_helm_app("aws-load-balancer-controller", "kube-system", "aws-load-balancer-controller", "aws-load-balancer-controller", "https://aws.github.io/eks-charts", "1.3.3", params=alb_controller_params, auto_commit=False)
    
    commit_and_push_env_repo_changes(f"install argo app {app_name}")
    

def ensure_alb_controller_policy(ctx):
    policy_name = "AWSLoadBalancerControllerAdditionalIAMPolicy"
    account_id = ctx.account_id
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    iam = boto3.resource('iam')
    policy = iam.Policy(policy_arn)
    try:
        policy.load()
        echo_comment("policy found, nothing to do ...")
    except iam.meta.client.exceptions.NoSuchEntityException as ex:
        echo_comment("create policy for alb controller service account role")
        fn = Path(__file__).parent / 'res' / 'alb_controller' / 'iam_policy_v1_to_v2_additional.json'
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
def X_install_alb_controller(ctx):
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
@click.option("--github_username", prompt="enter github username", default=github_username)
def install_argo(ctx, github_username):
    exec_command("kubectl create namespace argocd")
    exec_command("kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
    
    time.sleep(30)
    
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
    exec_comand(f"kubectl apply -f {cm_patch_yaml}")
    
    
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
    do_query_oidc_provider()


def do_query_oidc_provider():
    click.echo(f"current context is {cluster_name}")
    return exec_command(f'aws eks describe-cluster --name {cluster_name} --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///"').strip()

@cli.command()
@pass_ctx
def X_current(ctx):
    click.echo(f"current context is {ctx.cluster_name}")
    

cluster_config = {
    "dev":  "i-053c02913aa8a8eee@gitops-poc-dev.eu-central-1.eksctl.io",
    "test": "i-053c02913aa8a8eee@gitops-poc-test.eu-central-1.eksctl.io",
    "prod": "i-053c02913aa8a8eee@gitops-poc-prod.eu-central-1.eksctl.io"
}

@cli.command()
@pass_ctx
@click.option("--cluster", prompt="environment (dev, test, prod)")
def X_switch_cluster(ctx, cluster):
    cmd = f"kubectl config use-context {cluster_config[cluster]}"
    exec_command(cmd)
    
    
@cli.command()
@pass_ctx
def X_current_cluster(ctx):
    found_cluster = exec_command("kubectl config current-context")
    for env, cluster in cluster_config.items():
        if cluster == found_cluster:
            click.echo(f"current cluster context is: {env}")
            return
        
    click.echo(f"unkonwn cluster found")


