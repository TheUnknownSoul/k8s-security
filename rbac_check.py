import json
import logging
import os
import shutil
import subprocess
import sys
from colorama import init, Fore

import sys
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

root = logging.getLogger()
root.setLevel(logging.INFO)
if not root.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    fmt = logging.Formatter('%(message)s')
    h.setFormatter(fmt)
    root.addHandler(h)
# Read data from files
def open_file(file_path):
    with open(file_path) as f:
        return json.load(f)


class ExtensiveRolesChecker(object):
    def __init__(self, json_file, role_kind):
        self._role = logging.getLogger(role_kind)
        self._role.propagate = False
        self._role.setLevel(logging.INFO)
        self._role_handler = logging.StreamHandler(stream=sys.stdout)
        self._role_format = logging.Formatter(
            f'{Fore.YELLOW}[!][%(name)s]{Fore.WHITE}\u2192 %(message)s'
        )
        self._role_handler.setFormatter(self._role_format)
        # не дублировать хендлеры при повторных вызовах
        if not self._role.handlers:
            self._role.addHandler(self._role_handler)
        self._json_file = json_file
        self._results = {}
        self._generate()

    @property
    def results(self):
        return self._results

    def add_result(self, name, value):
        if not name:
            return
        if not (name in self._results.keys()):
            self._results[name] = [value]
        else:
            self._results[name].append(value)

    def _generate(self):
        for entity in self._json_file['items']:
            role_name = entity['metadata']['name']
            for rule in entity['rules']:
                if not rule.get('resources', None):
                    continue
                self.get_read_secrets(rule, role_name)
                self.cluster_admin_role(rule, role_name)
                self.any_resources(rule, role_name)
                self.any_verb(rule, role_name)
                self.high_risk_roles(rule, role_name)
                self.role_and_role_bindings(rule, role_name)
                self.create_pods(rule, role_name)
                self.pods_exec(rule, role_name)
                self.pods_attach(rule, role_name)

    # Read cluster secrets:
    def get_read_secrets(self, rule, role_name):
        verbs = ['*', 'get', 'list']
        if 'secrets' in rule['resources'] and any([sign for sign in verbs if sign in rule['verbs']]):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to list secrets!')
                self.add_result(filtered_name, 'Has permission to list secrets!')

    # Any roles
    def cluster_admin_role(self, rule, role_name):
        if '*' in rule['resources'] and '*' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has Admin-Cluster permission!')
                self.add_result(filtered_name, 'Has Admin-Cluster permission!')

    # get ANY verbs:
    def any_verb(self, rule, role_name):
        resources = ['secrets',
                     'pods',
                     'deployments',
                     'daemonsets',
                     'statefulsets',
                     'replicationcontrollers',
                     'replicasets',
                     'cronjobs',
                     'jobs',
                     'roles',
                     'clusterroles',
                     'rolebindings',
                     'clusterrolebindings',
                     'users',
                     'groups']
        found_sign = [sign for sign in resources if sign in rule['resources']]
        if not found_sign:
            return
        if '*' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(
                    f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to access {found_sign[0]} '
                                                     f'with any verb!')
                self.add_result(filtered_name, f'Has permission to access {found_sign[0]} with any verb!')

    def any_resources(self, rule, role_name):
        verbs = ['delete', 'deletecollection', 'create', 'list', 'get', 'impersonate']
        found_sign = [sign for sign in verbs if sign in rule['verbs']]
        if not found_sign:
            return
        if '*' in rule['resources']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(
                    f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to use {found_sign[0]} on any resource!')
                self.add_result(filtered_name, f'Has permission to use {found_sign[0]} on any resource')

    def high_risk_roles(self, rule, role_name):
        verb_actions = ['create', 'update']
        resources_attributes = ['deployments', 'daemonsets', 'statefulsets', 'replicationcontrollers', 'replicasets',
                                'jobs', 'cronjobs']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not found_attribute:
            return
        found_actions = [action for action in verb_actions if action in rule['verbs']]
        if not found_actions:
            return
        filtered_name = self.get_non_default_name(role_name)
        if filtered_name:
            self._role.warning(
                f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to {found_actions[0]} {found_attribute[0]}!')
            self.add_result(filtered_name, f'Has permission to {found_actions[0]} {found_attribute[0]}!')

    def role_and_role_bindings(self, rule, role_name):
        resources_attributes = ['rolebindings', 'roles', 'clusterrolebindings']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not found_attribute:
            return
        if 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(
                    f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to create {found_attribute[0]}!')
                self.add_result(filtered_name, f'Has permission to create {found_attribute[0]}!')

    def create_pods(self, rule, role_name):
        if 'pods' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to create pods!')
                self.add_result(filtered_name, 'Has permission to create pods!')

    def pods_exec(self, rule, role_name):
        if 'pods/exec' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to use pod exec!')
                self.add_result(filtered_name, 'Has permission to use pod exec!')

    def pods_attach(self, rule, role_name):
        if 'pods/attach' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to attach pods!')
                self.add_result(filtered_name, 'Has permission to attach pods!')

    @staticmethod
    def get_non_default_name(name):
        if not ((name[:7] == 'system:') or (name == 'edit') or (name == 'admin') or (name == 'cluster-admin') or (
                name == 'aws-node') or (name[:11] == 'kubernetes-')):
            return name


def print_role_binding_results(sub, role_name, bind_kind):
    if sub['kind'] == 'ServiceAccount':
        print(
            f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} is bounded to'
                                                                  f'{sub["name"]} ServiceAccount.')
    else:
        print(
            f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} '
                                                                  f'is bounded to the {sub["kind"]}:{sub["name"]}!')


class RoleBingingChecker(object):
    def __init__(self, json_file, extensive_roles, bind_kind):
        self._json_file = json_file
        self._extensive_roles = extensive_roles
        self._bind_kind = bind_kind
        self._results = []
        self.binds_check()

    def binds_check(self):
        role_binding_found = []
        for entity in self._json_file['items']:
            _role_name = entity['metadata']['name']
            _rol_ref = entity['roleRef']['name']
            if not entity.get('subjects', None):
                continue
            if _rol_ref in self._extensive_roles:
                role_binding_found.append(_rol_ref)
                for sub in entity['subjects']:
                    if not sub.get('name', None):
                        continue
                    print_role_binding_results(sub, _role_name, self._bind_kind)
        return role_binding_found

def _run_kubectl_json(args: list[str]) -> dict:
    """ДАЁТ живой прогресс: печатаем команду, ждём, потом парсим JSON."""
    logging.info(f"{Fore.WHITE}[*] running: kubectl {' '.join(args)}")
    # capture_output=True — тут окей, JSON придет целиком;
    # прогресс даем отдельной строкой выше.
    p = subprocess.run(["kubectl", *args, "-o", "json"],
                       capture_output=True, check=True)
                       

def get_cluster_roles_and_bindings():
    # создаём/переписываем файлы корректно
    roles_data              = _run_kubectl_json(["get", "roles", "--all-namespaces"])
    cluster_roles_data      = _run_kubectl_json(["get", "clusterroles"])
    role_bindings_data      = _run_kubectl_json(["get", "rolebindings", "--all-namespaces"])
    cluster_role_bind_data  = _run_kubectl_json(["get", "clusterrolebindings"])

    with open('roles.json', 'w') as roles_file:
        json.dump(roles_data, roles_file, indent=2)

    with open('clusterroles.json', 'w') as clusterroles_file:
        json.dump(cluster_roles_data, clusterroles_file, indent=2)

    with open('rolebindings.json', 'w') as rolebindings_file:
        json.dump(role_bindings_data, rolebindings_file, indent=2)

    with open('clusterrolebindings.json', 'w') as clusterrolebindings_file:
        json.dump(cluster_role_bind_data, clusterrolebindings_file, indent=2)


def process_cluster_roles_and_binding_files():
    required = [
        'roles.json',
        'clusterroles.json',
        'rolebindings.json',
        'clusterrolebindings.json'
    ]
    if not all(os.path.exists(p) for p in required):
        print(f"{Fore.RED}Missing one of required files: {', '.join(required)}")
        return
    # дальше — твоя логика без изменений
    print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoles:')
    role_kind = 'ClusterRole'
    cluster_role_json_file = open_file('clusterroles.json')
    extensive_cluster_roles_checker = ExtensiveRolesChecker(cluster_role_json_file, role_kind)
    extensive_cluster_roles = [result for result in extensive_cluster_roles_checker.results]

    print(f'{Fore.WHITE}[*] Started enumerating risky Roles:')
    role_kind = 'Role'
    role_json_file = open_file('roles.json')
    extensive_roles_checker = ExtensiveRolesChecker(role_json_file, role_kind)
    extensive_roles = [r for r in extensive_roles_checker.results if r not in extensive_cluster_roles]
    extensive_roles = extensive_roles + extensive_cluster_roles

    print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoleBinding:')
    bind_kind = 'ClusterRoleBinding'
    cluster_role_binding_json_file = open_file('clusterrolebindings.json')
    extensive_cluster_role_bindings = RoleBingingChecker(cluster_role_binding_json_file, extensive_roles, bind_kind)

    print(f'{Fore.WHITE}[*] Started enumerating risky RoleBindings:')
    bind_kind = 'RoleBinding'
    role_binding_json_file = open_file('rolebindings.json')
    extensive_role_bindings = RoleBingingChecker(role_binding_json_file, extensive_roles, bind_kind)
    print(f"{Fore.WHITE}Extensive roles: {extensive_roles}")
    print(f"{Fore.WHITE}Extensive role bindings: {extensive_role_bindings}")
    print(f"{Fore.WHITE}Extensive cluster role bindings: {extensive_cluster_role_bindings}")



if __name__ == '__main__':
    kubectl = shutil.which('kubectl')
    if kubectl is None:
        print(f'{Fore.RED}[!] kubectl not found'); sys.exit(1)

    print(f'{Fore.WHITE}[*] Fetching RBAC objects via kubectl…', flush=True)
    get_cluster_roles_and_bindings()

    print(f'{Fore.WHITE}[*] Processing JSON files…', flush=True)
    process_cluster_roles_and_binding_files()
