import json
import logging
import shutil
import subprocess

from colorama import init, Fore


# Read data from files
def open_file(file_path):
    with open(file_path) as f:
        return json.load(f)


class ExtensiveRolesChecker(object):
    def __init__(self, json_file, role_kind):
        init()
        self._role = logging.getLogger(role_kind)
        self._role_handler = logging.StreamHandler()
        self._role_format = logging.Formatter(f'{Fore.YELLOW}[!][%(name)s]{Fore.WHITE}\u2192 %(message)s')
        self._role_handler.setFormatter(self._role_format)
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


def get_cluster_roles_and_bindings():
    with open('roles.json') as roles_file:
        roles = subprocess.run(['kubectl', 'get', 'roles', '--all-namespaces', '-o', 'json'],
                               capture_output=True,
                               check=True)
        roles_data = json.load(roles.stdout)
        json.dump(roles_data, roles_file, indent=4)

    with open('clusterroles.json') as clusterroles_file:
        cluster_roles = subprocess.run(['kubectl', 'get', 'clusterroles', '-o', 'json'],
                                       capture_output=True,
                                       check=True)
        cluster_roles_data = json.load(cluster_roles.stdout)
        json.dump(cluster_roles_data, clusterroles_file, indent=4)

    with open('rolebindings.json') as rolebindings_file:
        role_bindings = subprocess.run(['kubectl', 'get', 'rolebindings', '--all-namespaces', '-o', 'json'],
                                       capture_output=True,
                                       check=True)
        role_bindings_data = json.load(role_bindings.stdout)
        json.dump(role_bindings_data, rolebindings_file, indent=4)

    with open('clusterrolebindings.json') as clusterrolebindings_file:
        cluster_role_bindings = subprocess.run(['kubectl', 'get', 'clusterrolebindings', '-o', 'json'],
                                               capture_output=True,
                                               check=True)
        cluster_role_bindings_data = json.load(cluster_role_bindings.stdout)
        json.dump(cluster_role_bindings_data, clusterrolebindings_file, indent=4)


def process_cluster_roles_and_binding_files():
    if len('roles.json') != 0 and len('clusterrolebindings.json') != 0 and len('clusterrolebindings.json') != 0 \
            and len('rolebindings.json') != 0:
        print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoles:')
        role_kind = 'ClusterRole'
        cluster_role_json_file = open_file('clusterroles.json')
        extensive_cluster_roles_checker = ExtensiveRolesChecker(cluster_role_json_file, role_kind)
        extensive_cluster_roles = [result for result in extensive_cluster_roles_checker.results]

        print(f'{Fore.WHITE}[*] Started enumerating risky Roles:')
        role_kind = 'Role'
        role_json_file = open_file('roles.json')
        extensive_roles_checker = ExtensiveRolesChecker(role_json_file, role_kind)
        extensive_roles = [result for result in extensive_roles_checker.results
                           if result not in extensive_cluster_roles]
        extensive_roles = extensive_roles + extensive_cluster_roles

        print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoleBinding:')
        bind_kind = 'ClusterRoleBinding'
        cluster_role_binding_json_file = open_file('clusterrolebindings.json')
        extensive_cluster_role_bindings = RoleBingingChecker(cluster_role_binding_json_file, extensive_roles, bind_kind)

        print(f'{Fore.WHITE}[*] Started enumerating risky RoleRoleBindings:')
        bind_kind = 'RoleBinding'
        role_binding_json_file = open_file('rolebindings.json')
        extensive_role_bindings = RoleBingingChecker(role_binding_json_file, extensive_roles, bind_kind)
        print(f"{Fore.WHITE}Extensive role bindings: {extensive_role_bindings}")
        print(f"{Fore.WHITE}Extensive cluster role bindings: {extensive_cluster_role_bindings}")
        print(f"{Fore.WHITE}Extensive roles: {extensive_roles}")
        print(f"{Fore.WHITE}Extensive role bindings: {extensive_role_bindings}")
    else:
        print(f"{Fore.RED}Could not find roles.json, clusterrolebindings.json, clusterrolebindings.json "
              f"or rolebindings.json !")


if __name__ == '__main__':
    kubectl = shutil.which('kubectl')
    if kubectl is None:
        print(f'{Fore.RED}[!] kubectl not found')
        exit(1)

    get_cluster_roles_and_bindings()
    process_cluster_roles_and_binding_files()
