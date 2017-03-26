import requests
import platform
import sys


def __virtual__():
    return not sys.platform.startswith('win')


def _get_local_packages():
    local_packages = __salt__['pkg.list_pkgs']()
    return ['{0}-{1}'.format(pkg, local_packages[pkg]) for pkg in local_packages]


def _vulners_query(packages, url='https://vulners.com/api/v3/audit/audit/'):
    (os, version, _) = platform.dist()

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    data = {
        "os": os,
        "package": packages,
        "version": version
    }

    try:
        response = requests.post(url=url, headers=headers, json=data)
        return response.json()
    except requests.Timeout:
        return {
            'result': 'ERROR',
            'data': {
                'error': 'Request to {0} timed out'.format(url)
            }
        }


def _process_vulners(vulners):
    return vulners


def audit(data_list, tags, debug=False):
    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    # get the vulnerable packages on the system
    vulners = _vulners_query(_get_local_packages()).get('data').get('packages')
    ret['Failure'] = _process_vulners(vulners)

    return ret
