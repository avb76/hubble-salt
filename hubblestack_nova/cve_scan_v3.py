import requests


def __virtual__():
    return True


def _get_pkgs_list():
    pkgs = __salt__['pkg.list_pkgs']()
    return ['{0}-{1}'.format(pkg, pkgs[pkg]) for pkg in pkgs]


def _vulners_query(pkg_list, url='https://vulners.com/api/v3/audit/audit/'):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    data = {
        "os": "centos",
        "package": pkg_list,
        "version": "7"
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


def audit():
    return _vulners_query(_get_pkgs_list())
