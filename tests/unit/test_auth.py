
try:
    import mock
except ImportError:  # pragma: NO COVER
    from unittest import mock

import pandas_gbq.auth


def test_get_user_credentials_path_w_env_var():
    env = {'PANDAS_GBQ_CREDENTIALS_FILE': '/tmp/dummy.dat'}
    with mock.patch.dict('os.environ', env):
        default_credentials_path = pandas_gbq.auth.get_user_credentials_path()
        assert default_credentials_path == '/tmp/dummy.dat'
