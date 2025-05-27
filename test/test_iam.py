import unittest
from iam.iam_api import authenticate_user, authorize_user

class TestIAM(unittest.TestCase):
    def test_authenticate_user(self):
        creds = {'user': 'user1', 'password': 'test', 'mfa_code': '123456'}
        self.assertTrue(authenticate_user(creds, mfa_enabled=True))
        creds['password'] = 'wrong'
        self.assertFalse(authenticate_user(creds, mfa_enabled=True))

    def test_authorize_user(self):
        user = {'username': 'user1', 'role': 'DriverA', 'risk_profile': 'low'}
        risk = 0.1
        self.assertTrue(authorize_user(user, risk, 'RBAC', {'location': 'Charger001'}))
        risk = 0.95
        self.assertFalse(authorize_user(user, risk, 'RBAC', {'location': 'Charger001'}))

if __name__ == '__main__':
    unittest.main()
