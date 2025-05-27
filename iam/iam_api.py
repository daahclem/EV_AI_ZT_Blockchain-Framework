"""
IAM API for authentication and authorization logic
Supports RBAC, ABAC, MAC policies for simulation
"""
import random

def authenticate_user(credentials, mfa_enabled):
    # Simulate MFA and credential check
    if mfa_enabled and credentials.get('mfa_code') != '123456':
        return False
    # Accept any username/password for demo
    return True

def authorize_user(user, risk_score, policy, context=None):
    """
    Simulated authorization logic for IAM policies:
    - RBAC: Allow if user role is 'user' and risk is low (<0.5)
    - ABAC: Allow if location starts with 'Charger' and risk is <0.6
    - MAC: Allow only if risk is very low (<0.3)
    - DAC: Allow if user is owner (DriverA) and risk is moderate (<0.7)
    """
    if policy == 'RBAC':
        return user.get('role', 'user') == 'user' and risk_score < 0.5
    if policy == 'ABAC':
        return context and context.get('location', '').startswith('Charger') and risk_score < 0.6
    if policy == 'MAC':
        return risk_score < 0.3
    if policy == 'DAC':
        return user.get('role', '') == 'DriverA' and risk_score < 0.7
    return False
