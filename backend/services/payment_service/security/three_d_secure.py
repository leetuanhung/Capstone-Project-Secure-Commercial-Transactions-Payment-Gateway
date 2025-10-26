"""
3D Secure 2.0 Implementation (3DS2)
Strong Customer Authentication (SCA) for PSD2 compliance
"""
from typing import Dict, Optional
from datetime import datetime, timedelta
import secrets
import hashlib

class ThreeDSecure:
    def __init__(self):
        self.challenges = {}
        self.authentication_results = {}
        
    def initiate_authentication(self, transaction: Dict) -> Dict:
        """
        Initiate 3DS authentication flow
        
        Args:
            transaction: {
                'amount': float,
                'currency': str,
                'merchant_id': str,
                'merchant_name': str,
                'transaction_id': str,
                'email': str,
                'phone': str,
                'device_channel': str (browser/app/3ri),
                'first_transaction': bool,
                'new_device': bool,
                'unusual_location': bool
            }
        
        Returns:
            Authentication request with session details
        """
        # Perform risk assessment
        risk_score = self._assess_risk(transaction)
        
        # Determine if challenge is required
        challenge_required = self._is_challenge_required(risk_score, transaction)
        
        # Generate 3DS session
        three_ds_session_id = f"3ds_{secrets.token_urlsafe(32)}"
        
        # Create authentication request
        auth_request = {
            'three_ds_session_id': three_ds_session_id,
            'three_ds_version': '2.2.0',
            'challenge_required': challenge_required,
            'challenge_type': self._determine_challenge_type(risk_score),
            'device_channel': transaction.get('device_channel', 'browser'),
            'merchant_data': {
                'merchant_id': transaction.get('merchant_id'),
                'merchant_name': transaction.get('merchant_name'),
                'transaction_id': transaction.get('transaction_id')
            },
            'transaction_data': {
                'amount': transaction.get('amount'),
                'currency': transaction.get('currency', 'USD'),
                'timestamp': datetime.utcnow().isoformat()
            },
            'cardholder_data': {
                'email': transaction.get('email'),
                'phone': transaction.get('phone'),
                'billing_address': transaction.get('billing_address')
            },
            'device_info': self._collect_device_info(transaction),
            'risk_score': risk_score
        }
        
        # Store challenge session
        self.challenges[three_ds_session_id] = {
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=10),
            'transaction': transaction,
            'auth_request': auth_request,
            'attempts': 0,
            'max_attempts': 3
        }
        
        return auth_request
    
    def _assess_risk(self, transaction: Dict) -> int:
        """
        Assess transaction risk for 3DS
        Returns risk score 0-100
        """
        risk_score = 0
        
        # Amount-based risk
        amount = transaction.get('amount', 0)
        if amount > 1000:
            risk_score += 20
        elif amount > 500:
            risk_score += 10
        
        # New customer risk
        if transaction.get('first_transaction', False):
            risk_score += 15
        
        # Device risk
        if transaction.get('new_device', False):
            risk_score += 10
        
        # Location risk
        if transaction.get('unusual_location', False):
            risk_score += 15
        
        # High-risk merchant category
        high_risk_mccs = ['5967', '5966']  # Digital goods, telecom
        if transaction.get('merchant_category_code') in high_risk_mccs:
            risk_score += 10
        
        return min(risk_score, 100)
    
    def _is_challenge_required(self, risk_score: int, transaction: Dict) -> bool:
        """
        Determine if SCA challenge is required
        Considers exemptions and risk thresholds
        """
        # Check exemptions
        
        # Low-value exemption (under €30)
        if transaction.get('amount', 0) < 30 and transaction.get('currency') == 'EUR':
            return False
        
        # Trusted beneficiary exemption
        if transaction.get('whitelisted_merchant', False):
            return False
        
        # Transaction risk analysis exemption (low risk + under €500)
        if risk_score < 20 and transaction.get('amount', 0) < 500:
            return False
        
        # Corporate payment exemption
        if transaction.get('corporate_payment', False):
            return False
        
        # High risk or regulatory requirement
        if risk_score >= 50:
            return True
        
        # European Economic Area (EEA) requirement for PSD2
        if transaction.get('issuer_region') == 'EEA':
            return True
        
        return risk_score >= 30
    
    def _determine_challenge_type(self, risk_score: int) -> str:
        """Determine type of authentication challenge"""
        if risk_score >= 70:
            return 'OTP_SMS'  # One-Time Password via SMS
        elif risk_score >= 40:
            return 'OTP_EMAIL'  # One-Time Password via Email
        else:
            return 'BIOMETRIC'  # Fingerprint/Face ID
    
    def _collect_device_info(self, transaction: Dict) -> Dict:
        """Collect device information for risk assessment"""
        return {
            'device_id': transaction.get('device_id'),
            'ip_address': transaction.get('ip_address'),
            'user_agent': transaction.get('user_agent'),
            'browser_language': transaction.get('browser_language', 'en-US'),
            'screen_resolution': transaction.get('screen_resolution', '1920x1080'),
            'timezone_offset': transaction.get('timezone_offset', 0),
            'javascript_enabled': transaction.get('javascript_enabled', True),
            'cookies_enabled': transaction.get('cookies_enabled', True)
        }
    
    def verify_challenge(self, three_ds_session_id: str, 
                        challenge_response: str) -> Dict:
        """
        Verify 3DS challenge response
        
        Args:
            three_ds_session_id: Session ID from initiate_authentication
            challenge_response: OTP or biometric response from user
        
        Returns:
            Authentication result with CAVV and ECI
        """
        if three_ds_session_id not in self.challenges:
            return {
                'authenticated': False,
                'error': 'INVALID_SESSION',
                'eci': '07'  # ECI 07 = authentication failed
            }
        
        session = self.challenges[three_ds_session_id]
        
        # Check expiration
        if datetime.utcnow() > session['expires_at']:
            del self.challenges[three_ds_session_id]
            return {
                'authenticated': False,
                'error': 'SESSION_EXPIRED',
                'eci': '07'
            }
        
        # Check attempts
        session['attempts'] += 1
        if session['attempts'] > session['max_attempts']:
            del self.challenges[three_ds_session_id]
            return {
                'authenticated': False,
                'error': 'MAX_ATTEMPTS_EXCEEDED',
                'eci': '07'
            }
        
        # Verify challenge response
        is_valid = self._verify_otp(challenge_response, session)
        
        if is_valid:
            # Generate authentication value
            cavv = self._generate_cavv(session)
            eci = self._determine_eci(session['auth_request']['challenge_required'])
            
            result = {
                'authenticated': True,
                'three_ds_session_id': three_ds_session_id,
                'transaction_id': session['transaction']['transaction_id'],
                'authentication_value': cavv,
                'eci': eci,  # Electronic Commerce Indicator
                'three_ds_version': '2.2.0',
                'directory_server_id': f"DS_{secrets.token_hex(8)}",
                'timestamp': datetime.utcnow().isoformat(),
                'liability_shift': True
            }
            
            # Store result
            self.authentication_results[three_ds_session_id] = result
            
            # Clean up challenge
            del self.challenges[three_ds_session_id]
            
            return result
        else:
            return {
                'authenticated': False,
                'error': 'INVALID_RESPONSE',
                'eci': '07',
                'attempts_remaining': session['max_attempts'] - session['attempts']
            }
    
    def _verify_otp(self, response: str, session: Dict) -> bool:
        """Verify OTP response"""
        # In production, verify against sent OTP stored in session
        stored_otp = session.get('otp')
        
        if stored_otp:
            # Check if OTP matches and not expired
            otp_sent_at = session.get('otp_sent_at')
            if otp_sent_at and datetime.utcnow() - otp_sent_at > timedelta(minutes=5):
                return False  # OTP expired
            return response == stored_otp
        
        # For demo, accept any 6-digit code
        return len(response) == 6 and response.isdigit()
    
    def _generate_cavv(self, session: Dict) -> str:
        """
        Generate Cardholder Authentication Verification Value (CAVV)
        Cryptographic proof of authentication
        """
        data = f"{session['transaction']['transaction_id']}{datetime.utcnow().isoformat()}"
        cavv = hashlib.sha256(data.encode()).hexdigest()[:28]
        return cavv
    
    def _determine_eci(self, challenge_required: bool) -> str:
        """
        Determine Electronic Commerce Indicator (ECI)
        Indicates authentication result and liability shift
        
        ECI Values:
        - 05: Full authentication with challenge (liability shift)
        - 06: Attempted authentication/frictionless (attempted)
        - 07: Authentication failed
        """
        if challenge_required:
            return '05'  # ECI 05 = Full authentication (liability shift)
        else:
            return '06'  # ECI 06 = Merchant authentication (attempted)
    
    def frictionless_authentication(self, transaction: Dict) -> Dict:
        """
        Attempt frictionless (no-challenge) authentication
        Used for low-risk transactions
        
        Args:
            transaction: Transaction data
        
        Returns:
            Authentication result or challenge request
        """
        risk_score = self._assess_risk(transaction)
        
        if risk_score < 20:
            # Generate frictionless auth result
            three_ds_session_id = f"3ds_{secrets.token_urlsafe(32)}"
            
            result = {
                'authenticated': True,
                'three_ds_session_id': three_ds_session_id,
                'transaction_id': transaction['transaction_id'],
                'authentication_value': self._generate_cavv({'transaction': transaction}),
                'eci': '06',  # Frictionless
                'three_ds_version': '2.2.0',
                'frictionless': True,
                'timestamp': datetime.utcnow().isoformat(),
                'liability_shift': True
            }
            
            self.authentication_results[three_ds_session_id] = result
            return result
        else:
            # Require challenge
            return self.initiate_authentication(transaction)
    
    def get_authentication_result(self, three_ds_session_id: str) -> Optional[Dict]:
        """Retrieve stored authentication result"""
        return self.authentication_results.get(three_ds_session_id)
    
    def send_challenge_otp(self, three_ds_session_id: str, method: str) -> Dict:
        """
        Send OTP challenge to cardholder
        
        Args:
            three_ds_session_id: Session ID
            method: 'SMS' or 'EMAIL'
        
        Returns:
            Send result
        """
        if three_ds_session_id not in self.challenges:
            return {'success': False, 'error': 'INVALID_SESSION'}
        
        session = self.challenges[three_ds_session_id]
        
        # Generate OTP
        otp = secrets.randbelow(1000000)
        otp_code = f"{otp:06d}"
        
        # Store OTP
        session['otp'] = otp_code
        session['otp_sent_at'] = datetime.utcnow()
        
        # Mock send (in production, integrate with SMS/Email service)
        if method == 'SMS':
            phone = session['transaction'].get('phone', 'MASKED')
            masked_phone = self._mask_phone(phone)
            return {
                'success': True,
                'message': f'OTP sent to {masked_phone}',
                'expires_in': 300,  # 5 minutes
                'otp_for_demo': otp_code  # Remove in production!
            }
        elif method == 'EMAIL':
            email = session['transaction'].get('email', 'MASKED')
            masked_email = self._mask_email(email)
            return {
                'success': True,
                'message': f'OTP sent to {masked_email}',
                'expires_in': 300,
                'otp_for_demo': otp_code  # Remove in production!
            }
        
        return {'success': False, 'error': 'INVALID_METHOD'}
    
    def _mask_phone(self, phone: str) -> str:
        """Mask phone number"""
        if len(phone) < 4:
            return '***'
        return phone[:3] + '***' + phone[-2:]
    
    def _mask_email(self, email: str) -> str:
        """Mask email"""
        if '@' not in email:
            return '***'
        local, domain = email.split('@')
        return local[0] + '***@' + domain
    
    def cancel_authentication(self, three_ds_session_id: str) -> bool:
        """Cancel an ongoing authentication session"""
        if three_ds_session_id in self.challenges:
            del self.challenges[three_ds_session_id]
            return True
        return False
    
    def get_session_status(self, three_ds_session_id: str) -> Dict:
        """Get status of authentication session"""
        if three_ds_session_id in self.challenges:
            session = self.challenges[three_ds_session_id]
            return {
                'status': 'PENDING',
                'created_at': session['created_at'].isoformat(),
                'expires_at': session['expires_at'].isoformat(),
                'attempts': session['attempts'],
                'max_attempts': session['max_attempts']
            }
        elif three_ds_session_id in self.authentication_results:
            return {
                'status': 'COMPLETED',
                'authenticated': True
            }
        else:
            return {
                'status': 'NOT_FOUND'
            }

# Singleton instance
three_d_secure = ThreeDSecure()