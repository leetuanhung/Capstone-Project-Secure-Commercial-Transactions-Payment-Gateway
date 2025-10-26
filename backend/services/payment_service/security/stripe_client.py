"""
Stripe Payment Gateway Client
Secure integration with Stripe API for payment processing
"""
import stripe
import os
from typing import Dict, Optional, List
from datetime import datetime

class StripeClient:
    def __init__(self, api_key: Optional[str] = None, public_key: Optional[str] = None):
        """
        Initialize Stripe client
        
        Args:
            api_key: Stripe Secret Key (sk_test_... or sk_live_...)
            public_key: Stripe Public Key (pk_test_... or pk_live_...)
        """
        self.api_key = api_key or os.getenv('Stripe_Secret_Key')
        self.public_key = public_key or os.getenv('Stripe_Public_Key')
        
        if not self.api_key:
            raise ValueError("Stripe API key is required")
        
        stripe.api_key = self.api_key
        self.customers = {}  # Cache for customer objects
    
    def create_payment_intent(self, amount: float, currency: str = 'usd',
                             customer_id: Optional[str] = None,
                             metadata: Optional[Dict] = None,
                             payment_method: Optional[str] = None) -> Dict:
        """
        Create a payment intent
        
        Args:
            amount: Amount in smallest currency unit (cents for USD)
            currency: Currency code (usd, eur, etc.)
            customer_id: Stripe customer ID
            metadata: Additional data to attach
            payment_method: Payment method ID
        
        Returns:
            Payment intent object
        """
        try:
            # Convert to smallest currency unit (cents)
            amount_cents = int(amount * 100)
            
            intent_params = {
                'amount': amount_cents,
                'currency': currency.lower(),
                'metadata': metadata or {}
            }
            
            if customer_id:
                intent_params['customer'] = customer_id
            
            if payment_method:
                intent_params['payment_method'] = payment_method
                intent_params['confirm'] = True
            
            payment_intent = stripe.PaymentIntent.create(**intent_params)
            
            return {
                'id': payment_intent.id,
                'client_secret': payment_intent.client_secret,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency,
                'status': payment_intent.status,
                'payment_method': payment_intent.payment_method,
                'created': payment_intent.created
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def confirm_payment_intent(self, payment_intent_id: str,
                              payment_method: Optional[str] = None) -> Dict:
        """
        Confirm a payment intent
        
        Args:
            payment_intent_id: Payment intent ID
            payment_method: Payment method ID
        
        Returns:
            Confirmed payment intent
        """
        try:
            params = {}
            if payment_method:
                params['payment_method'] = payment_method
            
            payment_intent = stripe.PaymentIntent.confirm(
                payment_intent_id,
                **params
            )
            
            return {
                'id': payment_intent.id,
                'status': payment_intent.status,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def create_payment_method(self, card_token: str,
                             billing_details: Optional[Dict] = None) -> Dict:
        """
        Create a payment method from card token
        
        Args:
            card_token: Card token from Stripe.js
            billing_details: Billing information
        
        Returns:
            Payment method object
        """
        try:
            params = {
                'type': 'card',
                'card': {'token': card_token}
            }
            
            if billing_details:
                params['billing_details'] = billing_details
            
            payment_method = stripe.PaymentMethod.create(**params)
            
            return {
                'id': payment_method.id,
                'type': payment_method.type,
                'card': {
                    'brand': payment_method.card.brand,
                    'last4': payment_method.card.last4,
                    'exp_month': payment_method.card.exp_month,
                    'exp_year': payment_method.card.exp_year
                }
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def create_customer(self, email: str, name: Optional[str] = None,
                       phone: Optional[str] = None,
                       metadata: Optional[Dict] = None) -> Dict:
        """
        Create a Stripe customer
        
        Args:
            email: Customer email
            name: Customer name
            phone: Customer phone
            metadata: Additional metadata
        
        Returns:
            Customer object
        """
        try:
            params = {
                'email': email,
                'metadata': metadata or {}
            }
            
            if name:
                params['name'] = name
            if phone:
                params['phone'] = phone
            
            customer = stripe.Customer.create(**params)
            
            # Cache customer
            self.customers[customer.id] = customer
            
            return {
                'id': customer.id,
                'email': customer.email,
                'name': customer.name,
                'created': customer.created
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def attach_payment_method(self, payment_method_id: str,
                             customer_id: str) -> Dict:
        """
        Attach payment method to customer
        
        Args:
            payment_method_id: Payment method ID
            customer_id: Customer ID
        
        Returns:
            Attached payment method
        """
        try:
            payment_method = stripe.PaymentMethod.attach(
                payment_method_id,
                customer=customer_id
            )
            
            return {
                'id': payment_method.id,
                'customer': payment_method.customer,
                'type': payment_method.type
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def charge_customer(self, amount: float, customer_id: str,
                       currency: str = 'usd',
                       payment_method_id: Optional[str] = None,
                       description: Optional[str] = None,
                       metadata: Optional[Dict] = None) -> Dict:
        """
        Charge a customer
        
        Args:
            amount: Amount to charge
            customer_id: Stripe customer ID
            currency: Currency code
            payment_method_id: Specific payment method (optional)
            description: Charge description
            metadata: Additional metadata
        
        Returns:
            Payment result
        """
        try:
            # Create payment intent
            intent_params = {
                'amount': amount,
                'currency': currency,
                'customer': customer_id,
                'metadata': metadata or {}
            }
            
            if description:
                intent_params['description'] = description
            
            if payment_method_id:
                intent_params['payment_method'] = payment_method_id
                intent_params['confirm'] = True
                intent_params['off_session'] = True
            
            payment_intent = self.create_payment_intent(**intent_params)
            
            return payment_intent
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def create_refund(self, payment_intent_id: str,
                     amount: Optional[int] = None,
                     reason: Optional[str] = None) -> Dict:
        """
        Create a refund
        
        Args:
            payment_intent_id: Payment intent ID to refund
            amount: Amount to refund (None for full refund)
            reason: Refund reason
        
        Returns:
            Refund object
        """
        try:
            params = {
                'payment_intent': payment_intent_id
            }
            
            if amount:
                params['amount'] = amount
            
            if reason:
                params['reason'] = reason
            
            refund = stripe.Refund.create(**params)
            
            return {
                'id': refund.id,
                'amount': refund.amount,
                'currency': refund.currency,
                'status': refund.status,
                'reason': refund.reason
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def retrieve_payment_intent(self, payment_intent_id: str) -> Dict:
        """Retrieve payment intent details"""
        try:
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            
            return {
                'id': payment_intent.id,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency,
                'status': payment_intent.status,
                'customer': payment_intent.customer,
                'payment_method': payment_intent.payment_method,
                'created': payment_intent.created
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def list_customer_payment_methods(self, customer_id: str) -> List[Dict]:
        """List all payment methods for a customer"""
        try:
            payment_methods = stripe.PaymentMethod.list(
                customer=customer_id,
                type='card'
            )
            
            return [
                {
                    'id': pm.id,
                    'type': pm.type,
                    'card': {
                        'brand': pm.card.brand,
                        'last4': pm.card.last4,
                        'exp_month': pm.card.exp_month,
                        'exp_year': pm.card.exp_year
                    }
                }
                for pm in payment_methods.data
            ]
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def cancel_payment_intent(self, payment_intent_id: str) -> Dict:
        """Cancel a payment intent"""
        try:
            payment_intent = stripe.PaymentIntent.cancel(payment_intent_id)
            
            return {
                'id': payment_intent.id,
                'status': payment_intent.status
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def create_subscription(self, customer_id: str, price_id: str,
                           metadata: Optional[Dict] = None) -> Dict:
        """
        Create a subscription
        
        Args:
            customer_id: Customer ID
            price_id: Price ID
            metadata: Additional metadata
        
        Returns:
            Subscription object
        """
        try:
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{'price': price_id}],
                metadata=metadata or {}
            )
            
            return {
                'id': subscription.id,
                'status': subscription.status,
                'customer': subscription.customer,
                'current_period_end': subscription.current_period_end
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def handle_webhook(self, payload: bytes, sig_header: str,
                      webhook_secret: str) -> Dict:
        """
        Handle Stripe webhook
        
        Args:
            payload: Request body
            sig_header: Stripe-Signature header
            webhook_secret: Webhook signing secret
        
        Returns:
            Webhook event
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
            
            return {
                'id': event.id,
                'type': event.type,
                'data': event.data.object
            }
        except ValueError as e:
            raise Exception(f"Invalid payload: {str(e)}")
        except stripe.error.SignatureVerificationError as e:
            raise Exception(f"Invalid signature: {str(e)}")
    
    def create_charge_with_3ds(self, amount: float, payment_method_id: str,
                               customer_id: str, return_url: str,
                               currency: str = 'usd',
                               metadata: Optional[Dict] = None) -> Dict:
        """
        Create charge with 3D Secure authentication
        
        Args:
            amount: Amount to charge
            payment_method_id: Payment method ID
            customer_id: Customer ID
            return_url: URL to return after 3DS
            currency: Currency code
            metadata: Additional metadata
        
        Returns:
            Payment intent with 3DS status
        """
        try:
            amount_cents = int(amount * 100)
            
            payment_intent = stripe.PaymentIntent.create(
                amount=amount_cents,
                currency=currency,
                customer=customer_id,
                payment_method=payment_method_id,
                confirmation_method='automatic',
                confirm=True,
                return_url=return_url,
                metadata=metadata or {}
            )
            
            return {
                'id': payment_intent.id,
                'status': payment_intent.status,
                'client_secret': payment_intent.client_secret,
                'next_action': payment_intent.next_action,
                'requires_action': payment_intent.status == 'requires_action'
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")
    
    def get_balance(self) -> Dict:
        """Get account balance"""
        try:
            balance = stripe.Balance.retrieve()
            
            return {
                'available': balance.available,
                'pending': balance.pending,
                'livemode': balance.livemode
            }
        except stripe.error.StripeError as e:
            raise Exception(f"Stripe error: {str(e)}")

# Singleton instance
stripe_client = StripeClient()