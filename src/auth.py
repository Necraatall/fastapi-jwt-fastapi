"""
jwt rest services
"""
from datetime import datetime, timedelta
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext



class AuthHandler():
    """
    AuthHandler
    """
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = 'hddtNoCzRVoda4zE2RK5AVFXV3c5yGCvRF5qTDQtWvoLwQu2G5pNEgY3yv9idZKc'

    def get_password_hash(self, password):
        """
        get_password_hash

        Args:
            password (String): password

        Returns:
            hash: hashed password
        """
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        """
        verify_password

        Args:
            plain_password (String): password unhashed
            hashed_password (Hashed String): password hashed

        Returns:
            pwd_context(plain_password, hashed_password) (self, user_id): 2 state of password
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        """
        encode_token

        Args:
            user_id

        Returns:
            (payload, self.secret, algoritm): Content of jwt code
        """
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=5),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def decode_token(self, token):
        """
        decode_token

        Args:
            token (HS256): hashed token

        Raises:
            HTTPException: Signature has expired
            HTTPException: Invalid token
        """
        try:
            payload = jwt.decode(token, self.secret, algoritms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)
    