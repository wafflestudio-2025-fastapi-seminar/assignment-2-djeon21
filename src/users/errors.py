from src.common import CustomException

class InvalidPasswordException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_002",
            error_message="INVALID PASSWORD"
        )
        
class InvalidPhoneNumberException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422, 
            error_code="ERR_003", 
            error_message="INVALID PHONE NUMBER"
        )

class BioTooLongException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422, 
            error_code="ERR_004", 
            error_message="BIO TOO LONG"
        )

class EmailAlreadyExistsException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=409, 
            error_code="ERR_005", 
            error_message="EMAIL ALREADY EXISTS"
        )
        
class InvalidSessionException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401, 
            error_code="ERR_006", 
            error_message="INVALID SESSION"
        )

class BadAuthorizationHeaderException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=400, 
            error_code="ERR_007", 
            error_message="BAD AUTHORIZATION HEADER"
        )

class InvalidTokenException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401, 
            error_code="ERR_008", 
            error_message="INVALID TOKEN"
        )

class UnauthenticatedException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401, 
            error_code="ERR_009", 
            error_message="UNAUTHENTICATED"
        )
        
class InvalidAccountException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401, 
            error_code="ERR_010", 
            error_message="Invalid Account"
        )