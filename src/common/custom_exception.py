import http
import logging

logger = logging.getLogger('uvicorn.error')

class CustomException(Exception):
    def __init__(
        self,
        status_code: int = 500,
        error_code: str = "ERR_000",
        error_message: str = "Unexpected error occurred"
    ):
        if not isinstance(status_code, int) or not (100 <= status_code <= 599):
            logger.critical(f"Invalid status_code {status_code} provided to CustomException, defaulting to 500")
            self.status_code = 500
        else:
            self.status_code = status_code

        if not isinstance(error_code, str):
            logger.critical(f"Invalid error_code {error_code!r} provided to CustomException, defaulting to 'ERR_000'")
            self.error_code = "ERR_000"
        else:
            self.error_code = error_code

        if not isinstance(error_message, str):
            self.error_message = http.HTTPStatus(self.status_code).description
            logger.critical(
                f"Invalid error_message {error_message!r} provided to CustomException, "
                f"defaulting to '{self.error_message}'"
            )
        else:
            self.error_message = error_message
