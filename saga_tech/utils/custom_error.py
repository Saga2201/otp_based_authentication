class FailedToLogin(Exception):
    def __init__(self, message):
        self.message = message

    internal_error_code = 400


class OTPExpired(Exception):
    def __init__(self, message):
        self.message = message

    internal_error_code = 400


class EmailSecretCode(Exception):
    def __init__(self, message):
        self.message = message

    internal_error_code = 400
