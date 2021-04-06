class DragoneyeException(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        if errors is None:
            errors = []
        self.errors = errors
