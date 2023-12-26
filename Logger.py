class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Logger:
    @staticmethod
    def info(message):
        print(f"{Color.GREEN}[INFO] {message}{Color.END}")
    @staticmethod
    def warn(message):
        print(f"{Color.YELLOW}[WARN] {message}{Color.END}")
    @staticmethod
    def error(message):
        print(f"{Color.RED}[ERROR]{message}{Color.END}")
    @staticmethod
    def debug(message):
        print(f"{Color.BLUE}[DEBUG]{message}{Color.END}")
    @staticmethod
    def custom(message, level='CUSTOM'):
        print(f"{Color.PURPLE}[{level}] {message}{Color.END}")
    @staticmethod
    def text(message):
        print(message)


# examples
# Logger.info("This is an info message")
# Logger.warning("This is a warning message")
# Logger.error("This is an error message")
# Logger.debug("This is a debug message")
# Logger.custom("This is a custom message", "CUSTOM")