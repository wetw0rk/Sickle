from sickle.common import main_helper
from sickle.common import main_handler

def entry():
    """This function is responsible for obtaining the user provided arguments and
    passing them to the main_handler.py file.

    return: None
    rtype: None
    """

    arg_parser = main_helper.parser()

    coordinator = main_handler.Handle(arg_parser)
    coordinator.handle_args()

if __name__ == '__main__':
    entry()
