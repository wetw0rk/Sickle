import os

class Colors():
    """Colors used within sickle, when used on the Windows platform the user must set the
    appropriate registry key. Once done os.system must be executed with the command color.
    """

    RED     = '\033[31m'
    BLUE    = '\033[94m'
    BOLD    = '\033[1m'
    YELLOW  = '\033[93m'
    GREEN   = '\033[32m'
    END     = '\033[0m'

    def __init__(self):

        if (os.name != 'posix'):
            os.system('color')
        pass

    def get_color_count(string):
        """Returns the number of color occurences in a string.

        :param string: The string containing color highlighting
        :type string: str

        :return: Number of color strings identified in the string
        :rtype: int
        """

        count = \
        (
            string.count(Colors.BOLD)   * len(Colors.BOLD) +
            string.count(Colors.BLUE)   * len(Colors.BLUE) + 
            string.count(Colors.GREEN)  * len(Colors.GREEN) +
            string.count(Colors.RED)    * len(Colors.RED) +
            string.count(Colors.YELLOW) * len(Colors.YELLOW) +
            string.count(Colors.END)    * len(Colors.END)
        )

        return count

def ansi_center(string, width, fillchar=' '):
    """Centers strings containing colors

    :param string: The string containing color highlighting
    :type string: str

    :param width: The width in which to center the string
    :type width: int

    :param fillchar: Padding to use on left and right side of centering
    :type fillchar: str

    :return: The formatted string
    :rtype: str
    """

    color_size = Colors.get_color_count(string)

    # If we can't add any padding simply return the string
    if (len(string) > width):
        return string

    # Calculate the total bytes that we will inject into the final string
    string_len = len(string) - color_size
    total_fill = int(width - string_len)
    rstring = ""

    # Since we are centering we want to add and prepend the same amount of
    # bytes
    filler_padding = int(total_fill / 2)

    # If we are dealing with an odd number prepend an additional space
    prepend = 0
    if ((total_fill % 2) != 0):
        prepend = 1

    # Generate the centered string
    rstring += fillchar * (filler_padding + prepend)
    rstring += string
    rstring += fillchar * filler_padding

    return rstring

def ansi_ljust(string, width, fillchar=' '):
    """Adds padding to the right of the string for formatting

    :param string: The string containing color highlighting
    :type string: str

    :param width: The amount of padding to append to the string
    :type width: int

    :param fillchar: Padding to use on the right side of string
    :type fillchar: str

    :return: The formatted string
    :rtype: str
    """

    color_size = Colors.get_color_count(string)

    string_len = len(string) - color_size
    total_fill = int(width - string_len)
  
    if ((total_fill > 0) and (string_len != width)):
        return (string + (fillchar * total_fill))
    else:
        return string

def ansi_rjust(string, width, fillchar=' '):
    """Adds padding to the right of the string for formatting

    :param string: The string containing color highlighting
    :type string: str

    :param width: The amount of padding to prepend to the string
    :type width: int

    :param fillchar: Padding to use on the left side of the string
    :type fillchar: str

    :return: The formatted string
    :rtype: str
    """

    color_size = Colors.get_color_count(string)

    string_len = len(string) - color_size
    total_fill = int(width - string_len)
  
    if ((total_fill > 0) and (string_len != width)):
        return ((fillchar * total_fill) + string)
    else:
        return string
