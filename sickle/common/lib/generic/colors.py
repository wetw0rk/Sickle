'''

colors: Colors used within sickle, in general keep functions that aid in formatting colors here

'''

import os

class Colors():

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

    ###
    # get_color_count: Get the number of "color" occurences in a string
    ###
    def get_color_count(string):
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
    color_size = Colors.get_color_count(string)

    # If we can't add any padding simply return the string
    if (len(string) > width):
        return string

    # Calculate the total bytes that we will inject into the final string
    string_len = len(string) - color_size
    total_fill = int(width - string_len)
    rstring = ""

    # Since we are centering we want to add and prepend the same amount of bytes
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
    color_size = Colors.get_color_count(string)

    string_len = len(string) - color_size
    total_fill = int(width - string_len)
  
    if ((total_fill > 0) and (string_len != width)):
        return (string + (fillchar * total_fill))
    else:
        return string

def ansi_rjust(string, width, fillchar=' '):
    color_size = Colors.get_color_count(string)

    string_len = len(string) - color_size
    total_fill = int(width - string_len)
  
    if ((total_fill > 0) and (string_len != width)):
        return ((fillchar * total_fill) + string)
    else:
        return string
