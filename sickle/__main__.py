#!/usr/bin/env python3

from sickle.common import helper
from sickle.common import handler

def entry_point():

  arg_parser = helper.parser()

  coordinator = handler.handle(arg_parser)
  coordinator.handle_args()

if __name__ == '__main__':
  entry_point()
