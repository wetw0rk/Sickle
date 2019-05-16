#!/usr/bin/env python3

from Sickle.common import helper
from Sickle.common import handler

def entry_point():

  args = helper.parser()

  coordinator = handler.handle(args)
  coordinator.handle_args()

if __name__ == '__main__':
  entry_point()
