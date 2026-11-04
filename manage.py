#!/usr/bin/env python
import os
import sys
from config.environment import prepare_environment

if __name__ == "__main__":
    prepare_environment()
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
