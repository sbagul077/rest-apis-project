"""
blocklist.py

This file contains the blocklist of the JWT tokens. it will be imported by app and
logout resource so that tokens can be added to the blocklist when the users log out.

"""

BLOCKLIST = set()
