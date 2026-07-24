"""No security issues here."""
import os

def greet(name):
    return f"hello {name}"

def read_token():
    return os.environ["API_TOKEN"]
