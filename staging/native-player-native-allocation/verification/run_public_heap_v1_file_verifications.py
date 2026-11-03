#!/usr/bin/env python3
"""Only immutable JSON/binary proof checks; no VM import or guest execution."""
import sys
sys.dont_write_bytecode=True
import verify_heap_constructor_observed_prefix
import verify_public_heap_cold_prefix
import verify_public_heap_partial_journals

def main():
    verify_heap_constructor_observed_prefix.main()
    verify_public_heap_cold_prefix.main()
    verify_public_heap_partial_journals.main()
if __name__=='__main__':main()
