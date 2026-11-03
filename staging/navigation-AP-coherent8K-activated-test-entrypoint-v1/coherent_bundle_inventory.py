#!/usr/bin/env python3
"""Pure catalog checks plus caller-supplied exact file verifier. No CLI/IO."""
from pathlib import PurePosixPath


def require(ok,message):
    if not ok:raise ValueError(message)


def validate_catalog(actual,expected):
    require(type(actual) is dict and type(expected) is dict and actual==expected,
            'Exact activated bundle input inventory required')
    seen=set()
    for path,row in actual.items():
        require(type(path) is str and path and not PurePosixPath(path).is_absolute() and
                all(p not in ('','.', '..') for p in path.split('/')) and '\\' not in path,
                'Inventory path must be a normal bundle-relative name')
        require(path.lower() not in seen,'Case-aliased bundle inventory path');seen.add(path.lower())
        require(type(row) is dict and set(row)=={'bytes','sha256','role'} and
                type(row['bytes']) is int and row['bytes']>0 and type(row['sha256']) is str and
                len(row['sha256'])==64 and all(c in '0123456789abcdef' for c in row['sha256']) and
                row['role'] in ('portable_helper','coherent_binding','actual_stock_proof','actual_source_seal',
                                'stock_recipe','virtual_old_v3_binding','road','candidate'),
                'Strict inventory size/hash/role fields')
    return actual


def verify_catalog(bundle,actual,expected,verify_file,safe_path):
    """Verify every declared input in deterministic small-before-payload order."""
    validate_catalog(actual,expected)
    order=('portable_helper','coherent_binding','actual_stock_proof','actual_source_seal',
           'stock_recipe','virtual_old_v3_binding','road','candidate')
    checked=[]
    for role in order:
        for name,row in actual.items():
            if row['role']==role:
                verify_file(safe_path(bundle,name),row['bytes'],row['sha256'],'Activated bundle input '+name)
                checked.append(name)
    require(len(checked)==len(actual),'Complete activated inventory coverage')
    return checked
