#!/usr/bin/env python3

import logging
import pprint
import sys

import angr


def exn_hasmessage(exn, message):
    return any(message in arg for arg in exn.args)


def main():
    input_fpath = sys.argv[1]
    logging.getLogger('angr').setLevel('DEBUG')


    ## detect architecture

    try:
        p = angr.Project(input_fpath, auto_load_libs=False)
    except angr.cle.errors.CLECompatibilityError as e:
        if exn_hasmessage(e, "Unable to find a loader backend"):
            # couldn't auto-detect binary format. try me as a blob
            opts = {
                'backend': 'blob',
                'arch': 'i386', # placeholder doesn't matter for BoyScout
            }
            p = angr.Project(input_fpath, main_opts=opts, auto_load_libs=False)

        else:
            raise e
    p.analyses.BoyScout()
    # p.analyses.GirlScout() # base address detection. too bad


    ## try to find init function

    try:
        p.analyses.InitFinder()
    except ValueError as e:
        if not exn_hasmessage(e, 'Unsupported analysis target.'):
            raise e


if __name__ == '__main__':
    main()
