#!/usr/bin/env python

from __future__ import print_function

import os
import shutil
import sys


def prompt(msg):
    print("> {}".format(msg))


def error(msg):
    print("ERROR: {}".format(msg), file=sys.stderr)


DIR = os.path.dirname(os.path.realpath(__file__))
DIR = os.path.relpath(DIR, os.path.curdir)
SUBMIT_DIR = os.path.join(DIR, "CECZ4024_tmp")
SRC_ROOT = os.path.join(DIR, "src")
PDF_ROOT = os.path.join(DIR, "pdf")
P_NUMS = [str(i) for i in [1, 2]]


def get_fname(number, ext, prefix="Attacker"):
    return prefix + number + "." + ext


def _are_pdfs_ready(pdf_root):
    src_pdfs = [os.path.join(pdf_root, get_fname(i, "pdf")) for i in P_NUMS]
    for pdf in src_pdfs:
        if not os.path.isfile(pdf):
            error("{} not exists".format(pdf))
            return False
    return True


def _final_check(root):
    files = [os.path.join(root, get_fname(i, ext)) for i in P_NUMS for ext in ["java", "pdf"]]
    for fpath in files:
        if not os.path.exists(fpath):
            error("{} not found".format(fpath))
            exit(1)
        else:
            prompt("* {}".format(fpath))


def _copy_src(src_dir, tgt_dir, ext):
    for num in P_NUMS:
        f_name = get_fname(num, ext)
        src_f = os.path.join(src_dir, f_name)
        if not os.path.exists(src_f):
            error("{} not exists".format(src_f))
            exit(1)
        if not os.path.exists(tgt_dir):
            prompt("creating {}".format(tgt_dir))
            os.makedirs(tgt_dir)
        tgt_f = os.path.join(tgt_dir, f_name)
        prompt("{} => {}".format(src_f, tgt_f))
        shutil.copy(src_f, tgt_f)


def _rename_submit(root):
    prompt("ensure you have collected all files before submission")
    _final_check(root)
    prompt("""changing submission directory name {}...
    WARNING: will remove old directory if exists.""".format(root))
    number = raw_input("\nInput your matriculation No.: ")
    sname = raw_input("Input your name [same as NTULearn; ' '(space) should be substituted with '_' (underscore)]: ")
    print()
    final_fname = number + "_" + sname.replace(" ", "_")
    final_root = os.path.join(os.path.dirname(root), final_fname)
    if os.path.isdir(final_root):
        prompt("removing all files in old submission folder")
        shutil.rmtree(final_root, True)
    prompt("{} => {}".format(root, final_root))
    os.rename(root, final_root)
    zipfname = final_root + ".zip"
    if os.path.isfile(zipfname):
        prompt("removing OLD {}".format(zipfname))
        os.remove(zipfname)
    prompt("zip {} to {}".format(final_root, zipfname))
    shutil.make_archive(final_root, 'zip', final_root)


def collect_files():
    prompt("copy java files")
    _copy_src(SRC_ROOT, SUBMIT_DIR, "java")
    if not _are_pdfs_ready(PDF_ROOT):
        error("make sure your pdfs are ready")
        exit(1)
    prompt("copy report files")
    _copy_src(PDF_ROOT, SUBMIT_DIR, "pdf")
    _rename_submit(SUBMIT_DIR)
    prompt("DONE!")


if __name__ == "__main__":
    collect_files()
