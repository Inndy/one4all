#!/usr/bin/env python
import glob
import os
import time

headers = glob.glob('src/*.h')
sources = glob.glob('src/*.c')

def emit(source, target_fp):
    with open(source, 'r') as fin:
        target_fp.write('/* filename: %s */\n\n' % source)
        target_fp.write(fin.read())

with open('one4all.h', 'w') as fp:
    fp.write('''\
// one4all.h by Inndy Lin <inndy.tw@gmail.com>
// compiled at %s
#ifndef _ONE4ALL_H_
#define _ONE4ALL_H_

''' % time.strftime('%Y-%m-%d %H:%M:%S %z'))

    # place src/one4all.h before anything
    emit(os.path.join('src', 'one4all.h'), fp)

    for f in headers:
        if os.path.basename(f) != 'one4all.h':
            emit(f, fp)

    for f in sources:
        emit(f, fp)

    fp.write('''
#endif
''')
