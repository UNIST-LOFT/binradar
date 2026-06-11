#!/usr/bin/env python3
# https://github.com/UNIST-LOFT/taosc/commit/7f884d3cc43ecfc6edce59bb37749839bddfb088#diff-296a39f9422dac004121c56b959022e9ad234263312c6433f8c58e2e6cd0b61e
#!/usr/bin/env python3
# Patch's predicate synthesizer
# Copyright (C) 2024-2025  Nguyễn Gia Phong
#
# This file is part of taosc.
#
# Taosc is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Taosc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with taosc.  If not, see <https://www.gnu.org/licenses/>.

from argparse import ArgumentParser
from cProfile import run
from functools import partial
from pathlib import Path
from sys import stderr

from pacfix import learn
from pacfix.invariant import INVARIANT_MAP, InvariantType
from pacfix.utils import get_live_vars, get_valuations, parse_valuation

write = partial(print, end='')


def write_invariant(inv):
    if inv.inv_type == InvariantType.VAR:
        write('v')
        write(inv.data)
    elif inv.inv_type == InvariantType.CONST:
        write('n' if inv.data < 0 else 'p')
        write(abs(inv.data))
    else:
        write(INVARIANT_MAP[inv.inv_type])
        write_invariant(inv.left)
        write_invariant(inv.right)


arg_parser = ArgumentParser(prog='taosc-synth')
arg_parser.add_argument('input', help='input directory', type=Path)
arg_parser.add_argument('delta', help='PAC delta', type=float,
                        nargs='?', default=0.01)
args = arg_parser.parse_args()

with open(args.input / 'list') as f: live_vars = get_live_vars(f)
vals_neg, vals_pos = parse_valuation(get_valuations(args.input / 'neg'),
                                     get_valuations(args.input / 'pos'))
result = learn(live_vars, vals_neg, vals_pos, args.delta)
print('PAC epsilon:', result.pac_epsilon, file=stderr)
for i in result.inv_mgr.invs:
    write_invariant(i)
    print()