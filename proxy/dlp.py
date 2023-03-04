#!/usr/bin/env python3

import re
import itertools

CPP_COMMON_KEYWORDS = [re.compile('.*#[ ]*%s.*' % (k, )) for k in
    ['if', 'ifdef', 'ifndef', 'include', 'error', 'else', 'pragma']]
C_COMMON_KEYWORDS = ['return', 'include', 'for', 'while', 'do', 'if', 'else','void', 'double', 'int', 'float', 'unsigned', 'signed','short', 'long', 'long long', 'byte', 'extern', 'const', 'register', 'typedef', 'sizeof', 'typeof', 'continue', 'break',' case', 'default:', 'switch', 'enum', 'volatile']
C_COMMON_CHARS = [';', '//', '=', '->', '\\']
_C_OPERATORS = ['+', '-', '/', '*', '>>', '<<', '~', '|', '^', '>', '<']
_C_OPERATORS_EQ = ['%s=' % (o, ) for o in _C_OPERATORS]
C_OPERATORS = _C_OPERATORS + _C_OPERATORS_EQ
_C_BRACES = [['(', ')'], ['[', ']'], ['/*', '*/'], ['{', '}']]
C_BRACES = list(itertools.chain(*_C_BRACES))


def is_bad_request(data):
    number_of_c_keywords = sum([data.count(keyword) for keyword in C_COMMON_KEYWORDS])
    number_of_cpp_keywords = sum([len(f.findall(data)) for f in CPP_COMMON_KEYWORDS])
    number_of_operators = sum([data.count(op) for op in C_OPERATORS])
    number_of_braces = sum([data.count(br) for br in C_BRACES])

    print('C keywords: %s, CPP keyboards: %s, ops: %s, braces: %s' % (number_of_c_keywords, number_of_cpp_keywords, number_of_operators, number_of_braces, ))


    is_harmful = ((number_of_c_keywords > 5) or number_of_cpp_keywords >= 2) and number_of_operators >= 2 and number_of_braces >= 4
    print('Is harmful: %s' % (is_harmful, ))
    return is_harmful

