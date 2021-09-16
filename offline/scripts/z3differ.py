#!/usr/bin/env python3

import logging
import re
import sys

from z3 import *

from s2e_utils import *


logFormatter = logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s")
#logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
#        datefmt='%H:%M:%S')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

fileHandler = logging.FileHandler("z3differ.log", mode='w')
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

ce_logger = logging.getLogger("counter_examples")
ce_logger.setLevel(logging.INFO)
ce_fileHandler = logging.FileHandler("ce.log", mode='w')
ce_logger.addHandler(ce_fileHandler)



def repl_func(match_obj):
    var_name = match_obj.group(0)
    renamed_var_name = '_'.join(var_name.split('_')[1:-1])
    return renamed_var_name


p_var_name = re.compile('a!\d+')

args = None


MOD32 = 2**32

def add(a, b):
    return (a + b) % MOD32

def sub(a, b):
	return (a - b) % MOD32

def before(a, b):
    if abs(a - b) > 2**31:
        if a < b:
            return False
        else:
            return True
    else:
        if a < b:
            return True
        else:
            return False

def find_all_tcp_states(tc_file1, tc_file2):
    all_tcp_states = set()
    with open(tc_file1, 'r') as f:
        for line in f:
            entry = eval(line)
            for sk_state in entry['sk_state'].values():
                all_tcp_states.add(sk_state)
    with open(tc_file2, 'r') as f:
        for line in f:
            entry = eval(line)
            for sk_state in entry['sk_state'].values():
                all_tcp_states.add(sk_state)
    return all_tcp_states

def find_all_tcp_state_seqs(tc_file1, tc_file2):
    all_tcp_states = set()
    with open(tc_file1, 'r') as f:
        for line in f:
            entry = eval(line)
            all_tcp_states.add(tuple([entry['sk_state'][i+1] for i in range(len(entry['sk_state']))]))
    with open(tc_file2, 'r') as f:
        for line in f:
            entry = eval(line)
            all_tcp_states.add(tuple([entry['sk_state'][i+1] for i in range(len(entry['sk_state']))]))
    return all_tcp_states

def find_related_vars(constraints, var_name):
    all_vars = {}
    lines = constraints.split('\n')
    elements = []
    level = 0
    target_level = 3
    s = ''
    for c in constraints:
        s += c
        if 'let' in s:
            target_level += 1
            s = ''
        if c == '(':
            level += 1
            if level == target_level:
                s = ''
        elif c == ')':
            level -= 1
            if level == target_level:
                elements.append(s.strip())
                s = ''

    for e in elements:
        v = e.split(' ', 1)[0]
        if p_var_name.match(v):
            all_vars[v] = e

    related_vars = [{}]
    # find direct vars
    for v, e in all_vars.iteritems():
        if e.find(var_name) > 0:
            related_vars[0][v] = e

    def has_v(v):
        for vd in related_vars:
            if v in vd:
                return True
        return False

    # find indirect vars
    changed = True if related_vars else False
    while changed:
        changed = False
        new_related_vars = {}
        for v, e in all_vars.iteritems():
            if has_v(v):
                # already in related_vars
                continue
            for v2 in related_vars[-1]:
                idx = e.find(v2)
                if idx > 0 and not e[idx + len(v2)].isdigit():
                    new_related_vars[v] = e

        if new_related_vars:
            changed = True
            related_vars.append(new_related_vars)

    return related_vars

def find_related_constraints(constraints, var_name):
    logger.debug(constraints)
    related_vars = find_related_vars(constraints, var_name)
    logger.debug('-------------------------------------')
    for i in range(len(related_vars)):
        vd = related_vars[i]
        for v, e in vd.iteritems():
            logger.debug('\t' * i + e)
            logger.debug('-------------------------------------')

def generate_constraint_str(varname, val, size):
    constraint = "(assert (and"
    for i in range(size):
        constraint += " (= (select {0} (_ bv{1} 32) ) #x{2:02x})".format(varname, i, val[i])
    constraint += "))"
    return constraint

def get_value_from_model(m, d, size):
    val = [0] * size
    if is_K(m[d]):
        for i in range(size):
            if i >= m[d].num_args():
                break
            val[i] = m[d].arg(i).as_long()
    elif isinstance(m[d], FuncInterp):
        for i in range(size):
            if i >= m[d].num_entries():
                break
            e = m[d].entry(i)
            assert e.num_args() == 1
            val[e.arg_value(0).as_long()] = e.value().as_long()
    elif isinstance(m[d], ArrayRef):
        # unwrap
        def process_node(e):
            if is_K(e):
                assert e.num_args() == 1
                for i in range(len(val)):
                    val[i] = e.arg(0).as_long()
                return
            else:
                if isinstance(e, ArrayRef) and e.decl().name() == 'store':
                    e, i, v = e.children()
                    # process inner node first
                    process_node(e)
                    # process current store
                    i = i.as_long()
                    v = v.as_long()
                    val[i] = v
                else:
                    assert False

        process_node(m[d])
    else:
        assert False

    return val

def extract_example_from_model(m):
    example = {}
    for d in m:
        k = str(d)
        if 'tcp_seq_num' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
        elif 'tcp_ack_num' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
        elif 'tcp_doff_reserved_flags' in k:
            field_val = get_value_from_model(m, d, 1)
            example[k] = field_val
        elif 'tcp_flags' in k:
            field_val = get_value_from_model(m, d, 1)
            example[k] = field_val
        elif 'tcp_win' in k:
            field_val = get_value_from_model(m, d, 2)
            example[k] = field_val
        elif 'tcp_urg_ptr' in k:
            field_val = get_value_from_model(m, d, 2)
            example[k] = field_val
        elif 'tcp_options' in k:
            field_val = get_value_from_model(m, d, args.payload_len)
            example[k] = field_val
        elif 'tcp_svr_isn' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
    return example


def generate_combined_constraints(constraints_group, constraints_to_exclude=None):
    formulas = []
    for i in range(len(constraints_group)):
        Fs = parse_smt2_string(constraints_group[i])
        if constraints_to_exclude is None:
            formulas.append(And(*Fs))
        else:
            E = constraints_to_exclude[i]
            formulas.append(And(And(*Fs), Not(E)))

    return Or(*formulas)


def is_known_ambiguity(entry):
    """
    if entry['sk_state'][1] == 12 and entry['sk_state'][2] == 8:
        constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
        F = parse_smt2_string(constraints)

        tcp_seq_num2_decl = Array('tcp_seq_num2', BitVecSort(32), BitVecSort(8))
        tcp_ack_num2_decl = Array('tcp_ack_num2', BitVecSort(32), BitVecSort(8))
        tcp_flags3_decl = Array('tcp_flags3', BitVecSort(32), BitVecSort(8))
        tcp_seq_num3_decl = Array('tcp_seq_num3', BitVecSort(32), BitVecSort(8))
        tcp_ack_num3_decl = Array('tcp_ack_num3', BitVecSort(32), BitVecSort(8))

        tcp_seq_num2 = Concat(Select(tcp_seq_num2_decl, 0), Select(tcp_seq_num2_decl, 1), Select(tcp_seq_num2_decl, 2), Select(tcp_seq_num2_decl, 3))
        tcp_ack_num2 = Concat(Select(tcp_ack_num2_decl, 0), Select(tcp_ack_num2_decl, 1), Select(tcp_ack_num2_decl, 2), Select(tcp_ack_num2_decl, 3))
        tcp_flags3 = Select(tcp_flags3_decl, 0)
        tcp_seq_num3 = Concat(Select(tcp_seq_num3_decl, 0), Select(tcp_seq_num3_decl, 1), Select(tcp_seq_num3_decl, 2), Select(tcp_seq_num3_decl, 3))
        tcp_ack_num3 = Concat(Select(tcp_ack_num3_decl, 0), Select(tcp_ack_num3_decl, 1), Select(tcp_ack_num3_decl, 2), Select(tcp_ack_num3_decl, 3))

        # RST after FIN
        s = Solver()
        s.add(F)
        s.add(tcp_flags3 & 4 == 4)
        s.add(tcp_seq_num3 == tcp_seq_num2 + 20)
        if s.check() == sat:
            return True

        # Data in CLOSING state
        s = Solver()
        s.add(F)
        s.add(tcp_ack_num3 != tcp_ack_num2)
        s.add(tcp_seq_num3 <= tcp_seq_num2 + 20)
        s.add(Or(And(tcp_flags3 & 17 == 16, tcp_seq_num3 + 20 > tcp_seq_num2 + 21), And(tcp_flags3 & 17 == 17, tcp_seq_num3 + 19 > tcp_seq_num2 + 21)))
        if s.check() == sat:
            return True
    """
    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
    F = parse_smt2_string(constraints)

    if entry['sk_state'][1] == 10:
        tcp_flags2_decl = Array('tcp_flags2', BitVecSort(32), BitVecSort(8))
        tcp_flags2 = Select(tcp_flags2_decl, 0)
        # SYN+FIN
        s = Solver()
        s.add(F)
        s.add(tcp_flags2 & 3 == 3)
        if s.check() == sat:
            return True
    elif entry['sk_state'][2] == 10:
        tcp_flags3_decl = Array('tcp_flags3', BitVecSort(32), BitVecSort(8))
        tcp_flags3 = Select(tcp_flags3_decl, 0)
        # SYN+FIN
        s = Solver()
        s.add(F)
        s.add(tcp_flags3 & 3 == 3)
        if s.check() == sat:
            return True
    else:
        tcp_flags1_decl = Array('tcp_flags1', BitVecSort(32), BitVecSort(8))
        tcp_flags1 = Select(tcp_flags1_decl, 0)
        # SYN+FIN
        s = Solver()
        s.add(F)
        s.add(tcp_flags1 & 3 == 3)
        if s.check() == sat:
            return True

    return False

def generate_constraints_to_exclude(entry):
    tcp_flags1_decl = Array('tcp_flags1', BitVecSort(32), BitVecSort(8))
    tcp_seq_num1_decl = Array('tcp_seq_num1', BitVecSort(32), BitVecSort(8))
    tcp_ack_num1_decl = Array('tcp_ack_num1', BitVecSort(32), BitVecSort(8))
    tcp_flags2_decl = Array('tcp_flags2', BitVecSort(32), BitVecSort(8))
    tcp_seq_num2_decl = Array('tcp_seq_num2', BitVecSort(32), BitVecSort(8))
    tcp_ack_num2_decl = Array('tcp_ack_num2', BitVecSort(32), BitVecSort(8))
    tcp_flags3_decl = Array('tcp_flags3', BitVecSort(32), BitVecSort(8))
    tcp_seq_num3_decl = Array('tcp_seq_num3', BitVecSort(32), BitVecSort(8))
    tcp_ack_num3_decl = Array('tcp_ack_num3', BitVecSort(32), BitVecSort(8))

    tcp_flags1 = Select(tcp_flags1_decl, 0)
    tcp_seq_num1 = Concat(Select(tcp_seq_num1_decl, 0), Select(tcp_seq_num1_decl, 1), Select(tcp_seq_num1_decl, 2), Select(tcp_seq_num1_decl, 3))
    tcp_ack_num1 = Concat(Select(tcp_ack_num1_decl, 0), Select(tcp_ack_num1_decl, 1), Select(tcp_ack_num1_decl, 2), Select(tcp_ack_num1_decl, 3))
    tcp_flags2 = Select(tcp_flags2_decl, 0)
    tcp_seq_num2 = Concat(Select(tcp_seq_num2_decl, 0), Select(tcp_seq_num2_decl, 1), Select(tcp_seq_num2_decl, 2), Select(tcp_seq_num2_decl, 3))
    tcp_ack_num2 = Concat(Select(tcp_ack_num2_decl, 0), Select(tcp_ack_num2_decl, 1), Select(tcp_ack_num2_decl, 2), Select(tcp_ack_num2_decl, 3))
    tcp_flags3 = Select(tcp_flags3_decl, 0)
    tcp_seq_num3 = Concat(Select(tcp_seq_num3_decl, 0), Select(tcp_seq_num3_decl, 1), Select(tcp_seq_num3_decl, 2), Select(tcp_seq_num3_decl, 3))
    tcp_ack_num3 = Concat(Select(tcp_ack_num3_decl, 0), Select(tcp_ack_num3_decl, 1), Select(tcp_ack_num3_decl, 2), Select(tcp_ack_num3_decl, 3))

    constraints = []
    # SYN+FIN
    constraints.append(tcp_flags1 & 3 == 3)
    if entry['sk_state'][1] == 10:
        constraints.append(tcp_flags2 & 3 == 3)
    if entry['sk_state'][2] == 10:
        constraints.append(tcp_flags3 & 3 == 3)

    if entry['sk_state'][1] == 12 and entry['sk_state'][2] == 12:
        constraints.append(And(tcp_flags2 & 6 != 0, tcp_flags3 & 3 == 3))
    
    # SEQ-end-in-window SYN/ACK in SYN_RECV state
    if entry['sk_state'][1] == 12:
        #constraints.append(And(tcp_flags2 & 18 == 18, tcp_seq_num2 <= tcp_seq_num1, tcp_seq_num2 > tcp_seq_num1 - 19))
        constraints.append(tcp_flags2 & 18 == 18)
        if entry['sk_state'][2] == 12:
            #constraints.append(And(tcp_flags3 & 18 == 18, tcp_seq_num3 <= tcp_seq_num1, tcp_seq_num3 > tcp_seq_num1 - 19))
            constraints.append(tcp_flags3 & 18 == 18)
    elif entry['sk_state'][2] == 12:
        #constraints.append(And(tcp_flags3 & 18 == 18, tcp_seq_num3 <= tcp_seq_num2, tcp_seq_num3 > tcp_seq_num2 - 19))
        constraints.append(tcp_flags3 & 18 == 18)

    # SEQ-in-window SYN in ESTABLISHED state
    if entry['sk_state'][2] == 1:
        constraints.append(And(tcp_flags3 & 2 == 2, tcp_seq_num3 >= tcp_seq_num1 - 21, tcp_seq_num3 < tcp_seq_num1 + 20 + 29200))

    # partial-SEQ-in-window RST in ESTABLISHED state
    if entry['sk_state'][2] == 1:
        constraints.append(And(tcp_flags3 & 4 == 4, tcp_seq_num3 >= tcp_seq_num1 - 21, tcp_seq_num3 < tcp_seq_num1 + 20 + 29200))

    # SEQ-in-window SYN in CLOSE_WAIT state
    if entry['sk_state'][2] == 8:
        constraints.append(And(tcp_flags3 & 2 == 2, tcp_seq_num3 >= tcp_seq_num1 - 21, tcp_seq_num3 < tcp_seq_num1 + 20 + 29200))

    # partial-SEQ-in-window RST in CLOSE_WAIT state
    if entry['sk_state'][2] == 8:
        constraints.append(And(tcp_flags3 & 4 == 4, tcp_seq_num3 >= tcp_seq_num1 - 21, tcp_seq_num3 < tcp_seq_num1 + 20 + 29200))

    # FIN in ESTABLISHED state
    if entry['sk_state'][2] == 1:
        constraints.append(tcp_flags3 & 20 == 0)

    # too old ACK in ESTABLISHED state
    if entry['sk_state'][2] == 1:
        constraints.append(And(ULE(tcp_ack_num3, 0xaaaaaaaa), UGE(tcp_ack_num3, 0x2aaaaaaa)))

    #print(Or(*constraints))
    #import pdb; pdb.set_trace()
    return Or(*constraints)


solver_cache = { 0: {}, 1: {} }
constraints_cache = { 0: {}, 1: {} }


def find_inconsistency(tc_file1, tc_file2, tcp_state = None, tcp_state_seq = None, accept_point1 = None, accept_point2 = None, exclude_states1 = [], exclude_states2 = []):
    logger.info("Finding a single inconsistency between %s and %s, tcp_state: %s, tcp state_seq: %s, accept point 1: %s, accept point 2: %s" % (tc_file1, tc_file2, tcp_state, tcp_state_seq, accept_point1, accept_point2))
    logger.info("Exclude states 1: %s. Exclude states 2: %s." % (exclude_states1, exclude_states2))
    #import pdb; pdb.set_trace()

    constraints_group1 = []
    constraints_to_exclude = []
    with open(tc_file1, 'r') as f:
        for line in f:
            entry = eval(line)
            if entry['state_id'] in exclude_states1:
                continue
            #if is_known_ambiguity(entry):
            #    continue
            if tcp_state:
                if tcp_state in entry['sk_state'].values():
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group1.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            elif tcp_state_seq:
                if all([entry['sk_state'][i+1] == tcp_state for i, tcp_state in enumerate(tcp_state_seq)]):
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group1.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            elif accept_point1:
                if accept_point1 in entry['accept_points'] :
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group1.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            else:
                # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                constraints_group1.append(constraints)
                constraints_to_exclude.append(generate_constraints_to_exclude(entry))
    logger.info("Number of states (#1): %d" % len(constraints_group1))
    combined_constraints1 = generate_combined_constraints(constraints_group1, constraints_to_exclude)

    constraints_group2 = []
    with open(tc_file2, 'r') as f:
        for line in f:
            entry = eval(line)
            if entry['state_id'] in exclude_states2:
                continue
            #if is_known_ambiguity(entry):
            #    continue
            if tcp_state:
                if tcp_state in entry['sk_state'].values():
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group2.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            elif tcp_state_seq:
                if all([entry['sk_state'][i+1] == tcp_state for i, tcp_state in enumerate(tcp_state_seq)]):
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group2.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            elif accept_point2:
                if accept_point2 in entry['accept_points'] :
                    # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    constraints_group2.append(constraints)
                    constraints_to_exclude.append(generate_constraints_to_exclude(entry))
            else:
                # rename symbols from v1_tcp_xxx_1 to tcp_xxx
                constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                constraints_group2.append(constraints)
                constraints_to_exclude.append(generate_constraints_to_exclude(entry))
    logger.info("Number of states (#2): %d" % len(constraints_group2))
    combined_constraints2 = generate_combined_constraints(constraints_group2, constraints_to_exclude)

    if len(constraints_group1) == 0 or len(constraints_group2) == 0:
        print("Empty constraints group.")
        import pdb; pdb.set_trace()

    logger.info("---------------------------------------------------------------")
    #logger.info("Combined constraints (#1): %s" % combined_constraints1.sexpr())
    logger.info("---------------------------------------------------------------")
    #logger.info("Combined constraints (#2): %s" % combined_constraints2.sexpr())

    """
    logger.info("---------------------------------------------------------------")
    logger.info("Simplifying combined constraints (#1)...")
    combined_constraints1 = simplify(combined_constraints1)
    #logger.debug("Simplified combined constraints (#1): %s" % combined_constraints1.sexpr())
    logger.info("---------------------------------------------------------------")
    logger.info("Simplifying combined constraints (#2)...")
    combined_constraints2 = simplify(combined_constraints2)
    #logger.debug("Simplified combined constraints (#2): %s" % combined_constraints2.sexpr())
    """

    logger.info("---------------------------------------------------------------")

    #prove(combined_constraints1 == combined_constraints2)
    s = Solver()
    client_isn_constraints = "(declare-fun tcp_seq_num1 () (Array (_ BitVec 32) (_ BitVec 8) ) )\n(assert (and (= (select tcp_seq_num1 (_ bv0 32) ) #xde) (= (select tcp_seq_num1 (_ bv1 32) ) #xad) (= (select tcp_seq_num1 (_ bv2 32) ) #xbe) (= (select tcp_seq_num1 (_ bv3 32) ) #xef) ))\n"
    s.add(parse_smt2_string(client_isn_constraints))
    s.add(Not(combined_constraints1 == combined_constraints2))
    #logger.debug(s)
    r = s.check()
    if r == unsat:
        logger.info("proved")
    elif r == unknown:
        logger.info("failed to prove")
        logger.info(s.model())
        assert False, "Z3 unknown results."
    else:
        logger.info("counterexample")
        m = s.model()
        logger.info(m)
        example = extract_example_from_model(m)
        ce_logger.info(example)

        saved_model = {}
        for d in m:
            k = str(d)
            saved_model[k] = m[d]
            
        s1 = Solver()
        s1.add(combined_constraints1)
        s1.check()

        for d in s1.model():
            k = str(d)
            if k in saved_model:
                s1.add(d() == saved_model[k])
    
        logger.info("#1: %s" % s1.check())

        s2 = Solver()
        s2.add(combined_constraints2)
        s2.check()

        for d in s2.model():
            k = str(d)
            if k in saved_model:
                s2.add(d() == saved_model[k])

        logger.info("#2: %s" % s2.check())

        logger.info("------------------tc file 1------------------")
        with open(tc_file1, 'r') as f:
            for line in f:
                entry = eval(line)
                """
                if entry['state_id'] not in constraints_cache[0]:
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    F = parse_smt2_string(constraints)
                    constraints_cache[0][entry['state_id']] = F
                else:
                    F = constraints_cache[0][entry['state_id']]
                """
                #logger.debug(F.sexpr())
                if entry['state_id'] not in solver_cache[0]:
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    F = parse_smt2_string(constraints)
                    s = Solver()
                    s.add(F)
                    solver_cache[0][entry['state_id']] = s
                else:
                    s = solver_cache[0][entry['state_id']]

                s.push()
                s.check()
                for d in s.model():
                    k = str(d)
                    if k in saved_model:
                        #logger.debug("%s: %s" % (k, saved_model[k]))
                        s.add(d() == saved_model[k])
                res = s.check()
                s.pop()
                if res == sat:
                    state_id1 = entry['state_id']
                    logger.info(entry)
                    break

        logger.info("------------------tc file 2------------------")
        with open(tc_file2, 'r') as f:
            for line in f:
                entry = eval(line)
                """
                if entry['state_id'] not in constraints_cache[1]:
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    F = parse_smt2_string(constraints)
                    constraints_cache[1][entry['state_id']] = F
                else:
                    F = constraints_cache[1][entry['state_id']]
                """
                #logger.debug(F.sexpr())
                if entry['state_id'] not in solver_cache[1]:
                    constraints = re.sub('v\d+_tcp_.*?_\d+', repl_func, entry['constraints'])
                    F = parse_smt2_string(constraints)
                    s = Solver()
                    s.add(F)
                    solver_cache[1][entry['state_id']] = s
                else:
                    s = solver_cache[1][entry['state_id']]

                s.push()
                s.check()
                for d in s.model():
                    k = str(d)
                    if k in saved_model:
                        #logger.debug("%s: %s" % (k, saved_model[k]))
                        s.add(d() == saved_model[k])
                res = s.check()
                s.pop()
                if res == sat:
                    logger.info(entry)
                    state_id2 = entry['state_id']
                    break

        return state_id1, state_id2

    return None, None


def find_all_inconsistencies(tc_file1, tc_file2, tcp_state = None, tcp_state_seq = None, accept_point1 = None, accept_point2 = None):
    logger.info("Finding all inconsistencies between %s and %s, tcp state: %s, tcp_state_seq: %s, accept point 1: %s, accept point 2: %s" % (tc_file1, tc_file2, tcp_state, tcp_state_seq, accept_point1, accept_point2))
    exclude_states1 = []
    exclude_states2 = []

    while True:
        state_id1, state_id2 = find_inconsistency(tc_file1, tc_file2, tcp_state, tcp_state_seq, accept_point1, accept_point2, exclude_states1, exclude_states2)
        if state_id1 is None and state_id2 is None:
            break
        if state_id1 is not None and state_id1 not in exclude_states1:
            exclude_states1.append(state_id1)
        if state_id2 is not None and state_id2 not in exclude_states2:
            exclude_states2.append(state_id2)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Compare two TCP implementations and find discrepancies.')
    parser.add_argument('tc_file1', type=str, help='test case file #1')
    parser.add_argument('tc_file2', type=str, help='test case file #2')
    parser.add_argument('-p', dest='payload_len', type=int, default=20, help='TCP options and payload len.')
    parser.add_argument('--pp', dest='print_packets', default=False, action='store_true', help='Print out the concete packets.')
    parser.add_argument('--pc', dest='print_constraints', default=False, action='store_true', help='Print out the constraints and solver result.')
    parser.add_argument('--packet', help='Load the counter example packet from file.')
    args = parser.parse_args()

    if args.packet:
        # find the state corresponding to a concrete example packet
        f = open(args.packet, 'r')
        example = eval(f.read())
        f.close()

        logger.info("------------------tc file 1------------------")
        with open(args.tc_file1, 'r') as f:
            for line in f:
                entry = eval(line)
                constraints = entry['constraints']
                if solve_constraints(constraints, example):
                    logger.info(entry)
                    #break

        logger.info("------------------tc file 2------------------")
        with open(args.tc_file2, 'r') as f:
            for line in f:
                entry = eval(line)
                constraints = entry['constraints']
                if solve_constraints(constraints, example):
                    logger.info(entry)
                    #break

        sys.exit(0)

    ACCEPT_POINTS = {
        'v3.0': {
            'syn_recv':             '0xffffffff8158b2b4',
            'established':          '0xffffffff815837c5',
            'in_order_data':        '0xffffffff8157ea70',
            'left_out_of_order':    '0xffffffff8157ecfd', 
            'right_out_of_order':   '0xffffffff8157e733',
            'close_wait':           '0xffffffff8157c290',
            'close':                '0xffffffff815765ac',
        }, 
        'v3.10': {
            'syn_recv':             '0xffffffff81636cba',
            'established':          '0xffffffff8162d8f4',
            'in_order_data':        '0xffffffff81629860',
            'left_out_of_order':    '0xffffffff81629830', 
            'right_out_of_order':   '0xffffffff81629ab8',
            'close_wait':           '0xffffffff81626588',
            'close':                '0xffffffff81620a51',
        }, 
        'v4.4': {
            'syn_recv':             '0xffffffff8172771b',
            'established':          '0xffffffff8172e17e',
            'in_order_data':        '0xffffffff81729789',
            'left_out_of_order':    '0xffffffff8172974f', 
            'right_out_of_order':   '0xffffffff81729a0a',
            'close_wait':           '0xffffffff81726dc0',
            'close':                '0xffffffff81721a01',
        }, 
        'v5.4': {
            'syn_recv':             '0xffffffff818a146a',
            'established':          '0xffffffff818a6be2',
            'in_order_data':        '0xffffffff818a519f',
            'left_out_of_order':    '0xffffffff818a53d4', 
            'right_out_of_order':   '0xffffffff818a567d',
            'close_wait':           '0xffffffff818a46d3',
            'close':                '0xffffffff8189828c',
        }, 
        'v5.10': {
            'syn_recv':             '0xffffffff81908ddb',
            'established':          '0xffffffff8190f214',
            'in_order_data':        '0xffffffff8190d804',
            'left_out_of_order':    '0xffffffff8190d701', 
            'right_out_of_order':   '0xffffffff8190d9e6',
            'close_wait':           '0xffffffff8190cc90',
            'close':                '0xffffffff818ffedc',
        }, 
    }

    #find_all_inconsistencies(args.tc_file1, args.tc_file2, accept_point1=ACCEPT_POINTS['v4.4']['right_out_of_order'], accept_point2=ACCEPT_POINTS['v5.4']['right_out_of_order'])
    #find_all_inconsistencies(args.tc_file1, args.tc_file2)
    for ap in ACCEPT_POINTS['v4.4']:
    #    find_all_inconsistencies(args.tc_file1, args.tc_file2, accept_point1=ACCEPT_POINTS['v4.4'][ap], accept_point2=ACCEPT_POINTS['v5.4'][ap])
    #    find_all_inconsistencies(args.tc_file1, args.tc_file2, accept_point1=ACCEPT_POINTS['v3.10'][ap], accept_point2=ACCEPT_POINTS['v4.4'][ap])
        find_all_inconsistencies(args.tc_file1, args.tc_file2, accept_point1=ACCEPT_POINTS['v3.0'][ap], accept_point2=ACCEPT_POINTS['v3.10'][ap])
    #    find_all_inconsistencies(args.tc_file1, args.tc_file2, accept_point1=ACCEPT_POINTS['v5.4'][ap], accept_point2=ACCEPT_POINTS['v5.10'][ap])

    #find_all_inconsistencies(args.tc_file1, args.tc_file2, tcp_state_seq=(12, 1, 1))
    #for tss in find_all_tcp_state_seqs(args.tc_file1, args.tc_file2):
    #    find_all_inconsistencies(args.tc_file1, args.tc_file2, tcp_state_seq=tss)

    #find_all_inconsistencies(args.tc_file1, args.tc_file2, 7)
    #for ts in find_all_tcp_states(args.tc_file1, args.tc_file2):
    #    find_all_inconsistencies(args.tc_file1, args.tc_file2, tcp_state=ts)
    
