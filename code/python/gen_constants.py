"""
gen_constants.py - regenerate poseidon2_constants.py from the official
HorizenLabs Poseidon2 reference implementation.

Source of truth:
  https://github.com/HorizenLabs/poseidon2
  plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs

Usage:
  curl -sL https://raw.githubusercontent.com/HorizenLabs/poseidon2/main/plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs -o goldilocks_instance.rs
  python3 gen_constants.py
"""

import re


def parse_vec_of_scalars(src, name):
    m = re.search(
        rf"pub static ref {name}: Vec<Scalar> = vec!\[(.*?)\n    \];",
        src, re.S)
    return [int(h, 16) for h in
            re.findall(r'from_hex\("(0x[0-9a-fA-F]+)"\)', m.group(1))]


def parse_vec_of_vecs(src, name):
    m = re.search(
        rf"pub static ref {name}: Vec<Vec<Scalar>> = vec!\[(.*?)\n    \];",
        src, re.S)
    rows = re.findall(r"vec!\[(.*?)\]", m.group(1), re.S)
    return [[int(h, 16) for h in
             re.findall(r'from_hex\("(0x[0-9a-fA-F]+)"\)', r)] for r in rows]


def main():
    src = open("goldilocks_instance.rs").read()
    diag8 = parse_vec_of_scalars(src, "MAT_DIAG8_M_1")
    rc8 = parse_vec_of_vecs(src, "RC8")
    diag12 = parse_vec_of_scalars(src, "MAT_DIAG12_M_1")
    rc12 = parse_vec_of_vecs(src, "RC12")
    assert len(diag8) == 8 and len(rc8) == 30
    assert all(len(r) == 8 for r in rc8)
    assert len(diag12) == 12 and len(rc12) == 30
    assert all(len(r) == 12 for r in rc12)

    with open("poseidon2_constants.py", "w") as f:
        f.write('"""\nPoseidon2 Goldilocks constants.\n\n'
                'Extracted verbatim from the official reference '
                'implementation by the\nPoseidon2 authors '
                '(Grassi-Khovratovich-Schofnegger):\n'
                '  https://github.com/HorizenLabs/poseidon2\n'
                '  plain_implementations/src/poseidon2/'
                'poseidon2_instance_goldilocks.rs\n\n'
                'Instances: t=8 and t=12, d=7, RF=8, RP=22.\n'
                'Regenerate with gen_constants.py. Validated against the\n'
                'reference known-answer test in test_core.py.\n"""\n\n')
        f.write("MAT_DIAG8_M_1 = %r\n\n" % (diag8,))
        f.write("RC8 = %r\n\n" % (rc8,))
        f.write("MAT_DIAG12_M_1 = %r\n\n" % (diag12,))
        f.write("RC12 = %r\n" % (rc12,))
    print("wrote poseidon2_constants.py")


if __name__ == "__main__":
    main()
