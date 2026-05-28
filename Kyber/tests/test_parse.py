import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Kyber.utils.Hash import XOF
from Kyber.utils.Parse import parse
from Kyber.parameters import Kyber512Parameters

Q = Kyber512Parameters["q"]
N = Kyber512Parameters["n"]

def test_parse_output_shape_and_bounds():
    rho = bytes(range(32))
    xof = XOF(rho, 0, 0)
    poly = parse(xof)
    assert isinstance(poly, list)
    assert len(poly) == N
    assert all(isinstance(c, int) for c in poly)
    assert all(0 <= c < Q for c in poly)

def test_parse_is_deterministic_for_same_inputs():
    rho = b"R" * 32
    p1 = parse(XOF(rho, 1, 2))
    p2 = parse(XOF(rho, 1, 2))
    assert p1 == p2

def test_parse_changes_when_indices_change():
    rho = b"R" * 32
    p12 = parse(XOF(rho, 1, 2))
    p21 = parse(XOF(rho, 2, 1))
    assert p12 != p21
