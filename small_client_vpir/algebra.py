"""Small modular-linear-algebra helpers for the executable reference model.

This module is deliberately simple and auditable.  It is not constant-time and
must not be used as a production cryptographic arithmetic layer.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence


Vector = tuple[int, ...]
Matrix = tuple[Vector, ...]


def as_vector(values: Iterable[int]) -> Vector:
    result = tuple(values)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in result):
        raise TypeError("vector entries must be integers")
    return result


def as_matrix(rows: Iterable[Iterable[int]], *, allow_empty: bool = False) -> Matrix:
    result = tuple(as_vector(row) for row in rows)
    if not result:
        if allow_empty:
            return result
        raise ValueError("matrix must contain at least one row")
    width = len(result[0])
    if width == 0 or any(len(row) != width for row in result):
        raise ValueError("matrix must be non-empty and rectangular")
    return result


def shape(matrix: Matrix) -> tuple[int, int]:
    checked = as_matrix(matrix)
    return len(checked), len(checked[0])


def transpose(matrix: Matrix) -> Matrix:
    rows, columns = shape(matrix)
    return tuple(tuple(matrix[row][column] for row in range(rows)) for column in range(columns))


def mod_vector(vector: Sequence[int], modulus: int) -> Vector:
    if modulus <= 1:
        raise ValueError("modulus must exceed one")
    return tuple(value % modulus for value in vector)


def mod_matrix(matrix: Matrix, modulus: int) -> Matrix:
    return tuple(mod_vector(row, modulus) for row in as_matrix(matrix))


def centered_lift(value: int, modulus: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("residue must be an integer")
    if modulus <= 1 or not 0 <= value < modulus:
        raise ValueError("residue is not canonically encoded in [0,q)")
    return value if value <= modulus // 2 else value - modulus


def centered_matrix(matrix: Matrix, modulus: int) -> Matrix:
    return tuple(
        tuple(centered_lift(value, modulus) for value in row)
        for row in as_matrix(matrix)
    )


def matmul(left: Matrix, right: Matrix, *, modulus: int | None = None) -> Matrix:
    left_rows, shared = shape(left)
    right_rows, right_columns = shape(right)
    if shared != right_rows:
        raise ValueError("matrix dimensions do not match")
    output = []
    for row in range(left_rows):
        output_row = []
        for column in range(right_columns):
            value = sum(left[row][k] * right[k][column] for k in range(shared))
            output_row.append(value if modulus is None else value % modulus)
        output.append(tuple(output_row))
    return tuple(output)


def matvec(matrix: Matrix, vector: Sequence[int], *, modulus: int | None = None) -> Vector:
    rows, columns = shape(matrix)
    checked_vector = as_vector(vector)
    if columns != len(checked_vector):
        raise ValueError("matrix and vector dimensions do not match")
    output = []
    for row in range(rows):
        value = sum(matrix[row][column] * checked_vector[column] for column in range(columns))
        output.append(value if modulus is None else value % modulus)
    return tuple(output)


def vector_add(*vectors: Sequence[int], modulus: int | None = None) -> Vector:
    if not vectors:
        raise ValueError("at least one vector is required")
    checked = tuple(as_vector(vector) for vector in vectors)
    width = len(checked[0])
    if any(len(vector) != width for vector in checked):
        raise ValueError("vector dimensions do not match")
    output = tuple(sum(vector[index] for vector in checked) for index in range(width))
    return output if modulus is None else mod_vector(output, modulus)


def vector_sub(left: Sequence[int], right: Sequence[int], *, modulus: int | None = None) -> Vector:
    checked_left, checked_right = as_vector(left), as_vector(right)
    if len(checked_left) != len(checked_right):
        raise ValueError("vector dimensions do not match")
    output = tuple(a - b for a, b in zip(checked_left, checked_right, strict=True))
    return output if modulus is None else mod_vector(output, modulus)


def infinity_norm(matrix: Matrix) -> int:
    return max(abs(value) for row in as_matrix(matrix) for value in row)


def encode_plaintext(value: int, plaintext_modulus: int, ciphertext_modulus: int) -> int:
    if not 0 <= value < plaintext_modulus:
        raise ValueError("plaintext value is outside Z_p")
    # Paper notation Ecd_{p,q}(x) = floor(q/p) * [x]_p.
    return ((ciphertext_modulus // plaintext_modulus) * value) % ciphertext_modulus


def decode_plaintext(value: int, plaintext_modulus: int, ciphertext_modulus: int) -> int:
    representative = value % ciphertext_modulus
    return ((representative * plaintext_modulus + ciphertext_modulus // 2) // ciphertext_modulus) % plaintext_modulus


def expand_public_matrix(seed: bytes, rows: int, columns: int, modulus: int) -> Matrix:
    """Deterministically expand A for the reference model.

    The production implementation must use the upstream scheme's specified PRG
    and domain separation.  SHAKE expansion here exists only so tests are
    reproducible and does not define wire compatibility.
    """

    if not isinstance(seed, bytes) or not seed:
        raise ValueError("matrix seed must be non-empty bytes")
    if rows <= 0 or columns <= 0 or modulus <= 1:
        raise ValueError("invalid public matrix dimensions or modulus")
    width = max(8, (modulus.bit_length() + 7) // 8)
    stream = hashlib.shake_256(b"SCVPIR-REFERENCE-A-v1\x00" + seed).digest(rows * columns * width)
    values = [
        int.from_bytes(stream[offset : offset + width], "big") % modulus
        for offset in range(0, len(stream), width)
    ]
    return tuple(
        tuple(values[row * columns : (row + 1) * columns])
        for row in range(rows)
    )


def matrix_logical_bytes(matrix: Matrix, modulus: int) -> int:
    rows, columns = shape(matrix)
    return rows * columns * max(1, (modulus.bit_length() + 7) // 8)
