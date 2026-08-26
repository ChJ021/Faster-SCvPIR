from __future__ import annotations

import random
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from threading import Event

from small_client_vpir.parameters import reference_parameters
from small_client_vpir.protocol import (
    HintAdvertisement,
    OnlineResponse,
    QueryLimitExceeded,
    QueryPreprocessingRejected,
    RegistrationRejected,
    TokenReuseError,
    UNIFORM_REJECTION_REASON,
    advertise_hint,
    answer_combined_online_query,
    answer_online_query,
    answer_query_preprocessing,
    answer_registration,
    begin_query_preprocessing,
    begin_registration,
    begin_combined_online_query,
    build_online_query,
    client_persistent_state_bytes,
    compressed_proof_state_bytes,
    finalize_query_preprocessing,
    finalize_registration,
    server_preprocess,
    setup,
    uncompressed_proof_state_bytes,
    verify_and_decode,
    verify_combined_online_query,
)
from small_client_vpir.reference_model import TransparentCiphertext, TransparentFHEBackend


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = reference_parameters(
            protocol_variant="experimental-split-qlp-reference"
        )
        self.public = setup(self.profile)
        self.database = tuple(
            tuple((row * 7 + column * 5 + 1) % self.profile.p for column in range(self.profile.m))
            for row in range(self.profile.ell)
        )
        self.server = server_preprocess(self.public, self.database)
        self.fhe = TransparentFHEBackend()
        self.client = self._register(self.server, seed=1)

    def _register(self, server, *, seed: int):
        prepared = begin_registration(
            self.public, advertise_hint(server), self.fhe, rng=random.Random(seed)
        )
        response = answer_registration(self.public, server, prepared.request, self.fhe)
        return finalize_registration(
            self.public, prepared, response, self.fhe, rng=random.Random(seed + 1000)
        )

    def _combined_stack(self, *, seed: int = 140):
        profile = reference_parameters(protocol_variant="figure5-combined")
        public = setup(profile)
        database = tuple(
            tuple(
                (row * 7 + column * 5 + 1) % profile.p
                for column in range(profile.m)
            )
            for row in range(profile.ell)
        )
        server = server_preprocess(public, database)
        fhe = TransparentFHEBackend()
        prepared = begin_registration(
            public, advertise_hint(server), fhe, rng=random.Random(seed)
        )
        client = finalize_registration(
            public,
            prepared,
            answer_registration(public, server, prepared.request, fhe),
            fhe,
            rng=random.Random(seed + 1),
        )
        return profile, public, database, server, fhe, client

    def _token(self, *, seed: int = 20):
        prepared = begin_query_preprocessing(
            self.public, self.client, self.fhe, rng=random.Random(seed)
        )
        response = answer_query_preprocessing(self.public, self.server, prepared.request, self.fhe)
        return finalize_query_preprocessing(
            self.public, self.client, prepared, response, self.fhe
        )

    def _retrieve(self, row: int, column: int, *, seed: int = 30):
        prepared, response = self._prepare_retrieval(row, column, seed=seed)
        return prepared, response, verify_and_decode(self.public, self.client, prepared, response)

    def _prepare_retrieval(self, row: int, column: int, *, seed: int = 30):
        token = self._token(seed=seed)
        prepared = build_online_query(
            self.public, token, row=row, column=column, rng=random.Random(seed + 1)
        )
        response = answer_online_query(self.public, self.server, prepared.request)
        return prepared, response

    def test_honest_round_trip_all_cells(self) -> None:
        for row in range(self.profile.ell):
            for column in range(self.profile.m):
                with self.subTest(row=row, column=column):
                    _, _, result = self._retrieve(row, column, seed=100 + row * self.profile.m + column)
                    self.assertTrue(result.accepted)
                    self.assertEqual(result.value, self.database[row][column])

    def test_combined_figure5_round_trip(self) -> None:
        _, public, database, server, fhe, client = self._combined_stack(seed=140)
        prepared = begin_combined_online_query(
            public,
            client,
            fhe,
            row=2,
            column=5,
            rng=random.Random(150),
        )
        names = {field.name for field in fields(prepared.request)}
        self.assertNotIn("row", names)
        self.assertNotIn("column", names)
        response = answer_combined_online_query(
            public, server, prepared.request, fhe
        )
        result = verify_combined_online_query(
            public, client, prepared, response, fhe
        )
        self.assertTrue(result.accepted)
        self.assertEqual(result.value, database[2][5])
        self.assertTrue(prepared.context.verified)
        self.assertIsNone(prepared.context.fhe_secret_key)

    def test_combined_figure5_tampering_is_uniformly_rejected(self) -> None:
        profile, public, _, server, fhe, client = self._combined_stack(seed=142)
        prepared = begin_combined_online_query(
            public,
            client,
            fhe,
            row=1,
            column=4,
            rng=random.Random(151),
        )
        response = answer_combined_online_query(
            public, server, prepared.request, fhe
        )
        values = list(response.transformed_ciphertext)
        values[0] = (values[0] + 1) % profile.q
        result = verify_combined_online_query(
            public,
            client,
            prepared,
            replace(response, transformed_ciphertext=tuple(values)),
            fhe,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, UNIFORM_REJECTION_REASON)

    def test_combined_figure5_noncanonical_response_is_rejected(self) -> None:
        profile, public, _, server, fhe, client = self._combined_stack(seed=144)
        prepared = begin_combined_online_query(
            public,
            client,
            fhe,
            row=1,
            column=4,
            rng=random.Random(152),
        )
        response = answer_combined_online_query(
            public, server, prepared.request, fhe
        )
        values = list(response.transformed_ciphertext)
        values[0] += profile.q
        result = verify_combined_online_query(
            public,
            client,
            prepared,
            replace(response, transformed_ciphertext=tuple(values)),
            fhe,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, UNIFORM_REJECTION_REASON)

    def test_combined_verification_has_one_concurrent_outcome(self) -> None:
        _, public, _, server, fhe, client = self._combined_stack(seed=146)
        prepared = begin_combined_online_query(
            public,
            client,
            fhe,
            row=1,
            column=4,
            rng=random.Random(160),
        )
        response = answer_combined_online_query(
            public, server, prepared.request, fhe
        )

        def verify(_):
            return verify_combined_online_query(
                public, client, prepared, response, fhe
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(verify, (0, 1)))
        self.assertEqual(sum(item.accepted for item in results), 1)
        self.assertEqual(
            sum(item.reason == UNIFORM_REJECTION_REASON for item in results), 1
        )

    def test_server_request_has_no_explicit_index(self) -> None:
        token = self._token()
        prepared = build_online_query(
            self.public, token, row=2, column=6, rng=random.Random(50)
        )
        names = {field.name for field in fields(prepared.request)}
        self.assertNotIn("row", names)
        self.assertNotIn("column", names)
        self.assertEqual(names, {"lwe_ciphertext", "profile_digest_hex"})

    def test_combined_profile_rejects_split_qlp_api(self) -> None:
        combined_profile = reference_parameters(protocol_variant="figure5-combined")
        public = setup(combined_profile)
        server = server_preprocess(public, self.database)
        prepared_registration = begin_registration(
            public, advertise_hint(server), self.fhe, rng=random.Random(157)
        )
        client = finalize_registration(
            public,
            prepared_registration,
            answer_registration(
                public, server, prepared_registration.request, self.fhe
            ),
            self.fhe,
            rng=random.Random(158),
        )
        with self.assertRaisesRegex(ValueError, "split QLP is disabled"):
            begin_query_preprocessing(
                public, client, self.fhe, rng=random.Random(159)
            )

    def test_split_profile_rejects_all_combined_apis(self) -> None:
        with self.assertRaisesRegex(ValueError, "combined Figure-5"):
            begin_combined_online_query(
                self.public,
                self.client,
                self.fhe,
                row=0,
                column=0,
                rng=random.Random(162),
            )
        with self.assertRaisesRegex(ValueError, "combined Figure-5"):
            answer_combined_online_query(
                self.public, self.server, object(), self.fhe
            )
        with self.assertRaisesRegex(ValueError, "combined Figure-5"):
            verify_combined_online_query(
                self.public, self.client, object(), object(), self.fhe
            )

    def test_self_consistent_server_selected_database_is_accepted(self) -> None:
        alternative = tuple(
            tuple((value + 3) % self.profile.p for value in row) for row in self.database
        )
        alternate_server = server_preprocess(self.public, alternative)
        alternate_client = self._register(alternate_server, seed=8)
        prepared_prep = begin_query_preprocessing(
            self.public, alternate_client, self.fhe, rng=random.Random(9)
        )
        prep_response = answer_query_preprocessing(
            self.public, alternate_server, prepared_prep.request, self.fhe
        )
        token = finalize_query_preprocessing(
            self.public, alternate_client, prepared_prep, prep_response, self.fhe
        )
        online = build_online_query(
            self.public, token, row=1, column=3, rng=random.Random(10)
        )
        result = verify_and_decode(
            self.public,
            alternate_client,
            online,
            answer_online_query(self.public, alternate_server, online.request),
        )
        self.assertTrue(result.accepted)
        self.assertEqual(result.value, alternative[1][3])

    def test_cross_hint_registration_is_rejected(self) -> None:
        alternative = tuple(
            tuple((value + 1) % self.profile.p for value in row) for row in self.database
        )
        alternate_server = server_preprocess(self.public, alternative)
        prepared = begin_registration(
            self.public, advertise_hint(self.server), self.fhe, rng=random.Random(12)
        )
        wrong_response = answer_registration(
            self.public, alternate_server, prepared.request, self.fhe
        )
        with self.assertRaises(RegistrationRejected):
            finalize_registration(
                self.public, prepared, wrong_response, self.fhe, rng=random.Random(13)
            )

    def test_arbitrary_inconsistent_hint_is_rejected(self) -> None:
        malicious_hint = HintAdvertisement(
            tuple(tuple(0 for _ in range(self.profile.n)) for _ in range(self.profile.ell)),
            self.public.profile_digest_hex,
        )
        prepared = begin_registration(
            self.public, malicious_hint, self.fhe, rng=random.Random(121)
        )
        response = answer_registration(
            self.public, self.server, prepared.request, self.fhe
        )
        with self.assertRaisesRegex(RegistrationRejected, UNIFORM_REJECTION_REASON):
            finalize_registration(
                self.public, prepared, response, self.fhe, rng=random.Random(122)
            )

    def test_noncanonical_hint_is_rejected_before_registration(self) -> None:
        rows = [list(row) for row in advertise_hint(self.server).hint]
        rows[0][0] += self.profile.q
        advertisement = HintAdvertisement(
            tuple(tuple(row) for row in rows), self.public.profile_digest_hex
        )
        with self.assertRaisesRegex(ValueError, "non-canonical"):
            begin_registration(
                self.public, advertisement, self.fhe, rng=random.Random(129)
            )

    def test_malformed_registration_response_is_uniformly_rejected(self) -> None:
        for malformed in (None, object(), "not-a-response"):
            with self.subTest(type=type(malformed).__name__):
                prepared = begin_registration(
                    self.public,
                    advertise_hint(self.server),
                    self.fhe,
                    rng=random.Random(123),
                )
                with self.assertRaisesRegex(
                    RegistrationRejected, UNIFORM_REJECTION_REASON
                ):
                    finalize_registration(
                        self.public,
                        prepared,
                        malformed,
                        self.fhe,
                        rng=random.Random(124),
                    )
                self.assertTrue(prepared.context.finalized)

    def test_uncompressed_norm_check_is_enforced_before_compression(self) -> None:
        wide_registration_profile = replace(
            self.profile,
            name="wide-registration-reference",
            registration_lhe=replace(
                self.profile.registration_lhe,
                plaintext_modulus=2 * self.profile.proof_norm_bound + 1,
            ),
        )
        public = setup(wide_registration_profile)
        server = server_preprocess(public, self.database)
        prepared = begin_registration(
            public, advertise_hint(server), self.fhe, rng=random.Random(14)
        )
        oversized_zt = tuple(
            tuple(
                wide_registration_profile.proof_norm_bound + 1
                for _ in range(wide_registration_profile.kappa)
            )
            for _ in range(wide_registration_profile.m)
        )
        forged = TransparentCiphertext(oversized_zt, prepared.context.secret_key)
        response = answer_registration(public, server, prepared.request, self.fhe)
        with self.assertRaises(RegistrationRejected):
            finalize_registration(
                public,
                prepared,
                replace(response, encrypted_proof_transpose=forged),
                self.fhe,
                rng=random.Random(15),
            )

    def test_delegation_phases_use_distinct_plaintext_moduli(self) -> None:
        class RecordingBackend(TransparentFHEBackend):
            def __init__(self) -> None:
                self.moduli: list[int] = []

            def evaluate_left_matrix(
                self, evaluation_key, left_matrix, ciphertext, *, modulus
            ):
                self.moduli.append(modulus)
                return super().evaluate_left_matrix(
                    evaluation_key,
                    left_matrix,
                    ciphertext,
                    modulus=modulus,
                )

        registration = RecordingBackend()
        prepared_registration = begin_registration(
            self.public,
            advertise_hint(self.server),
            registration,
            rng=random.Random(126),
        )
        registration_response = answer_registration(
            self.public, self.server, prepared_registration.request, registration
        )
        client = finalize_registration(
            self.public,
            prepared_registration,
            registration_response,
            registration,
            rng=random.Random(127),
        )
        self.assertEqual(
            registration.moduli, [self.profile.registration_lhe.plaintext_modulus]
        )

        hint_delegation = RecordingBackend()
        prepared_prep = begin_query_preprocessing(
            self.public, client, hint_delegation, rng=random.Random(128)
        )
        response = answer_query_preprocessing(
            self.public, self.server, prepared_prep.request, hint_delegation
        )
        finalize_query_preprocessing(
            self.public, client, prepared_prep, response, hint_delegation
        )
        self.assertEqual(hint_delegation.moduli, [self.profile.q])

    def test_backend_context_digest_mismatch_is_rejected_before_request(self) -> None:
        class WrongBindingBackend(TransparentFHEBackend):
            def bind_context(self, **kwargs):
                return "00" * 32

        with self.assertRaisesRegex(ValueError, "did not bind"):
            begin_registration(
                self.public,
                advertise_hint(self.server),
                WrongBindingBackend(),
                rng=random.Random(161),
            )

    def test_shared_stateful_backend_has_no_cross_role_context_race(self) -> None:
        class StatefulInterleavingBackend(TransparentFHEBackend):
            def __init__(self) -> None:
                self.active_binding = None
                self.registration_keygen_entered = Event()
                self.release_registration_keygen = Event()
                self.hint_context_bound = Event()

            def bind_context(self, **kwargs):
                self.active_binding = (
                    kwargs["context_digest_hex"],
                    kwargs["profile_digest_hex"],
                    kwargs["role"],
                    kwargs["plaintext_modulus"],
                )
                if kwargs["role"] == "hint-delegation-fhe":
                    self.hint_context_bound.set()
                return super().bind_context(**kwargs)

            def keygen(self):
                expected = self.active_binding
                if (
                    expected is not None
                    and expected[2] == "client-registration-lhe"
                    and not self.registration_keygen_entered.is_set()
                ):
                    self.registration_keygen_entered.set()
                    if not self.release_registration_keygen.wait(timeout=2):
                        raise TimeoutError("registration keygen was not released")
                if self.active_binding != expected:
                    raise AssertionError("FHE context changed during an operation")
                return super().keygen()

        _, public, _, server, _, client = self._combined_stack(seed=164)
        shared_backend = StatefulInterleavingBackend()

        def start_registration():
            return begin_registration(
                public,
                advertise_hint(server),
                shared_backend,
                rng=random.Random(166),
            )

        def start_combined_query():
            return begin_combined_online_query(
                public,
                client,
                shared_backend,
                row=0,
                column=1,
                rng=random.Random(167),
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            registration_future = pool.submit(start_registration)
            self.assertTrue(
                shared_backend.registration_keygen_entered.wait(timeout=1)
            )
            combined_future = pool.submit(start_combined_query)
            try:
                self.assertFalse(shared_backend.hint_context_bound.wait(timeout=0.1))
            finally:
                shared_backend.release_registration_keygen.set()
            registration_future.result(timeout=2)
            combined_future.result(timeout=2)
        self.assertTrue(shared_backend.hint_context_bound.is_set())

    def test_tampered_query_preprocessing_is_rejected(self) -> None:
        prepared = begin_query_preprocessing(
            self.public, self.client, self.fhe, rng=random.Random(16)
        )
        response = answer_query_preprocessing(self.public, self.server, prepared.request, self.fhe)
        rows = list(response.encrypted_hint_product.payload)
        first = list(rows[0])
        first[0] = (first[0] + 1) % self.profile.q
        rows[0] = tuple(first)
        forged = TransparentCiphertext(tuple(rows), response.encrypted_hint_product.key_tag)
        with self.assertRaises(QueryPreprocessingRejected):
            finalize_query_preprocessing(
                self.public,
                self.client,
                prepared,
                replace(response, encrypted_hint_product=forged),
                self.fhe,
            )

    def test_noncanonical_query_preprocessing_plaintext_is_rejected(self) -> None:
        prepared = begin_query_preprocessing(
            self.public, self.client, self.fhe, rng=random.Random(130)
        )
        response = answer_query_preprocessing(
            self.public, self.server, prepared.request, self.fhe
        )
        rows = [list(row) for row in response.encrypted_hint_product.payload]
        rows[0][0] += self.profile.q
        forged = TransparentCiphertext(
            tuple(tuple(row) for row in rows),
            response.encrypted_hint_product.key_tag,
        )
        with self.assertRaisesRegex(
            QueryPreprocessingRejected, UNIFORM_REJECTION_REASON
        ):
            finalize_query_preprocessing(
                self.public,
                self.client,
                prepared,
                replace(response, encrypted_hint_product=forged),
                self.fhe,
            )

    def test_malformed_query_preprocessing_response_is_uniformly_rejected(self) -> None:
        for malformed in (None, object(), "not-a-response"):
            with self.subTest(type=type(malformed).__name__):
                prepared = begin_query_preprocessing(
                    self.public, self.client, self.fhe, rng=random.Random(125)
                )
                with self.assertRaisesRegex(
                    QueryPreprocessingRejected, UNIFORM_REJECTION_REASON
                ):
                    finalize_query_preprocessing(
                        self.public, self.client, prepared, malformed, self.fhe
                    )
                self.assertTrue(prepared.context.finalized)

    def test_tampered_online_response_is_uniformly_rejected(self) -> None:
        prepared, response = self._prepare_retrieval(1, 2)
        values = list(response.transformed_ciphertext)
        values[0] = (values[0] + 1) % self.profile.q
        result = verify_and_decode(
            self.public,
            self.client,
            prepared,
            replace(response, transformed_ciphertext=tuple(values)),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, UNIFORM_REJECTION_REASON)

    def test_malformed_online_responses_are_uniformly_rejected(self) -> None:
        malformed_factories = (
            lambda response: None,
            lambda response: object(),
            lambda response: replace(response, transformed_ciphertext=(1,)),
            lambda response: replace(response, transformed_ciphertext="not-a-vector"),
            lambda response: replace(response, profile_digest_hex="00" * 32),
            lambda response: OnlineResponse(
                tuple(range(self.profile.ell)), self.public.profile_digest_hex
            ),
            lambda response: replace(
                response,
                transformed_ciphertext=(
                    response.transformed_ciphertext[0] + self.profile.q,
                    *response.transformed_ciphertext[1:],
                ),
            ),
        )
        for index, factory in enumerate(malformed_factories):
            with self.subTest(index=index):
                prepared, response = self._prepare_retrieval(1, 2, seed=80 + index)
                item = factory(response)
                result = verify_and_decode(self.public, self.client, prepared, item)
                self.assertFalse(result.accepted)
                self.assertEqual(result.reason, UNIFORM_REJECTION_REASON)

    def test_query_preprocessing_token_is_single_use(self) -> None:
        token = self._token(seed=40)
        build_online_query(self.public, token, row=0, column=0, rng=random.Random(41))
        with self.assertRaises(TokenReuseError):
            build_online_query(self.public, token, row=0, column=1, rng=random.Random(42))

    def test_query_token_has_one_in_process_concurrent_consumer(self) -> None:
        token = self._token(seed=43)

        def consume(column: int):
            try:
                return build_online_query(
                    self.public,
                    token,
                    row=0,
                    column=column,
                    rng=random.Random(140 + column),
                )
            except TokenReuseError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(consume, (0, 1)))
        self.assertEqual(sum(not isinstance(item, Exception) for item in results), 1)
        self.assertEqual(sum(isinstance(item, TokenReuseError) for item in results), 1)

    def test_query_token_is_bound_to_registered_proof_state(self) -> None:
        other_client = self._register(self.server, seed=44)
        token = self._token(seed=45)
        prepared = build_online_query(
            self.public, token, row=1, column=2, rng=random.Random(46)
        )
        response = answer_online_query(self.public, self.server, prepared.request)
        result = verify_and_decode(self.public, other_client, prepared, response)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, UNIFORM_REJECTION_REASON)

    def test_registration_query_budget_is_enforced(self) -> None:
        limited_profile = replace(
            self.profile,
            name="one-query-reference",
            max_queries_per_registration=1,
            correctness_budget_bits=1,
        )
        public = setup(limited_profile)
        server = server_preprocess(public, self.database)
        prepared_registration = begin_registration(
            public, advertise_hint(server), self.fhe, rng=random.Random(70)
        )
        client = finalize_registration(
            public,
            prepared_registration,
            answer_registration(public, server, prepared_registration.request, self.fhe),
            self.fhe,
            rng=random.Random(71),
        )
        begin_query_preprocessing(public, client, self.fhe, rng=random.Random(72))
        with self.assertRaises(QueryLimitExceeded):
            begin_query_preprocessing(public, client, self.fhe, rng=random.Random(73))

    def test_query_budget_has_one_in_process_concurrent_reservation(self) -> None:
        limited_profile = replace(
            self.profile,
            name="one-query-concurrent-reference",
            max_queries_per_registration=1,
            correctness_budget_bits=1,
        )
        public = setup(limited_profile)
        server = server_preprocess(public, self.database)
        prepared_registration = begin_registration(
            public, advertise_hint(server), self.fhe, rng=random.Random(153)
        )
        client = finalize_registration(
            public,
            prepared_registration,
            answer_registration(
                public, server, prepared_registration.request, self.fhe
            ),
            self.fhe,
            rng=random.Random(154),
        )

        def reserve(seed: int):
            try:
                return begin_query_preprocessing(
                    public, client, TransparentFHEBackend(), rng=random.Random(seed)
                )
            except QueryLimitExceeded as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(reserve, (155, 156)))
        self.assertEqual(sum(not isinstance(item, Exception) for item in results), 1)
        self.assertEqual(sum(isinstance(item, QueryLimitExceeded) for item in results), 1)

    def test_reusable_client_proof_survives_failed_online_response(self) -> None:
        prepared, response = self._prepare_retrieval(0, 0, seed=50)
        values = list(response.transformed_ciphertext)
        values[-1] = (values[-1] + 1) % self.profile.q
        rejected = verify_and_decode(
            self.public,
            self.client,
            prepared,
            replace(response, transformed_ciphertext=tuple(values)),
        )
        self.assertFalse(rejected.accepted)
        _, _, later = self._retrieve(2, 3, seed=60)
        self.assertTrue(later.accepted)
        self.assertEqual(later.value, self.database[2][3])

    def test_ephemeral_contexts_are_logically_invalidated(self) -> None:
        prepared_registration = begin_registration(
            self.public, advertise_hint(self.server), self.fhe, rng=random.Random(90)
        )
        finalize_registration(
            self.public,
            prepared_registration,
            answer_registration(
                self.public, self.server, prepared_registration.request, self.fhe
            ),
            self.fhe,
            rng=random.Random(91),
        )
        self.assertTrue(prepared_registration.context.finalized)
        self.assertIsNone(prepared_registration.context.challenge)
        self.assertIsNone(prepared_registration.context.secret_key)

        prepared_prep = begin_query_preprocessing(
            self.public, self.client, self.fhe, rng=random.Random(92)
        )
        token = finalize_query_preprocessing(
            self.public,
            self.client,
            prepared_prep,
            answer_query_preprocessing(self.public, self.server, prepared_prep.request, self.fhe),
            self.fhe,
        )
        self.assertTrue(prepared_prep.context.finalized)
        self.assertIsNone(prepared_prep.context.secret)
        online = build_online_query(
            self.public, token, row=0, column=0, rng=random.Random(93)
        )
        self.assertTrue(token.consumed)
        self.assertEqual(token.public_matrix_product, ())
        verify_and_decode(
            self.public,
            self.client,
            online,
            answer_online_query(self.public, self.server, online.request),
        )
        self.assertTrue(online.context.verified)
        self.assertEqual(online.context.hint_product, ())
        self.assertEqual(online.context.requested_row, -1)

    def test_compression_reduces_reference_proof_state(self) -> None:
        # Compare like with like: fixed digests/counters can dominate a tiny toy
        # matrix even though the compressed proof payload is smaller.
        self.assertLess(
            compressed_proof_state_bytes(self.public, self.client),
            uncompressed_proof_state_bytes(self.public),
        )
        self.assertGreater(
            client_persistent_state_bytes(self.public, self.client),
            compressed_proof_state_bytes(self.public, self.client),
        )

    def test_bundled_fhe_backend_is_explicitly_insecure(self) -> None:
        self.assertFalse(self.fhe.cryptographically_secure)


if __name__ == "__main__":
    unittest.main()
