"""
Live read-only checks that decompiled C says which SLEIGH variant produced it.

Read-only like test_readonly_endpoints.py, and kept out of it on purpose. That
file is also replayed in CI against the offline fake
(``-p tests.offline.replay_plugin``), which serves ONE recorded response per
endpoint. Most of what this class asserts is how a response CHANGES with
``variant=`` -- accepted, refused as a mismatch, refused as unknown, withheld by
a composite -- and no single recording can answer that; nor is there any
recording of ``/get_functions`` to replay. In that file the class would sit
skipped until the next re-record of ``get_language_metadata.snap`` and then fail
against synthesized bodies, or pass while proving nothing.

The same behaviour is pinned in CI, without a deploy, by
``src/test/java/com/xebyte/core/DecompileVariantLabellingGhidraTest.java``, which
drives these endpoints on real x86 and PowerPC programs with the real decompiler.
This file is the live confirmation after a deploy:

    pytest tests/integration/test_decompile_variant_labelling.py -v
"""

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.readonly,
    pytest.mark.usefixtures("require_server"),
]


@pytest.fixture(scope="module")
def require_server(server_available):
    """Skip all tests in module if server is not available."""
    if not server_available:
        pytest.skip(
            "MCP server is not running (start with Tools → GhidraMCP → Start MCP Server)"
        )


class TestDecompileVariantLabelling:
    """Decompiler output must say which SLEIGH dialect produced it, and must
    refuse a dialect the caller names that the program contradicts.

    Ghidra's loader guesses the variant column (PowerPC 'default' vs
    'PowerISA-VLE-64-32addr'), and the two decode the same bytes into different
    instruction streams. The wrong guess produces C that is syntactically
    perfect and wholly fictional, with nothing in the output to say so.

    The answer is a label, not a mandatory parameter. Requiring one would fire
    on every x86 binary (`default` vs `System Management Mode` share one
    decoder) and could not be enforced anyway: a refusal has to enumerate the
    legal values to be answerable, so it names the answer and the caller echoes
    it back unchecked. So: every response carrying C is stamped, an ambiguous
    processor also carries an advisory, and a variant the caller NAMES that the
    program is not loaded under is refused -- that one is a claim worth
    contradicting.

    Decompiled C reaches a caller through four endpoints: get_functions
    (decompiled_code and call_context, single and bulk), force_decompile, and
    the two composites. All four are covered here. Every assertion reads the
    response body, never just the status code: a refusal is a structured HTTP
    200, precisely so a caller can see why.
    """

    @pytest.fixture(autouse=True)
    def _requires_variant_support(self, language_metadata):
        """Skip the whole class against a server built before this work, rather
        than reporting its absence as a stack of failures."""
        if "variant_ambiguous" not in language_metadata:
            pytest.skip("server predates the decompile variant labelling (redeploy the plugin)")

    @staticmethod
    def _decoders(metadata):
        return {v.get("decoder") for v in metadata.get("available_variants") or []}

    @staticmethod
    def _other_variants(metadata):
        return [
            v.get("variant")
            for v in metadata.get("available_variants") or []
            if not v.get("loaded")
        ]

    @staticmethod
    def _decompile(http_client, **params):
        return http_client.get(
            "/get_functions", params={"fields": "decompiled_code", **params}
        )

    def test_language_metadata_exposes_the_variant_choice(self, language_metadata):
        """variant= has to be lookup-able somewhere, and this is where."""
        data = language_metadata
        variants = data.get("available_variants")
        assert isinstance(variants, list) and variants, data
        # The loaded variant is always one of the candidates, flagged as such.
        loaded = [v for v in variants if v.get("loaded")]
        assert len(loaded) == 1, variants
        assert loaded[0].get("variant") == data.get("variant")
        # Every candidate names the decoder it loads; that field is what the
        # ambiguity test counts, so a missing one would make the flag unreadable.
        assert all(v.get("decoder") for v in variants), variants

    def test_ambiguity_counts_decoders_not_variant_rows(self, language_metadata):
        """The measurement this design rests on. x86 has two variant rows and one
        x86.sla, so it must NOT be flagged; PowerPC has eleven rows and ten
        decoders, so it must be."""
        data = language_metadata
        assert data["variant_ambiguous"] == (len(self._decoders(data)) > 1), data

    def test_omitting_the_variant_decompiles_and_stamps_the_language(
        self, http_client, sample_address, language_metadata
    ):
        """The case the first cut refused. No variant named, so nothing to
        contradict: the code comes back, labelled with what produced it."""
        response = self._decompile(http_client, function=sample_address)
        assert response.status_code == 200
        data = response.json()
        assert data.get("decompiled_code"), data
        assert data.get("variant") == language_metadata.get("variant")
        assert data.get("language_id") == language_metadata.get("language_id")

    def test_a_bundle_without_decompiler_output_is_not_stamped(
        self, http_client, sample_address
    ):
        """The label travels with decompiler output, not with every read."""
        response = http_client.get(
            "/get_functions",
            params={"function": sample_address, "fields": "signature",
                    "include_call_context": "false"},
        )
        data = response.json()
        assert data.get("signature"), data
        assert "language_id" not in data, data

    def test_call_context_is_stamped(self, http_client, sample_address, language_metadata):
        """call_context is the callers' decompiled C, so it is labelled too --
        asked for on its own, without decompiled_code."""
        response = http_client.get(
            "/get_functions", params={"function": sample_address, "fields": "call_context"}
        )
        data = response.json()
        assert not data.get("error"), data
        assert data.get("language_id") == language_metadata.get("language_id"), data

    def test_the_advisory_rides_along_exactly_when_the_loader_guessed(
        self, http_client, sample_address, language_metadata, variant_ambiguous
    ):
        """Present on a multi-decoder processor, absent otherwise. A field that
        is always there and almost always false is one readers learn to skip."""
        data = self._decompile(http_client, function=sample_address).json()
        if variant_ambiguous:
            assert data.get("variant_ambiguous") is True, data
            candidates = data.get("variant_candidates")
            assert isinstance(candidates, list) and len(candidates) > 1, data
            assert language_metadata.get("variant") in candidates
            notice = data.get("variant_notice") or ""
            # Built from this processor's own candidates, not a canned example.
            assert language_metadata.get("variant") in notice
            assert "import_file(language=" in notice
        else:
            assert "variant_ambiguous" not in data, data
            assert "variant_candidates" not in data, data
            assert "variant_notice" not in data, data

    def test_naming_the_loaded_variant_is_accepted(
        self, http_client, sample_address, program_variant, language_metadata
    ):
        response = self._decompile(
            http_client, function=sample_address, variant=program_variant
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("decompiled_code"), data
        assert data.get("variant") == language_metadata.get("variant")

    def test_the_full_language_id_is_accepted_too(
        self, http_client, sample_address, language_metadata
    ):
        """get_language_metadata reports language_id, and echoing back what you
        were just shown is the first thing anyone tries."""
        response = self._decompile(
            http_client,
            function=sample_address,
            variant=language_metadata.get("language_id"),
        )
        assert response.status_code == 200
        assert response.json().get("decompiled_code")

    def test_a_variant_this_processor_does_not_have_is_refused(
        self, http_client, sample_address
    ):
        response = self._decompile(
            http_client, function=sample_address, variant="NotARealVariant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "rejected", data
        assert data.get("error") == "unknown_variant", data
        assert not data.get("decompiled_code")

    def test_a_real_but_unloaded_variant_is_refused_rather_than_answered(
        self, http_client, sample_address, language_metadata
    ):
        """Asking for a variant the program is not loaded under must not quietly
        return the loaded variant's output under the requested label. This is the
        one refusal that is never ceremony: the caller volunteered the claim."""
        others = self._other_variants(language_metadata)
        if not others:
            pytest.skip("single-variant processor: no other variant to ask for")
        response = self._decompile(http_client, function=sample_address, variant=others[0])
        assert response.status_code == 200
        data = response.json()
        assert data.get("error") == "variant_mismatch", data
        assert not data.get("decompiled_code")
        assert "import_file(language=" in data.get("suggestion", "")

    def test_bulk_mode_stamps_every_entry(
        self, http_client, sample_function, language_metadata
    ):
        """Each entry carries its own stamp, and the function map -- keyed by
        references the caller chose -- never shares a namespace with it."""
        response = self._decompile(http_client, functions=sample_function)
        assert response.status_code == 200
        data = response.json()
        functions = data.get("functions")
        assert isinstance(functions, dict), data
        entry = functions.get(sample_function)
        assert isinstance(entry, dict) and entry.get("decompiled_code"), data
        assert entry.get("language_id") == language_metadata.get("language_id"), entry
        assert entry.get("variant") == language_metadata.get("variant"), entry
        assert "language_id" not in functions, functions

    def test_bulk_mode_is_refused_on_a_contradicted_variant(
        self, http_client, sample_function, language_metadata
    ):
        """The check runs ahead of the bulk dispatch, so functions= cannot be the
        unchecked way to ask the same question."""
        others = self._other_variants(language_metadata)
        if not others:
            pytest.skip("single-variant processor: no other variant to ask for")
        response = self._decompile(http_client, functions=sample_function, variant=others[0])
        assert response.status_code == 200
        data = response.json()
        assert data.get("error") == "variant_mismatch", data
        assert "functions" not in data, data

    def test_force_decompile_follows_the_same_rules(
        self, http_client, sample_address, program_variant, language_metadata
    ):
        """force_decompile is reached for when ordinary output looks wrong, which
        is exactly when a wrong variant gets mistaken for a stale cache."""
        response = http_client.get("/force_decompile", params={"function": sample_address})
        assert response.status_code == 200
        data = response.json()
        assert data.get("decompiled"), data
        assert data.get("variant") == language_metadata.get("variant")
        assert data.get("language_id") == language_metadata.get("language_id")

        response = http_client.get(
            "/force_decompile",
            params={"function": sample_address, "variant": program_variant},
        )
        assert response.status_code == 200
        assert response.json().get("decompiled")

        others = self._other_variants(language_metadata)
        if others:
            response = http_client.get(
                "/force_decompile",
                params={"function": sample_address, "variant": others[0]},
            )
            data = response.json()
            assert data.get("error") == "variant_mismatch", data
            assert not data.get("decompiled")

    def test_composites_stamp_accepted_pseudocode(
        self, http_client, sample_address, language_metadata
    ):
        """All four C-returning endpoints label their output, not just the two
        obvious ones -- otherwise the identical pseudocode is reachable one tool
        over with nothing on it."""
        for path in ("/analyze_for_documentation", "/analyze_function_complete"):
            response = http_client.get(path, params={"function": sample_address})
            assert response.status_code == 200
            data = response.json()
            if not data.get("decompiled_code"):
                continue
            assert data.get("language_id") == language_metadata.get("language_id"), (path, data)
            assert data.get("variant") == language_metadata.get("variant"), (path, data)

    def test_composites_withhold_only_the_pseudocode_on_a_contradicted_variant(
        self, http_client, sample_address, language_metadata
    ):
        """A caller refused by get_functions must not get the same C out of a
        composite. The rest of the composite still answers; only the pseudocode
        field is held back."""
        others = self._other_variants(language_metadata)
        if not others:
            pytest.skip("single-variant processor: no other variant to ask for")
        for path in ("/analyze_for_documentation", "/analyze_function_complete"):
            response = http_client.get(
                path, params={"function": sample_address, "variant": others[0]}
            )
            assert response.status_code == 200
            data = response.json()
            assert "decompiled_code" not in data, (path, "pseudocode escaped the check")
            withheld = data.get("decompiled_code_withheld")
            assert isinstance(withheld, dict), (path, data)
            assert withheld.get("error") == "variant_mismatch", (path, withheld)
            # The composite still did its job.
            assert data.get("status") != "rejected", (path, data)
