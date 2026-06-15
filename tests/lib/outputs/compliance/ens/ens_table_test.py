import re
from types import SimpleNamespace

from prowler.lib.outputs.compliance.ens.ens import get_ens_table


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _attr(marco, categoria, tipo="requisito", nivel="alto"):
    return SimpleNamespace(Marco=marco, Categoria=categoria, Tipo=tipo, Nivel=nivel)


def _make_compliance(provider, attributes, framework="ENS"):
    """Build a per-check ENS compliance with the given marco/categoria attrs."""
    return SimpleNamespace(
        Framework=framework,
        Provider=provider,
        Requirements=[SimpleNamespace(Attributes=attributes)],
    )


class TestENSTable:
    def test_no_cumple_marked_in_every_marco(self, capsys):
        """A single failing finding mapped to several marcos must mark every
        one of them as NO CUMPLE, not only the first marco seen."""
        bulk_metadata = {
            # check_a fails and belongs to two distinct marcos/categorias.
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance(
                        "aws",
                        [
                            _attr("operacional", "control de acceso"),
                            _attr("organizativo", "politica de seguridad"),
                        ],
                    )
                ]
            ),
            # A passing finding so the overview total reaches 2.
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("operacional", "control de acceso")])
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_ens_table(
            findings,
            bulk_metadata,
            "ens_rd2022_aws",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # Both marco rows the failing finding maps to must read NO CUMPLE.
        # Before the fix only the first marco was marked, the second stayed
        # CUMPLE. Anchor the assertion to the actual marco rows (not the
        # overview header line which also mentions NO CUMPLE).
        op_row = [
            line
            for line in plain.splitlines()
            if "operacional/control de acceso" in line
        ]
        org_row = [
            line
            for line in plain.splitlines()
            if "organizativo/politica de seguridad" in line
        ]
        assert len(op_row) == 1 and "NO CUMPLE" in op_row[0]
        assert len(org_row) == 1 and "NO CUMPLE" in org_row[0]

    def test_recomendacion_does_not_set_no_cumple(self, capsys):
        """A FAIL on a 'recomendacion' attribute must not flip a marco to
        NO CUMPLE (this path is intentionally excluded from the fix)."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance(
                        "aws",
                        [_attr("operacional", "control de acceso", tipo="recomendacion")],
                    )
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[_make_compliance("aws", [_attr("organizativo", "politica")])]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_ens_table(
            findings,
            bulk_metadata,
            "ens_rd2022_aws",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # The recomendacion FAIL must not appear as a NO CUMPLE marco row in the
        # results table (the overview header line is allowed to mention it).
        marco_rows = [
            line
            for line in plain.splitlines()
            if "operacional" in line or "organizativo" in line
        ]
        assert all("NO CUMPLE" not in line for line in marco_rows)

    def test_muted_multi_marco_not_undercounted(self, capsys):
        """A single MUTED finding mapped to several marcos must increment the
        per-marco Muted column for every marco, not only the first seen."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance(
                        "aws",
                        [
                            _attr("operacional", "control de acceso"),
                            _attr("organizativo", "politica de seguridad"),
                        ],
                    )
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("operacional", "control de acceso")])
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            _make_finding("check_b", "FAIL"),
        ]

        get_ens_table(
            findings,
            bulk_metadata,
            "ens_rd2022_aws",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # Both marco rows the muted finding maps to must report a Muted count of
        # 1 in their last cell.
        muted_one_rows = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_one_rows) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys):
        """The Proveedor column must come from the matched ENS compliance, not
        from a different framework that trails it in the compliance list."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("operacional", "control de acceso")]),
                    _make_compliance(
                        "gcp", [_attr("x", "y")], framework="OtherFramework"
                    ),
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("operacional", "control de acceso")]),
                    _make_compliance(
                        "gcp", [_attr("x", "y")], framework="OtherFramework"
                    ),
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_ens_table(
            findings,
            bulk_metadata,
            "ens_rd2022_aws",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        assert "aws" in captured.out
        assert "gcp" not in captured.out
