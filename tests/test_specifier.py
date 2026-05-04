"""Tests for scanner.specifier — minimal PEP 440 evaluator."""

from __future__ import annotations

from scanner.specifier import any_satisfies, satisfies


class TestSatisfies:
    def test_empty_spec_allows_anything(self):
        assert satisfies("1.0.0", "") is True
        assert satisfies("1.0.0", "   ") is True

    def test_lt(self):
        assert satisfies("3.4.3", "<3.5") is True
        assert satisfies("3.5.0", "<3.5") is False
        assert satisfies("3.8.2", "<3.5") is False

    def test_lte(self):
        assert satisfies("3.5", "<=3.5") is True
        assert satisfies("3.5.0", "<=3.5") is True
        assert satisfies("3.5.1", "<=3.5") is False

    def test_gt(self):
        assert satisfies("3.5.1", ">3.5") is True
        assert satisfies("3.5", ">3.5") is False

    def test_gte(self):
        assert satisfies("3.11.16", ">=3.11.16") is True
        assert satisfies("3.11.15", ">=3.11.16") is False

    def test_compound(self):
        # hail's actual aiohttp constraint
        assert satisfies("3.13.4", "<4,>=3.11.16") is True
        assert satisfies("4.0.0", "<4,>=3.11.16") is False
        assert satisfies("3.10.0", "<4,>=3.11.16") is False

    def test_compound_blocks_bokeh_38(self):
        # hail's bokeh<3.5 cap blocks the 3.8.2 CVE fix
        assert satisfies("3.8.2", "<3.5,>=3") is False
        assert satisfies("3.4.3", "<3.5,>=3") is True

    def test_eq(self):
        assert satisfies("1.2.3", "==1.2.3") is True
        assert satisfies("1.2.4", "==1.2.3") is False

    def test_eq_wildcard(self):
        # ==1.4.* is treated as ==1.4
        assert satisfies("1.4.0", "==1.4.*") is True

    def test_neq(self):
        assert satisfies("1.2.3", "!=1.2.3") is False
        assert satisfies("1.2.4", "!=1.2.3") is True

    def test_compatible(self):
        # ~= 1.4.2 allows >= 1.4.2 and < 1.5
        assert satisfies("1.4.2", "~=1.4.2") is True
        assert satisfies("1.4.99", "~=1.4.2") is True
        assert satisfies("1.5.0", "~=1.4.2") is False
        assert satisfies("1.4.1", "~=1.4.2") is False

    def test_compatible_two_segment(self):
        # ~= 0.2 allows >= 0.2 and < 1
        assert satisfies("0.2.137", "~=0.2") is True
        assert satisfies("1.0.0", "~=0.2") is False

    def test_unknown_clause_ignored(self):
        # Garbage clauses don't blow up — just skipped
        assert satisfies("1.0", "garbage") is True

    def test_pre_release_release_segment_only(self):
        # Pre-release suffix is stripped; we compare release segments
        assert satisfies("3.5rc1", "<3.5") is False  # treated as 3.5

    def test_padding(self):
        # 3.5 vs 3.5.0 should compare equal
        assert satisfies("3.5", "==3.5.0") is True
        assert satisfies("3.5.0", "==3.5") is True


class TestAnySatisfies:
    def test_one_match(self):
        assert any_satisfies(["3.0.0", "3.13.4"], "<4,>=3.11.16") is True

    def test_no_match(self):
        assert any_satisfies(["3.0.0", "4.0.0"], "<4,>=3.11.16") is False

    def test_empty_versions(self):
        assert any_satisfies([], "<4") is False
