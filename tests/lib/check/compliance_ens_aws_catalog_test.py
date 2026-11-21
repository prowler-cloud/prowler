"""The ENS RD 311/2022 catalog for AWS keeps the invariants of every ENS catalog."""

from tests.lib.check.ens_catalog_invariants import (
    execution_mode_mismatches,
    load_requirements,
    malformed_measure_ids,
    misfiled_measures,
    misnamed_requirements,
    requirements_without_attributes,
)

REQUIREMENTS = load_requirements("aws")


def test_requirements_have_attributes():
    assert not requirements_without_attributes(REQUIREMENTS)


def test_execution_mode_follows_from_the_checks():
    assert not execution_mode_mismatches(REQUIREMENTS)


def test_group_ids_are_measures_of_the_rd():
    assert not malformed_measure_ids(REQUIREMENTS)


def test_measures_are_filed_under_their_block_and_group():
    assert not misfiled_measures(REQUIREMENTS)


def test_requirement_ids_name_their_measure():
    assert not misnamed_requirements(REQUIREMENTS, "aws")


# Every requirement id of CCN-STIC-887A, the CCN guide to configuring AWS for the ENS
# (September 2023 edition), which names each requirement between brackets.
CCN_STIC_887A_REQUIREMENT_IDS = """
    op.acc.1.aws.iam.1
    op.acc.2.aws.imds.1
    op.acc.3.r1.aws.iam.1
    op.acc.3.r2.aws.iam.1
    op.acc.4.aws.iam.1 op.acc.4.aws.iam.2 op.acc.4.aws.iam.3
    op.acc.6.aws.iam.1 op.acc.6.aws.iam.2 op.acc.6.aws.iam.3 op.acc.6.aws.iam.4
    op.acc.6.r1.aws.iam.1
    op.acc.6.r2.aws.iam.1
    op.acc.6.r4.aws.iam.1
    op.acc.6.r5.aws.iam.1
    op.acc.6.r7.aws.iam.1 op.acc.6.r7.aws.iam.2
    op.acc.6.r8.aws.iam.1
    op.cont.3.aws.drs.1
    op.exp.1.aws.cfg.1 op.exp.1.aws.cfg.2 op.exp.1.aws.re.1 op.exp.1.aws.sys.1
    op.exp.1.aws.sys.2 op.exp.1.aws.tag.1
    op.exp.3.aws.cfg.1
    op.exp.3.r3.aws.cfg.1
    op.exp.3.r4.aws.patch.1 op.exp.3.r4.aws.smexp.1
    op.exp.4.aws.sys.1 op.exp.4.aws.sys.2
    op.exp.4.r2.aws.sys.1
    op.exp.4.r4.aws.gd.1 op.exp.4.r4.aws.insp.1 op.exp.4.r4.aws.shub.1
    op.exp.6.aws.gd.1
    op.exp.7.aws.cf.1 op.exp.7.aws.gd.1 op.exp.7.aws.iam.1 op.exp.7.aws.sh.1
    op.exp.7.r4.aws.gd.1
    op.exp.8.aws.ct.1 op.exp.8.aws.ct.2 op.exp.8.aws.ct.3 op.exp.8.aws.ct.4
    op.exp.8.aws.ct.5
    op.exp.8.r1.aws.ct.3
    op.exp.8.r3.aws.cw.1
    op.exp.8.r4.aws.ct.1 op.exp.8.r4.aws.ct.2 op.exp.8.r4.aws.ct.3
    op.exp.8.r4.aws.ct.4
    op.exp.9.aws.ct.1 op.exp.9.aws.img.1
    op.exp.10.aws.cmk.1 op.exp.10.aws.cmk.2 op.exp.10.aws.cmk.3 op.exp.10.aws.cmk.4
    op.exp.10.aws.cmk.5 op.exp.10.aws.tag.1
    op.ext.2.aws.iam.1
    op.mon.1.aws.ct.1 op.mon.1.aws.flow.1 op.mon.1.aws.gd.1
    op.mon.2.aws.sh.1
    op.mon.3.aws.cwl.1
    op.mon.3.r1.aws.gd.1 op.mon.3.r1.aws.sh.1
    op.mon.3.r2.aws.adv.1 op.mon.3.r2.aws.cfg.1 op.mon.3.r2.aws.insp.1
    op.mon.3.r2.aws.sh.1
    op.mon.3.r3.aws.gd.1
    op.mon.3.r6.aws.cfg.1 op.mon.3.r6.aws.insp.1
    mp.com.1.aws.nfw.1 mp.com.1.aws.sg.1 mp.com.1.aws.sg.2 mp.com.1.aws.sg.3
    mp.com.1.aws.sg.4
    mp.com.3.aws.cf.1 mp.com.3.aws.elb.1 mp.com.3.aws.elb.2 mp.com.3.aws.s3.1
    mp.com.4.aws.vpc.1 mp.com.4.aws.vpc.2
    mp.com.4.r1.aws.vpc.1
    mp.com.4.r3.aws.vpc.1
    mp.info.6.aws.bcku.1 mp.info.6.aws.tag.1
    mp.s.2.aws.waf.1 mp.s.2.aws.waf.2 mp.s.2.aws.waf.3
    mp.s.4.aws.as.1
    mp.s.4.r1.aws.shieldadv.1
    mp.si.2.aws.cw.1 mp.si.2.aws.dydb.1 mp.si.2.aws.ebs.1 mp.si.2.aws.es.1
    mp.si.2.aws.kms.1 mp.si.2.aws.rds.1 mp.si.2.aws.s3.1 mp.si.2.aws.sqs.1
    mp.si.2.r2.aws.ebs.1
    mp.sw.2.r1.aws.acb.1
""".split()


def test_covers_every_requirement_of_ccn_stic_887a():
    catalog_ids = {requirement["Id"] for requirement in REQUIREMENTS}
    assert sorted(set(CCN_STIC_887A_REQUIREMENT_IDS) - catalog_ids) == []
