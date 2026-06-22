"""Flash-loanable governance (v0.5) -- Beanstalk class."""
from pathlib import Path
from backend.detectors.base import TargetContext
from backend.detectors.flashloan_governance import FlashloanGovernanceDetector


def _ctx(src):
    return TargetContext(address="0xabc", chain="ethereum", profile="defi-deep",
                         onchain=None, proxy_info=None, workspace=Path("."),
                         contract_name="T", source_files={"T.sol": src})


def _gov(src):
    return [f for f in FlashloanGovernanceDetector().run(_ctx(src)) if f.evidence.get("bug_class") == "governance_flashloan"]


BEANSTALK = """contract Gov {
  mapping(address => uint) stalk; mapping(uint => uint) votes;
  address init; bytes data;
  function balanceOfStalk(address a) public view returns (uint) { return stalk[a]; }
  function quorum() public view returns (uint) { return 1; }
  function vote(uint bip) external { votes[bip] = votes[bip] + balanceOfStalk(msg.sender); }
  function emergencyCommit(uint bip) external { require(votes[bip] > quorum()); (bool ok, ) = init.delegatecall(data); require(ok); }
}"""

SAFE_SNAPSHOT = """contract SafeGov {
  mapping(uint => uint) votes; mapping(uint => uint) snap; mapping(uint => uint) eta;
  function getPastVotes(address a, uint bn) public view returns (uint) { return 0; }
  function castVote(uint id) external { votes[id] = votes[id] + getPastVotes(msg.sender, snap[id]); }
  function execute(uint id) external { require(block.timestamp > eta[id]); }
}"""

SAFE_POLL = """contract Poll {
  mapping(address => uint) bal; mapping(uint => uint) votes;
  function balanceOf(address a) public view returns (uint) { return bal[a]; }
  function vote(uint id) external { votes[id] = votes[id] + balanceOf(msg.sender); }
  function tally(uint id) external view returns (uint) { return votes[id]; }
}"""


def test_beanstalk_flashloan_governance_flagged():
    fs = _gov(BEANSTALK)
    assert fs and fs[0].evidence.get("emergency_exec") is True


def test_snapshot_governor_not_flagged():
    assert not _gov(SAFE_SNAPSHOT)


def test_spot_power_without_arbitrary_exec_not_flagged():
    assert not _gov(SAFE_POLL)
