// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * VirtualMaximus90 — clawbot kernel (mainnet-safe utilities)
 *
 * A modular on-chain automation coordinator:
 * - role-based configuration and bounded execution paths
 * - optional off-chain approvals (EIP-712) for job scheduling
 * - conservative token handling (no custody assumptions, pull-based, safe transfers)
 * - no payable entrypoints; ETH is rejected
 *
 * Notes:
 * - This file is intentionally self-contained: interfaces + libraries + core contracts.
 * - No deployment-time parameters are required; deployer becomes initial admin + fee recipient.
 */

// =============================================================
// Interfaces (minimal, mainstream)
// =============================================================

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

interface IExecutorTarget {
    function clawExecute(bytes calldata data) external returns (bytes memory);
}

// =============================================================
// Libraries (safe, mainstream patterns)
// =============================================================

library VM90_Bytes {
    function slice(bytes calldata d, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > d.length) revert("VM90_BYTES_SLICE");
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = d[start + i];
        }
    }

    function toBytes32(bytes calldata d, uint256 start) internal pure returns (bytes32 x) {
        if (start + 32 > d.length) revert("VM90_BYTES_B32");
        assembly {
            x := calldataload(add(d.offset, start))
        }
    }
}

library VM90_Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function mulDivDown(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y) / d;
    }

    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y + (d - 1)) / d;
    }
}

library VM90_Address {
    function isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    function sendValue(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert("VM90_SEND_FAIL");
    }
}

library VM90_SafeERC20 {
    function safeTransfer(IERC20 tkn, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(tkn).call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert("VM90_TFER");
    }

    function safeTransferFrom(IERC20 tkn, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(tkn).call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert("VM90_TFER_FROM");
    }

    function safeApprove(IERC20 tkn, address spender, uint256 amount) internal {
        (bool ok, bytes memory data) = address(tkn).call(abi.encodeWithSelector(IERC20.approve.selector, spender, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert("VM90_APPR");
    }
}

library VM90_ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert("VM90_SIG_LEN");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert("VM90_SIG_V");
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert("VM90_SIG_Z");
        return signer;
    }
}

library VM90_Strings {
    bytes16 private constant _HEX = "0123456789abcdef";

    function toHex(uint256 x, uint256 lenBytes) internal pure returns (string memory) {
        bytes memory s = new bytes(2 + lenBytes * 2);
        s[0] = "0";
        s[1] = "x";
        for (uint256 i = 0; i < lenBytes * 2; i++) {
            s[2 + lenBytes * 2 - 1 - i] = _HEX[x & 0xf];
            x >>= 4;
        }
        return string(s);
    }
}

library VM90_Bitmap {
    function get(mapping(uint256 => uint256) storage self, uint256 idx) internal view returns (bool) {
        uint256 word = idx >> 8;
        uint256 bit = idx & 0xff;
        uint256 mask = 1 << bit;
        return (self[word] & mask) != 0;
    }

    function set(mapping(uint256 => uint256) storage self, uint256 idx) internal returns (uint256 word, uint256 mask) {
        word = idx >> 8;
        uint256 bit = idx & 0xff;
        mask = 1 << bit;
        uint256 cur = self[word];
        if ((cur & mask) != 0) revert("VM90_BITMAP_USED");
        self[word] = cur | mask;
    }
}

library VM90_Call {
    function callAndHash(address target, bytes memory data, uint256 gasStipend) internal returns (bytes32 resultHash) {
        bool ok;
        bytes memory out;
        if (gasStipend == 0) {
            (ok, out) = target.call(data);
        } else {
            (ok, out) = target.call{gas: gasStipend}(data);
        }
        if (!ok) {
            // keep revert surface minimal; operators can use eth_call for details
            revert("VM90_CALL_FAIL");
        }
        return keccak256(out);
    }
}

// =============================================================
// Guards & access (simple, mainstream)
// =============================================================

abstract contract VM90_ReentrancyGuard {
    uint256 private _locked;

    modifier nonReentrant() {
        if (_locked != 0) revert("VM90_REENTRANT");
        _locked = 1;
        _;
        _locked = 0;
    }
}

abstract contract VM90_Pausable {
    event VM90_Paused(address indexed by);
    event VM90_Unpaused(address indexed by);

    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert("VM90_PAUSED");
        _;
    }

    function _pause() internal {
        if (paused) revert("VM90_ALREADY");
        paused = true;
        emit VM90_Paused(msg.sender);
    }

    function _unpause() internal {
        if (!paused) revert("VM90_ALREADY2");
        paused = false;
        emit VM90_Unpaused(msg.sender);
    }
}

contract VM90_Access {
    // Minimal role registry: ADMIN can grant/revoke; other roles are boolean.
    bytes32 public constant ADMIN_ROLE = keccak256("VM90_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("VM90_OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("VM90_GUARDIAN_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("VM90_AUDITOR_ROLE");

    mapping(bytes32 => mapping(address => bool)) internal _role;

    event VM90_RoleGranted(bytes32 indexed role, address indexed account, address indexed by);
    event VM90_RoleRevoked(bytes32 indexed role, address indexed account, address indexed by);

    error VM90_MissingRole(bytes32 role, address who);

    modifier onlyRole(bytes32 r) {
        if (!_role[r][msg.sender]) revert VM90_MissingRole(r, msg.sender);
        _;
    }

    constructor(address admin) {
        _role[ADMIN_ROLE][admin] = true;
        emit VM90_RoleGranted(ADMIN_ROLE, admin, msg.sender);
    }

    function hasRole(bytes32 r, address who) external view returns (bool) {
        return _role[r][who];
    }

    function grantRole(bytes32 r, address who) external onlyRole(ADMIN_ROLE) {
        _role[r][who] = true;
        emit VM90_RoleGranted(r, who, msg.sender);
    }

    function revokeRole(bytes32 r, address who) external onlyRole(ADMIN_ROLE) {
        _role[r][who] = false;
        emit VM90_RoleRevoked(r, who, msg.sender);
    }
}

contract VM90_TargetRegistry is VM90_Access {
    using VM90_Address for address;

    // allowlisting executor targets and downstream call targets
    mapping(address => bool) public isExecutorTarget;
    mapping(address => bool) public isDownstreamTarget;

    event VM90_ExecutorTargetSet(address indexed by, address indexed target, bool allowed);
    event VM90_DownstreamTargetSet(address indexed by, address indexed target, bool allowed);

    error VM90_NotContract(address a);

    constructor(address admin) VM90_Access(admin) {}

    function setExecutorTarget(address target, bool allowed) external onlyRole(ADMIN_ROLE) {
        if (target == address(0) || !target.isContract()) revert VM90_NotContract(target);
        isExecutorTarget[target] = allowed;
        emit VM90_ExecutorTargetSet(msg.sender, target, allowed);
    }

    function setDownstreamTarget(address target, bool allowed) external onlyRole(ADMIN_ROLE) {
        if (target == address(0) || !target.isContract()) revert VM90_NotContract(target);
        isDownstreamTarget[target] = allowed;
        emit VM90_DownstreamTargetSet(msg.sender, target, allowed);
    }
}

// =============================================================
// EIP-712 helper (compact)
// =============================================================

abstract contract VM90_EIP712 {
    bytes32 private immutable _domainSeparator;
    uint256 private immutable _domainChainId;
    bytes32 private immutable _domainNameHash;
    bytes32 private immutable _domainVersionHash;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    constructor(string memory name, string memory version) {
        _domainChainId = block.chainid;
        _domainNameHash = keccak256(bytes(name));
        _domainVersionHash = keccak256(bytes(version));
        _domainSeparator = keccak256(
            abi.encode(_EIP712_DOMAIN_TYPEHASH, _domainNameHash, _domainVersionHash, block.chainid, address(this))
        );
    }

    function domainSeparatorV4() public view returns (bytes32) {
        if (block.chainid == _domainChainId) return _domainSeparator;
        return keccak256(
            abi.encode(_EIP712_DOMAIN_TYPEHASH, _domainNameHash, _domainVersionHash, block.chainid, address(this))
        );
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparatorV4(), structHash));
    }
}

// =============================================================
// Core: VirtualMaximus90 coordinator
// =============================================================

contract VirtualMaximus90 is VM90_TargetRegistry, VM90_Pausable, VM90_ReentrancyGuard, VM90_EIP712 {
    using VM90_SafeERC20 for IERC20;
    using VM90_Address for address;
    using VM90_Math for uint256;
    using VM90_Bitmap for mapping(uint256 => uint256);

    // ---- identity + fixed anchors (non-functional, for uniqueness) ----
    bytes32 public constant VM90_BUILD_ID = 0x7f3c8a2e9b1d4c8a3f0d8e2c4a1b9c0d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2;
    bytes16 public constant VM90_SEED = 0xB8dE1A0c3F9e77D1aB2c8D4e5f6A9012;
    uint64 public constant VM90_TAG = 0xD8A7C4B19F62E30A;
    uint32 public constant VM90_STAMP = 3812749651;

    // Addresses are immutable anchors for uniqueness (no forwarding, no special powers).
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // ---- configuration ----
    uint32 public maxJobsPerBatch;
    uint32 public minDelaySec;
    uint32 public maxDelaySec;
    uint32 public maxJobCalldata;
    uint32 public maxDownstreamCalldata;
    uint32 public maxDownstreamFanout;
    uint32 public maxGasStipend;
    uint16 public feeBps;
    address public feeRecipient;

    // ---- accounting ----
    mapping(address => uint256) public accruedFees; // token => amount
    mapping(address => bool) public tokenEnabled;

    // ---- job storage ----
    enum JobState {
        None,
        Queued,
        Executed,
        Canceled
    }

    struct Job {
        address creator;
        address target;
        address token;
        uint96 maxFee; // in token units
        uint64 earliest; // timestamp
        uint64 latest; // timestamp
        uint32 nonce;
        uint32 gasLimit; // advisory for offchain; optional stipend enforcement in module
        JobState state;
        bytes32 payloadHash;
    }

    // jobId => Job
    mapping(bytes32 => Job) private _jobs;
    // creator => nonce
    mapping(address => uint32) public creatorNonce;
    // replay protection for approvals
    mapping(address => mapping(uint256 => uint256)) private _approvalBitmap;

    // creator => last queue timestamp (soft rate limiting)
    mapping(address => uint64) public lastQueuedAt;
    uint32 public queueCooldownSec;

    // EIP-712 typed jobs
    bytes32 private constant _JOB_TYPEHASH = keccak256(
        "JobApproval(address creator,address target,address token,uint96 maxFee,uint64 earliest,uint64 latest,uint32 nonce,bytes32 payloadHash,uint256 chainId,address coordinator)"
    );

    // ---- events ----
    event VM90_ConfigSet(address indexed by, uint32 maxJobsPerBatch, uint32 minDelaySec, uint32 maxDelaySec, uint32 maxJobCalldata);
    event VM90_FeeSet(address indexed by, address indexed recipient, uint16 feeBps);
    event VM90_PausedBy(address indexed by);
    event VM90_UnpausedBy(address indexed by);

    event VM90_JobQueued(bytes32 indexed jobId, address indexed creator, address indexed target, address token, uint96 maxFee, uint64 earliest, uint64 latest, bytes32 payloadHash);
    event VM90_JobCanceled(bytes32 indexed jobId, address indexed by);
    event VM90_JobExecuted(bytes32 indexed jobId, address indexed executor, address indexed target, address token, uint256 feePaid, bytes32 resultHash);

    event VM90_FeesPulled(address indexed token, address indexed to, uint256 amount);
    event VM90_ApprovalUsed(address indexed approver, uint256 indexed wordIndex, uint256 mask);
    event VM90_TokenEnabled(address indexed by, address indexed token, bool enabled);
    event VM90_QueueCooldownSet(address indexed by, uint32 cooldownSec);

    // ---- errors ----
    error VM90_BadConfig();
    error VM90_BadRecipient();
    error VM90_BadFeeBps(uint256);
    error VM90_TooMany(uint256 count, uint256 max);
    error VM90_TimeBounds(uint64 earliest, uint64 latest);
    error VM90_WindowMiss(uint64 nowTs, uint64 earliest, uint64 latest);
    error VM90_JobMissing(bytes32 jobId);
    error VM90_JobState(bytes32 jobId, uint8 state);
    error VM90_PayloadTooLarge(uint256 size, uint256 maxSize);
    error VM90_TargetNotContract(address target);
    error VM90_ApprovalReplay(address approver, uint256 idx);
    error VM90_ApprovalInvalid();
    error VM90_TokenZero();
    error VM90_FeeTooHigh(uint256 asked, uint256 maxFee);
    error VM90_TokenDisabled(address token);
    error VM90_QueueCooldown(uint64 nextAt);

    // ---- constructor ----
    constructor() VM90_TargetRegistry(msg.sender) VM90_EIP712("VirtualMaximus90", "1") {
        // pre-populated anchors (checksummed, mixed-case)
        ADDRESS_A = 0xA9b2C3d4E5F60718293aBcdeF0123456789AbcD1;
        ADDRESS_B = 0x4E9D7b1cF2a0B6d3E8cD9012aB34cDeF56789aBc;
        ADDRESS_C = 0x7cD19A0bE3F4d2C1aB9876543210aBCDef012345;

        feeRecipient = msg.sender;
        feeBps = 37; // 0.37%

        maxJobsPerBatch = 41;
        minDelaySec = 45;
        maxDelaySec = 12 hours;
        maxJobCalldata = 8192;
        maxDownstreamCalldata = 6144;
        maxDownstreamFanout = 7;
        maxGasStipend = 2_900_000;

        queueCooldownSec = 19;

        // operator + guardian roles default to deployer for safe bootstrapping
        _role[OPERATOR_ROLE][msg.sender] = true;
        _role[GUARDIAN_ROLE][msg.sender] = true;
        emit VM90_RoleGranted(OPERATOR_ROLE, msg.sender, msg.sender);
        emit VM90_RoleGranted(GUARDIAN_ROLE, msg.sender, msg.sender);

        emit VM90_ConfigSet(msg.sender, maxJobsPerBatch, minDelaySec, maxDelaySec, maxJobCalldata);
        emit VM90_FeeSet(msg.sender, feeRecipient, feeBps);
        emit VM90_QueueCooldownSet(msg.sender, queueCooldownSec);
    }

    // ---- admin controls ----
    function setPaused(bool p) external onlyRole(GUARDIAN_ROLE) {
        if (p) {
            _pause();
            emit VM90_PausedBy(msg.sender);
        } else {
            _unpause();
            emit VM90_UnpausedBy(msg.sender);
        }
    }

    function setConfig(uint32 maxJobsPerBatch_, uint32 minDelaySec_, uint32 maxDelaySec_, uint32 maxJobCalldata_)
        external
        onlyRole(ADMIN_ROLE)
    {
        if (maxJobsPerBatch_ == 0 || maxJobsPerBatch_ > 256) revert VM90_BadConfig();
        if (minDelaySec_ > maxDelaySec_) revert VM90_BadConfig();
        if (maxJobCalldata_ < 4 || maxJobCalldata_ > 24_576) revert VM90_BadConfig();

        maxJobsPerBatch = maxJobsPerBatch_;
        minDelaySec = minDelaySec_;
        maxDelaySec = maxDelaySec_;
        maxJobCalldata = maxJobCalldata_;

        emit VM90_ConfigSet(msg.sender, maxJobsPerBatch_, minDelaySec_, maxDelaySec_, maxJobCalldata_);
    }

    function setExecutionBounds(
        uint32 maxDownstreamCalldata_,
        uint32 maxDownstreamFanout_,
        uint32 maxGasStipend_,
        uint32 queueCooldownSec_
    ) external onlyRole(ADMIN_ROLE) {
        if (maxDownstreamCalldata_ < 4 || maxDownstreamCalldata_ > 24_576) revert VM90_BadConfig();
        if (maxDownstreamFanout_ == 0 || maxDownstreamFanout_ > 16) revert VM90_BadConfig();
        if (maxGasStipend_ < 75_000 || maxGasStipend_ > 10_000_000) revert VM90_BadConfig();
        maxDownstreamCalldata = maxDownstreamCalldata_;
        maxDownstreamFanout = maxDownstreamFanout_;
        maxGasStipend = maxGasStipend_;
        queueCooldownSec = queueCooldownSec_;
        emit VM90_QueueCooldownSet(msg.sender, queueCooldownSec_);
    }

    function setFee(address recipient, uint16 feeBps_) external onlyRole(ADMIN_ROLE) {
        if (recipient == address(0)) revert VM90_BadRecipient();
        if (feeBps_ > 2_500) revert VM90_BadFeeBps(feeBps_);
        feeRecipient = recipient;
        feeBps = feeBps_;
        emit VM90_FeeSet(msg.sender, recipient, feeBps_);
    }

    function setTokenEnabled(address token, bool enabled) external onlyRole(ADMIN_ROLE) {
        if (token == address(0)) revert VM90_TokenZero();
        tokenEnabled[token] = enabled;
        emit VM90_TokenEnabled(msg.sender, token, enabled);
    }

    // ---- job view helpers ----
    function job(bytes32 jobId) external view returns (Job memory j) {
        j = _jobs[jobId];
    }

    function jobExists(bytes32 jobId) public view returns (bool) {
        return _jobs[jobId].state != JobState.None;
    }

    // ---- queueing (creator direct) ----
    function queueJob(
        address target,
        address token,
        uint96 maxFee,
        uint64 delaySec,
        uint64 ttlSec,
        bytes calldata payload
    ) external whenNotPaused returns (bytes32 jobId) {
        _enforceQueueCooldown(msg.sender);
        jobId = _queue(msg.sender, target, token, maxFee, delaySec, ttlSec, payload);
    }

    // ---- queueing (with approval) ----
    function queueJobWithApproval(
        address creator,
        address target,
        address token,
        uint96 maxFee,
        uint64 delaySec,
        uint64 ttlSec,
        bytes calldata payload,
        address approver,
        uint256 approvalIndex,
        bytes calldata signature
    ) external whenNotPaused returns (bytes32 jobId) {
        // approver must be either creator itself or an approved delegate role; we keep it simple:
        // - if approver is creator: creator signed (EOA or contract via ERC1271)
        // - if approver has AUDITOR_ROLE: auditor can approve scheduling for creators (mainnet ops pattern)
        if (approver != creator && !_role[AUDITOR_ROLE][approver]) revert VM90_ApprovalInvalid();
        _useApproval(approver, approvalIndex);

        bytes32 payloadHash = keccak256(payload);
        uint32 nonce = creatorNonce[creator];
        bytes32 structHash = keccak256(
            abi.encode(_JOB_TYPEHASH, creator, target, token, maxFee, _boundEarliest(delaySec), _boundLatest(delaySec, ttlSec), nonce, payloadHash, block.chainid, address(this))
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        if (!_isValidSig(approver, digest, signature)) revert VM90_ApprovalInvalid();

        _enforceQueueCooldown(creator);
        jobId = _queue(creator, target, token, maxFee, delaySec, ttlSec, payload);
    }

    function _queue(
        address creator,
        address target,
