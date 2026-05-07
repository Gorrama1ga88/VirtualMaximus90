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
