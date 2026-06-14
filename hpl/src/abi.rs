//! Minimal ABI helpers for the single function the spike needs: `balanceOf`.

use alloy_primitives::{Address, U256, keccak256};

/// ABI-encode `balanceOf(address)`: 4-byte selector + 32-byte left-padded
/// address. The selector is derived from the canonical signature at call time
/// (not hard-coded) so it can never silently drift from the function name.
pub fn encode_balance_of(account: Address) -> Vec<u8> {
    let hash = keccak256(b"balanceOf(address)");
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&hash[..4]);
    // Left-pad the 20-byte address into a 32-byte ABI word.
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(account.as_slice());
    data
}

/// Decode a 32-byte big-endian ABI word (a `uint256`) from `eth_call` output.
pub fn decode_uint256(output: &[u8]) -> anyhow::Result<U256> {
    if output.len() < 32 {
        anyhow::bail!("eth_call returned {} bytes, expected >= 32", output.len());
    }
    Ok(U256::from_be_slice(&output[..32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn selector_is_canonical_balance_of() {
        // The well-known balanceOf(address) selector is 0x70a08231.
        let data = encode_balance_of(Address::ZERO);
        assert_eq!(&data[..4], &[0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(data.len(), 36);
    }

    #[test]
    fn encodes_address_right_aligned() {
        let a = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let data = encode_balance_of(a);
        assert_eq!(&data[4..16], &[0u8; 12], "12 leading zero bytes");
        assert_eq!(&data[16..36], a.as_slice(), "address right-aligned");
    }

    #[test]
    fn decodes_word() {
        let mut w = [0u8; 32];
        w[31] = 42;
        assert_eq!(decode_uint256(&w).unwrap(), U256::from(42u64));
    }

    #[test]
    fn rejects_short_output() {
        assert!(decode_uint256(&[0u8; 4]).is_err());
    }
}
