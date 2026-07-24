// Goldilocks field, p = 2^64 - 2^32 + 1. All values canonical (< P),
// matching the Python reference which reduces with % P everywhere.

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
const EPSILON: u128 = 0xFFFF_FFFF; // 2^64 mod p

#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let s = a as u128 + b as u128;
    if s >= P as u128 {
        (s - P as u128) as u64
    } else {
        s as u64
    }
}

#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_add(P).wrapping_sub(b)
    }
}

// x = lo + 2^64 * hi, 2^64 = eps (mod p), 2^96 = -1 (mod p), so
// x = lo + eps * hi_lo - hi_hi (mod p)
#[inline(always)]
fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_lo = (hi as u128) & EPSILON;
    let hi_hi = hi >> 32;
    let mut acc = lo as u128 + hi_lo * EPSILON + (P - hi_hi) as u128;
    while acc >= P as u128 {
        acc -= P as u128;
    }
    acc as u64
}

#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128(a as u128 * b as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_matches_naive() {
        let vals = [
            0u64,
            1,
            2,
            P - 1,
            P - 2,
            0xFFFF_FFFF,
            1 << 32,
            0x1234_5678_9ABC_DEF0 % P,
        ];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(mul(a, b), ((a as u128 * b as u128) % P as u128) as u64);
                assert_eq!(add(a, b), ((a as u128 + b as u128) % P as u128) as u64);
                assert_eq!(
                    sub(a, b) as u128,
                    (a as u128 + P as u128 - b as u128) % P as u128
                );
            }
        }
    }
}
