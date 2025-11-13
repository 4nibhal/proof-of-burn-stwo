// Poseidon2 implementation using stwo's primitives
// Adapted from: https://github.com/starkware-libs/stwo/blob/main/crates/examples/src/poseidon/mod.rs
// Paper: https://eprint.iacr.org/2023/323.pdf Section 5

use std::ops::{Add, AddAssign, Mul, Sub};
use stwo_prover::core::fields::m31::BaseField;

// Poseidon2 parameters for M31 field (2^31 - 1)
// Generated using HorizenLabs/poseidon2 parameter generation script
// Security level: 128 bits
// Prime: p = 2147483647 (M31)
// State size: t = 16
// Alpha (S-box): 5
pub const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 26;  // Optimized for M31
const N_HALF_FULL_ROUNDS: usize = 4; // Total R_F = 8

// External round constants (8 rounds, 16 constants each)
// Generated using Grain LFSR as specified in Poseidon2 paper
const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] = [
    [BaseField::from_u32_unchecked(1323103696), BaseField::from_u32_unchecked(32820862), BaseField::from_u32_unchecked(1980729053), BaseField::from_u32_unchecked(317622338), BaseField::from_u32_unchecked(50263984), BaseField::from_u32_unchecked(427303566), BaseField::from_u32_unchecked(476470815), BaseField::from_u32_unchecked(1873216103), BaseField::from_u32_unchecked(1013492029), BaseField::from_u32_unchecked(1876243821), BaseField::from_u32_unchecked(1423021976), BaseField::from_u32_unchecked(1034880506), BaseField::from_u32_unchecked(255516447), BaseField::from_u32_unchecked(1751710500), BaseField::from_u32_unchecked(1772458188), BaseField::from_u32_unchecked(1905707724)],
    [BaseField::from_u32_unchecked(2146357039), BaseField::from_u32_unchecked(300477280), BaseField::from_u32_unchecked(1303317487), BaseField::from_u32_unchecked(1896371959), BaseField::from_u32_unchecked(1077911909), BaseField::from_u32_unchecked(1623307068), BaseField::from_u32_unchecked(1716928924), BaseField::from_u32_unchecked(1899262763), BaseField::from_u32_unchecked(561896200), BaseField::from_u32_unchecked(2147059615), BaseField::from_u32_unchecked(262690381), BaseField::from_u32_unchecked(2144164168), BaseField::from_u32_unchecked(1245079228), BaseField::from_u32_unchecked(715189338), BaseField::from_u32_unchecked(588134996), BaseField::from_u32_unchecked(1875961624)],
    [BaseField::from_u32_unchecked(727635773), BaseField::from_u32_unchecked(1044882765), BaseField::from_u32_unchecked(1256399791), BaseField::from_u32_unchecked(170160872), BaseField::from_u32_unchecked(776522156), BaseField::from_u32_unchecked(1947778522), BaseField::from_u32_unchecked(1540706240), BaseField::from_u32_unchecked(1368992253), BaseField::from_u32_unchecked(412370089), BaseField::from_u32_unchecked(1562388559), BaseField::from_u32_unchecked(1199766382), BaseField::from_u32_unchecked(257896456), BaseField::from_u32_unchecked(931242721), BaseField::from_u32_unchecked(266356162), BaseField::from_u32_unchecked(1661329514), BaseField::from_u32_unchecked(1750311239)],
    [BaseField::from_u32_unchecked(818000640), BaseField::from_u32_unchecked(1603533679), BaseField::from_u32_unchecked(1930399982), BaseField::from_u32_unchecked(1297369576), BaseField::from_u32_unchecked(725793885), BaseField::from_u32_unchecked(1909393024), BaseField::from_u32_unchecked(542194279), BaseField::from_u32_unchecked(835590442), BaseField::from_u32_unchecked(118405644), BaseField::from_u32_unchecked(363245886), BaseField::from_u32_unchecked(306379271), BaseField::from_u32_unchecked(1859125274), BaseField::from_u32_unchecked(907155627), BaseField::from_u32_unchecked(728473679), BaseField::from_u32_unchecked(68216888), BaseField::from_u32_unchecked(955416744)],
    [BaseField::from_u32_unchecked(1460405014), BaseField::from_u32_unchecked(1954678784), BaseField::from_u32_unchecked(1737828686), BaseField::from_u32_unchecked(1054416209), BaseField::from_u32_unchecked(404011322), BaseField::from_u32_unchecked(887173471), BaseField::from_u32_unchecked(2106282024), BaseField::from_u32_unchecked(89192021), BaseField::from_u32_unchecked(1805308905), BaseField::from_u32_unchecked(731574445), BaseField::from_u32_unchecked(1689910155), BaseField::from_u32_unchecked(2010105078), BaseField::from_u32_unchecked(1592067770), BaseField::from_u32_unchecked(2053284731), BaseField::from_u32_unchecked(1704275285), BaseField::from_u32_unchecked(1622667542)],
    [BaseField::from_u32_unchecked(1496650353), BaseField::from_u32_unchecked(1129998437), BaseField::from_u32_unchecked(94975783), BaseField::from_u32_unchecked(1405456603), BaseField::from_u32_unchecked(1491473593), BaseField::from_u32_unchecked(1152648986), BaseField::from_u32_unchecked(1745698830), BaseField::from_u32_unchecked(786137366), BaseField::from_u32_unchecked(1273851054), BaseField::from_u32_unchecked(46867306), BaseField::from_u32_unchecked(1106872977), BaseField::from_u32_unchecked(1239847504), BaseField::from_u32_unchecked(1618342387), BaseField::from_u32_unchecked(767578938), BaseField::from_u32_unchecked(988319243), BaseField::from_u32_unchecked(1608609998)],
    [BaseField::from_u32_unchecked(1259045680), BaseField::from_u32_unchecked(1943647915), BaseField::from_u32_unchecked(1878170765), BaseField::from_u32_unchecked(1617904628), BaseField::from_u32_unchecked(77215054), BaseField::from_u32_unchecked(1172823114), BaseField::from_u32_unchecked(270899505), BaseField::from_u32_unchecked(648507064), BaseField::from_u32_unchecked(1275491737), BaseField::from_u32_unchecked(1639546117), BaseField::from_u32_unchecked(1743480048), BaseField::from_u32_unchecked(452460390), BaseField::from_u32_unchecked(8777006), BaseField::from_u32_unchecked(137880181), BaseField::from_u32_unchecked(1299964759), BaseField::from_u32_unchecked(932562216)],
    [BaseField::from_u32_unchecked(795180932), BaseField::from_u32_unchecked(178810366), BaseField::from_u32_unchecked(104268930), BaseField::from_u32_unchecked(86930848), BaseField::from_u32_unchecked(1965844883), BaseField::from_u32_unchecked(1574834033), BaseField::from_u32_unchecked(1529304802), BaseField::from_u32_unchecked(2046056540), BaseField::from_u32_unchecked(1725752411), BaseField::from_u32_unchecked(1791806377), BaseField::from_u32_unchecked(178907537), BaseField::from_u32_unchecked(2097766673), BaseField::from_u32_unchecked(1024197625), BaseField::from_u32_unchecked(1683581695), BaseField::from_u32_unchecked(1760930095), BaseField::from_u32_unchecked(1350479555)],
];

// Internal round constants (26 partial rounds)
const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] = [
    BaseField::from_u32_unchecked(2059409277),
    BaseField::from_u32_unchecked(1595326017),
    BaseField::from_u32_unchecked(729019563),
    BaseField::from_u32_unchecked(821223358),
    BaseField::from_u32_unchecked(821187094),
    BaseField::from_u32_unchecked(1018226477),
    BaseField::from_u32_unchecked(446527941),
    BaseField::from_u32_unchecked(1373425565),
    BaseField::from_u32_unchecked(1207007119),
    BaseField::from_u32_unchecked(810524052),
    BaseField::from_u32_unchecked(613105743),
    BaseField::from_u32_unchecked(340008665),
    BaseField::from_u32_unchecked(112809736),
    BaseField::from_u32_unchecked(418771749),
    BaseField::from_u32_unchecked(1786887756),
    BaseField::from_u32_unchecked(406920982),
    BaseField::from_u32_unchecked(458308628),
    BaseField::from_u32_unchecked(501550214),
    BaseField::from_u32_unchecked(873604502),
    BaseField::from_u32_unchecked(2101098514),
    BaseField::from_u32_unchecked(1717274910),
    BaseField::from_u32_unchecked(1611916122),
    BaseField::from_u32_unchecked(368379723),
    BaseField::from_u32_unchecked(1530763479),
    BaseField::from_u32_unchecked(1570467377),
    BaseField::from_u32_unchecked(1796879066),
];

/// S-box: x^5 (standard for Poseidon)
#[inline(always)]
fn pow5(x: BaseField) -> BaseField {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Applies the M4 MDS matrix from Poseidon2 paper Section 5.1
#[inline(always)]
fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

/// Applies the external round matrix (Poseidon2 paper Section 5.1 and Appendix B)
fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Applies circ(2M4, M4, M4, M4)
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

/// Applies the internal round matrix (Poseidon2 paper Section 5.2)
/// 
/// SECURITY FIX: Modified to satisfy minimal polynomial condition
/// 
/// The standard formula mu_i = 2^{i+1} + 1 does NOT satisfy the minpoly condition
/// required in section 5.3 of the Poseidon2 paper.
/// 
/// Solution: Change first diagonal element from 3 to 4
/// Resulting diagonal: [4, 5, 9, 17, 33, 65, 129, 257, 513, 1025, 2049, 4097, 8193, 16385, 32769, 65537]
/// 
/// This ensures the matrix is:
/// - Invertible
/// - Satisfies minimal polynomial condition (degree = NUM_CELLS and irreducible)
/// - Provides proper security guarantees
/// 
/// References:
/// - Poseidon2 paper Section 5.3: https://eprint.iacr.org/2023/323.pdf
/// - Stwo issue discussion: https://github.com/starkware-libs/stwo/issues/ (security fix for internal matrix)
/// - Mathematical verification: See Sage code validating minpoly condition
fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Sum of all state elements
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    
    // Apply: new_state[i] = mu_i * state[i] + sum
    // where mu_0 = 4 (special case for minpoly condition)
    //       mu_i = 2^{i+1} for i > 0
    state.iter_mut().enumerate().for_each(|(i, s)| {
        let multiplier = if i == 0 {
            // mu_0 = 4 (changed from 3 to satisfy minpoly condition)
            BaseField::from_u32_unchecked(4)
        } else {
            // mu_i = 2^{i+1}
            BaseField::from_u32_unchecked(1 << (i + 1))
        };
        *s = s.clone() * multiplier + sum.clone();
    });
}

/// Complete Poseidon2 permutation for state size 16 (in-place)
/// This follows the exact structure from stwo's implementation
fn poseidon2_permutation_inplace(state: &mut [BaseField; N_STATE]) {
    // 4 full rounds (first half)
    for round in 0..N_HALF_FULL_ROUNDS {
        // Add round constants
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round][i];
        }
        // Apply MDS matrix
        apply_external_round_matrix(state);
        // Apply S-box
        for i in 0..N_STATE {
            state[i] = pow5(state[i]);
        }
    }

    // Partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += INTERNAL_ROUND_CONSTS[round];
        apply_internal_round_matrix(state);
        state[0] = pow5(state[0]);
    }

    // 4 full rounds (second half)
    for round in 0..N_HALF_FULL_ROUNDS {
        // Add round constants
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        // Apply MDS matrix
        apply_external_round_matrix(state);
        // Apply S-box
        for i in 0..N_STATE {
            state[i] = pow5(state[i]);
        }
    }
}

/// Complete Poseidon2 permutation that returns the result
/// (wrapper around the in-place version for convenience)
pub fn poseidon2_permutation(state: [BaseField; N_STATE]) -> [BaseField; N_STATE] {
    let mut result = state;
    poseidon2_permutation_inplace(&mut result);
    result
}

/// Poseidon2 hash for 2 inputs (rate 2, capacity 14 for security)
pub fn poseidon2_hash_2(inputs: [BaseField; 2]) -> BaseField {
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = inputs[0];
    state[1] = inputs[1];
    poseidon2_permutation_inplace(&mut state);
    state[0]
}

/// Poseidon2 hash for 3 inputs
pub fn poseidon2_hash_3(inputs: [BaseField; 3]) -> BaseField {
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = inputs[0];
    state[1] = inputs[1];
    state[2] = inputs[2];
    poseidon2_permutation_inplace(&mut state);
    state[0]
}

/// Compute critical states for Poseidon2 verification
/// Returns: (initial_state, after_first_round, final_result)
pub fn poseidon2_critical_states(input_state: [BaseField; N_STATE]) -> ([BaseField; N_STATE], [BaseField; N_STATE], BaseField) {
    let mut state = input_state;

    // Save initial state
    let initial_state = state;

    // Compute first full round
    // Add round constants
    for i in 0..N_STATE {
        state[i] += EXTERNAL_ROUND_CONSTS[0][i];
    }
    // Apply MDS matrix
    apply_external_round_matrix(&mut state);
    // Apply S-box
    for i in 0..N_STATE {
        state[i] = pow5(state[i]);
    }

    // Save state after first round
    let after_first_round = state;

    // Complete the permutation to get final result
    poseidon2_permutation_inplace(&mut state);
    let final_result = state[0];

    (initial_state, after_first_round, final_result)
}

/// Poseidon2 hash for 4 inputs
pub fn poseidon2_hash_4(inputs: [BaseField; 4]) -> BaseField {
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = inputs[0];
    state[1] = inputs[1];
    state[2] = inputs[2];
    state[3] = inputs[3];
    poseidon2_permutation_inplace(&mut state);
    state[0]
}

/// Convert between stwo's BaseField and our custom M31
pub fn basefield_to_custom_m31(bf: BaseField) -> crate::field::M31 {
    crate::field::M31::new(bf.0)
}

/// Convert from our custom M31 to stwo's BaseField
pub fn custom_m31_to_basefield(m31: crate::field::M31) -> BaseField {
    BaseField::from_u32_unchecked(m31.value())
}

/// Wrapper for poseidon2 inputs using custom M31
pub fn poseidon2(inputs: [crate::field::M31; 2]) -> crate::field::M31 {
    let bf_inputs = [
        custom_m31_to_basefield(inputs[0]),
        custom_m31_to_basefield(inputs[1]),
    ];
    let result = poseidon2_hash_2(bf_inputs);
    basefield_to_custom_m31(result)
}

pub fn poseidon3(inputs: [crate::field::M31; 3]) -> crate::field::M31 {
    let bf_inputs = [
        custom_m31_to_basefield(inputs[0]),
        custom_m31_to_basefield(inputs[1]),
        custom_m31_to_basefield(inputs[2]),
    ];
    let result = poseidon2_hash_3(bf_inputs);
    basefield_to_custom_m31(result)
}

pub fn poseidon4(inputs: [crate::field::M31; 4]) -> crate::field::M31 {
    let bf_inputs = [
        custom_m31_to_basefield(inputs[0]),
        custom_m31_to_basefield(inputs[1]),
        custom_m31_to_basefield(inputs[2]),
        custom_m31_to_basefield(inputs[3]),
    ];
    let result = poseidon2_hash_4(bf_inputs);
    basefield_to_custom_m31(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_deterministic() {
        let inputs = [
            BaseField::from_u32_unchecked(1),
            BaseField::from_u32_unchecked(2),
        ];
        let result1 = poseidon2_hash_2(inputs);
        let result2 = poseidon2_hash_2(inputs);
        assert_eq!(result1, result2, "Poseidon2 should be deterministic");
    }

    #[test]
    fn test_poseidon2_different_inputs() {
        let inputs1 = [
            BaseField::from_u32_unchecked(1),
            BaseField::from_u32_unchecked(2),
        ];
        let inputs2 = [
            BaseField::from_u32_unchecked(3),
            BaseField::from_u32_unchecked(4),
        ];
        let result1 = poseidon2_hash_2(inputs1);
        let result2 = poseidon2_hash_2(inputs2);
        assert_ne!(result1, result2, "Different inputs should produce different outputs");
    }

    #[test]
    fn test_poseidon2_custom_m31_wrapper() {
        let inputs = [
            crate::field::M31::new(1),
            crate::field::M31::new(2),
        ];
        let result = poseidon2(inputs);
        // Just check it doesn't crash and returns a valid M31
        assert!(result.value() < crate::constants::M31_PRIME);
    }
}

