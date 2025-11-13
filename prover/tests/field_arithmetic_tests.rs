// Comprehensive M31 Field Arithmetic Tests
// These tests verify every aspect of field operations to catch any potential issues

use proof_of_burn_stwo::field::M31;

#[cfg(test)]
mod field_basic_tests {
    use super::*;

    #[test]
    fn test_field_prime_is_mersenne() {
        // M31 prime should be 2^31 - 1
        assert_eq!(M31::PRIME, 2147483647);
        assert_eq!(M31::PRIME, (1u64 << 31) as u32 - 1);
    }

    #[test]
    fn test_zero_identity() {
        let zero = M31::zero();
        assert_eq!(zero.value(), 0);
        
        // Adding zero should not change value
        let a = M31::from(12345u32);
        assert_eq!(a + zero, a);
        assert_eq!(zero + a, a);
    }

    #[test]
    fn test_one_identity() {
        let one = M31::one();
        assert_eq!(one.value(), 1);
        
        // Multiplying by one should not change value
        let a = M31::from(12345u32);
        assert_eq!(a * one, a);
        assert_eq!(one * a, a);
    }

    #[test]
    fn test_modular_reduction() {
        // Values >= PRIME should be reduced
        let large = M31::from(M31::PRIME);
        assert_eq!(large.value(), 0);
        
        let large2 = M31::from(M31::PRIME + 1);
        assert_eq!(large2.value(), 1);
        
        let large3 = M31::from(M31::PRIME + 100);
        assert_eq!(large3.value(), 100);
    }

    #[test]
    fn test_max_value() {
        let max = M31::from(M31::PRIME - 1);
        assert_eq!(max.value(), M31::PRIME - 1);
    }
}

#[cfg(test)]
mod field_addition_tests {
    use super::*;

    #[test]
    fn test_addition_basic() {
        let a = M31::from(100u32);
        let b = M31::from(200u32);
        let c = a + b;
        assert_eq!(c.value(), 300);
    }

    #[test]
    fn test_addition_commutative() {
        // a + b = b + a
        for i in 0..100 {
            for j in 0..100 {
                let a = M31::from(i * 1000);
                let b = M31::from(j * 2000);
                assert_eq!(a + b, b + a, "Addition not commutative for {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_addition_associative() {
        // (a + b) + c = a + (b + c)
        for i in 0..50 {
            for j in 0..50 {
                for k in 0..50 {
                    let a = M31::from(i * 10000);
                    let b = M31::from(j * 20000);
                    let c = M31::from(k * 30000);
                    assert_eq!((a + b) + c, a + (b + c));
                }
            }
        }
    }

    #[test]
    fn test_addition_with_overflow() {
        // Adding near PRIME should wrap correctly
        let near_max = M31::from(M31::PRIME - 10);
        let small = M31::from(20u32);
        let result = near_max + small;
        // (P - 10) + 20 = P + 10 = 10 (mod P)
        assert_eq!(result.value(), 10);
    }

    #[test]
    fn test_addition_zero() {
        for i in 0..1000 {
            let a = M31::from(i * 1000);
            let zero = M31::zero();
            assert_eq!(a + zero, a);
            assert_eq!(zero + a, a);
        }
    }

    #[test]
    fn test_addition_wraparound() {
        let max = M31::from(M31::PRIME - 1);
        let one = M31::one();
        let result = max + one;
        // (P - 1) + 1 = P = 0 (mod P)
        assert_eq!(result.value(), 0);
    }
}

#[cfg(test)]
mod field_subtraction_tests {
    use super::*;

    #[test]
    fn test_subtraction_basic() {
        let a = M31::from(200u32);
        let b = M31::from(100u32);
        let c = a - b;
        assert_eq!(c.value(), 100);
    }

    #[test]
    fn test_subtraction_with_underflow() {
        // Subtracting larger from smaller should wrap
        let small = M31::from(10u32);
        let large = M31::from(20u32);
        let result = small - large;
        // 10 - 20 = -10 = P - 10 (mod P)
        assert_eq!(result.value(), M31::PRIME - 10);
    }

    #[test]
    fn test_subtraction_self() {
        for i in 0..1000 {
            let a = M31::from(i * 1234);
            let result = a - a;
            assert_eq!(result, M31::zero());
        }
    }

    #[test]
    fn test_subtraction_zero() {
        for i in 0..1000 {
            let a = M31::from(i * 5678);
            let zero = M31::zero();
            assert_eq!(a - zero, a);
        }
    }

    #[test]
    fn test_addition_subtraction_inverse() {
        // (a + b) - b = a
        for i in 0..100 {
            for j in 0..100 {
                let a = M31::from(i * 10000);
                let b = M31::from(j * 20000);
                assert_eq!((a + b) - b, a);
            }
        }
    }
}

#[cfg(test)]
mod field_multiplication_tests {
    use super::*;

    #[test]
    fn test_multiplication_basic() {
        let a = M31::from(100u32);
        let b = M31::from(200u32);
        let c = a * b;
        assert_eq!(c.value(), 20000);
    }

    #[test]
    fn test_multiplication_commutative() {
        // a * b = b * a
        for i in 1..100 {
            for j in 1..100 {
                let a = M31::from(i * 100);
                let b = M31::from(j * 200);
                assert_eq!(a * b, b * a, "Multiplication not commutative for {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_multiplication_associative() {
        // (a * b) * c = a * (b * c)
        for i in 1..30 {
            for j in 1..30 {
                for k in 1..30 {
                    let a = M31::from(i * 100);
                    let b = M31::from(j * 200);
                    let c = M31::from(k * 300);
                    assert_eq!((a * b) * c, a * (b * c));
                }
            }
        }
    }

    #[test]
    fn test_multiplication_distributive() {
        // a * (b + c) = a * b + a * c
        for i in 1..50 {
            for j in 1..50 {
                for k in 1..50 {
                    let a = M31::from(i * 1000);
                    let b = M31::from(j * 2000);
                    let c = M31::from(k * 3000);
                    assert_eq!(a * (b + c), a * b + a * c);
                }
            }
        }
    }

    #[test]
    fn test_multiplication_one() {
        for i in 0..1000 {
            let a = M31::from(i * 2345);
            let one = M31::one();
            assert_eq!(a * one, a);
            assert_eq!(one * a, a);
        }
    }

    #[test]
    fn test_multiplication_zero() {
        for i in 1..1000 {
            let a = M31::from(i * 6789);
            let zero = M31::zero();
            assert_eq!(a * zero, zero);
            assert_eq!(zero * a, zero);
        }
    }

    #[test]
    fn test_multiplication_large_values() {
        // Test multiplication near the field prime
        let large1 = M31::from(M31::PRIME / 2);
        let large2 = M31::from(M31::PRIME / 3);
        let result = large1 * large2;
        
        // Result should still be in field
        assert!(result.value() < M31::PRIME);
    }
}

#[cfg(test)]
mod field_conversion_tests {
    use super::*;

    #[test]
    fn test_from_u32() {
        for i in 0..10000 {
            let val = i * 123;
            let m31 = M31::from(val);
            assert_eq!(m31.value(), val % M31::PRIME);
        }
    }

    #[test]
    fn test_from_i32_positive() {
        for i in 0..5000 {
            let val = i as i32;
            let m31 = M31::from(val);
            assert_eq!(m31.value(), val as u32);
        }
    }

    #[test]
    fn test_from_i32_negative() {
        for i in 1..5000 {
            let val = -(i as i32);
            let m31 = M31::from(val);
            // -x should be P - x (mod P)
            let expected = M31::PRIME - (((-val) as u32) % M31::PRIME);
            assert_eq!(m31.value(), expected);
        }
    }

    #[test]
    fn test_from_u64() {
        for i in 0..10000u64 {
            let val = i * 123456789;
            let m31 = M31::from(val);
            assert_eq!(m31.value(), (val % (M31::PRIME as u64)) as u32);
        }
    }

    #[test]
    fn test_from_u64_large() {
        let large = u64::MAX;
        let m31 = M31::from(large);
        assert!(m31.value() < M31::PRIME);
    }
}

#[cfg(test)]
mod field_edge_case_tests {
    use super::*;

    #[test]
    fn test_prime_minus_one() {
        let val = M31::from(M31::PRIME - 1);
        assert_eq!(val.value(), M31::PRIME - 1);
        
        // Adding 1 should give 0
        let one = M31::one();
        assert_eq!(val + one, M31::zero());
    }

    #[test]
    fn test_exactly_prime() {
        let val = M31::from(M31::PRIME);
        assert_eq!(val.value(), 0);
    }

    #[test]
    fn test_double_prime() {
        let val = M31::from(M31::PRIME * 2);
        assert_eq!(val.value(), 0);
    }

    #[test]
    fn test_all_small_values() {
        // Test all values from 0 to 10000
        for i in 0..10000u32 {
            let m31 = M31::from(i);
            assert_eq!(m31.value(), i);
        }
    }

    #[test]
    fn test_powers_of_two() {
        for i in 0..31 {
            let val = 1u32 << i;
            let m31 = M31::from(val);
            assert_eq!(m31.value(), val);
        }
    }

    #[test]
    fn test_boundary_arithmetic() {
        let max = M31::from(M31::PRIME - 1);
        let one = M31::one();
        
        // max + 1 = 0
        assert_eq!(max + one, M31::zero());
        
        // max - max = 0
        assert_eq!(max - max, M31::zero());
        
        // max * 2 = 2P - 2 = P - 2 (mod P)
        let two = M31::from(2u32);
        let result = max * two;
        assert_eq!(result.value(), M31::PRIME - 2);
    }
}

#[cfg(test)]
mod field_property_tests {
    use super::*;

    #[test]
    fn test_field_closure() {
        // All operations should produce elements in the field
        for i in 0..100 {
            for j in 0..100 {
                let a = M31::from(i * 100000);
                let b = M31::from(j * 200000);
                
                let sum = a + b;
                let diff = a - b;
                let product = a * b;
                
                assert!(sum.value() < M31::PRIME);
                assert!(diff.value() < M31::PRIME);
                assert!(product.value() < M31::PRIME);
            }
        }
    }

    #[test]
    fn test_additive_inverse() {
        // For each a, there exists -a such that a + (-a) = 0
        for i in 1..1000 {
            let a = M31::from(i * 1234);
            // -a in field is P - a
            let neg_a = M31::from(M31::PRIME - a.value());
            assert_eq!(a + neg_a, M31::zero());
        }
    }

    #[test]
    fn test_no_zero_divisors() {
        // a * b = 0 implies a = 0 or b = 0
        for i in 1..100 {
            for j in 1..100 {
                let a = M31::from(i * 10000);
                let b = M31::from(j * 20000);
                let product = a * b;
                
                // If neither is zero, product should not be zero
                if a != M31::zero() && b != M31::zero() {
                    assert_ne!(product, M31::zero());
                }
            }
        }
    }
}

#[cfg(test)]
mod field_consistency_tests {
    use super::*;

    #[test]
    fn test_repeated_operations() {
        let a = M31::from(12345u32);
        
        // a + a + a = 3 * a
        let sum = a + a + a;
        let three = M31::from(3u32);
        let product = three * a;
        assert_eq!(sum, product);
    }

    #[test]
    fn test_operation_order() {
        // Test that operations are performed in correct order
        let a = M31::from(100u32);
        let b = M31::from(200u32);
        let c = M31::from(300u32);
        
        // (a + b) * c should not equal a + (b * c)
        let result1 = (a + b) * c;
        let result2 = a + (b * c);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_large_computation_chain() {
        let mut result = M31::one();
        let increment = M31::from(17u32);
        
        // Perform 1000 additions
        for _ in 0..1000 {
            result = result + increment;
        }
        
        // Should equal 1 + 1000 * 17 = 17001
        let expected = M31::from(17001u32);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_alternating_operations() {
        let start = M31::from(1000u32);
        let add_val = M31::from(500u32);
        let sub_val = M31::from(500u32);
        
        let mut result = start;
        for _ in 0..100 {
            result = result + add_val;
            result = result - sub_val;
        }
        
        // Should return to original value
        assert_eq!(result, start);
    }
}

#[cfg(test)]
mod field_hash_and_eq_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_equality() {
        let a = M31::from(12345u32);
        let b = M31::from(12345u32);
        let c = M31::from(54321u32);
        
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_equality_after_reduction() {
        let a = M31::from(100u32);
        let b = M31::from(M31::PRIME + 100);
        
        // Should be equal after modular reduction
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_consistency() {
        let mut set = HashSet::new();
        
        for i in 0..10000 {
            let m31 = M31::from(i);
            set.insert(m31);
        }
        
        // All values should be unique
        assert_eq!(set.len(), 10000);
    }

    #[test]
    fn test_hash_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let a = M31::from(12345u32);
        let b = M31::from(12345u32);
        
        let mut hasher1 = DefaultHasher::new();
        a.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        b.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod field_stress_tests {
    use super::*;

    #[test]
    fn test_many_additions() {
        let mut result = M31::zero();
        let one = M31::one();
        
        // Add 1 a million times
        for _ in 0..1_000_000 {
            result = result + one;
        }
        
        let expected = M31::from(1_000_000u32);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_many_multiplications() {
        let mut result = M31::one();
        let two = M31::from(2u32);
        
        // Multiply by 2 twenty times: 2^20 = 1048576
        for _ in 0..20 {
            result = result * two;
        }
        
        let expected = M31::from(1048576u32);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_random_operations() {
        // Simulate random operations with deterministic seed
        let mut val = M31::from(12345u32);
        
        for i in 0..10000 {
            let op_type = i % 4;
            let operand = M31::from((i * 7919) % 100000);
            
            val = match op_type {
                0 => val + operand,
                1 => val - operand,
                2 => val * operand,
                _ => val + operand,
            };
            
            // Value should always be in field
            assert!(val.value() < M31::PRIME);
        }
    }
}

