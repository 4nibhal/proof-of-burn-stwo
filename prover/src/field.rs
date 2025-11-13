// M31 field implementation for testing
// This is a standalone implementation that doesn't depend on stwo
// Once stwo is stable, we'll use their implementation

use std::ops::{Add, Mul, Sub};
use serde::{Serialize, Deserialize};

/// M31 field element: elements of the field F_{2^31 - 1}
/// This is the Mersenne prime field used by Circle STARKs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct M31(pub u32);

impl M31 {
    pub const PRIME: u32 = 2147483647; // 2^31 - 1

    /// Create a new M31 element, automatically reducing modulo the prime
    pub fn new(value: u32) -> Self {
        M31(value % Self::PRIME)
    }

    /// Create M31 from u64, reducing modulo the prime
    pub fn from_u64(value: u64) -> Self {
        M31((value % (Self::PRIME as u64)) as u32)
    }

    /// Zero element
    pub fn zero() -> Self {
        M31(0)
    }

    /// One element
    pub fn one() -> Self {
        M31(1)
    }

    /// Get the raw value
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for M31 {
    fn from(value: u32) -> Self {
        M31::new(value)
    }
}

impl From<i32> for M31 {
    fn from(value: i32) -> Self {
        if value >= 0 {
            M31::new(value as u32)
        } else {
            // Handle negative by wrapping: -x = P - x
            M31::new(M31::PRIME - ((-value) as u32 % M31::PRIME))
        }
    }
}

impl From<u64> for M31 {
    fn from(value: u64) -> Self {
        M31::from_u64(value)
    }
}

impl From<usize> for M31 {
    fn from(value: usize) -> Self {
        M31::from_u64(value as u64)
    }
}

impl Add for M31 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // Addition in M31: (a + b) mod P
        let sum = (self.0 as u64 + rhs.0 as u64) % (M31::PRIME as u64);
        M31(sum as u32)
    }
}

impl Sub for M31 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // Subtraction in M31: (a - b) mod P
        // Handle underflow by adding P first
        let diff = if self.0 >= rhs.0 {
            self.0 - rhs.0
        } else {
            (M31::PRIME - rhs.0) + self.0
        };
        M31(diff)
    }
}

impl Mul for M31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // Multiplication in M31: (a * b) mod P
        let product = (self.0 as u64 * rhs.0 as u64) % (M31::PRIME as u64);
        M31(product as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m31_basic() {
        let a = M31::from(10);
        let b = M31::from(20);
        let c = a + b;
        assert_eq!(c.value(), 30);
    }

    #[test]
    fn test_m31_modulo() {
        let large = M31::from(M31::PRIME + 5);
        assert_eq!(large.value(), 5);
    }

    #[test]
    fn test_m31_mul() {
        let a = M31::from(1000);
        let b = M31::from(2000);
        let c = a * b;
        assert_eq!(c.value(), 2000000);
    }

    #[test]
    fn test_m31_sub() {
        let a = M31::from(100);
        let b = M31::from(30);
        let c = a - b;
        assert_eq!(c.value(), 70);
    }

    #[test]
    fn test_m31_sub_underflow() {
        let a = M31::from(30);
        let b = M31::from(100);
        let c = a - b;
        // Should wrap around: (30 - 100) mod P = (P - 70) = 2147483577
        assert_eq!(c.value(), M31::PRIME - 70);
    }

    #[test]
    fn test_m31_field_properties() {
        // Test additive identity
        let a = M31::from(42);
        let zero = M31::zero();
        assert_eq!(a + zero, a);

        // Test multiplicative identity
        let one = M31::one();
        assert_eq!(a * one, a);

        // Test commutativity of addition
        let b = M31::from(17);
        assert_eq!(a + b, b + a);

        // Test commutativity of multiplication
        assert_eq!(a * b, b * a);
    }
}

