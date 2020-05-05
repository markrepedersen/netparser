/// This is taken from https://github.com/kjetilkjeka/uX. All credits go to the author of it.
/// This is being copied because for some reason it doesn't implement Serializable/Deserialiable. Until that's fixed I'll just keep this here.
use serde::{Deserialize, Serialize};
use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt::{Binary, Display, Formatter, LowerHex, Octal, UpperHex};
use std::hash::{Hash, Hasher};
use std::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, ShlAssign, Shr,
    ShrAssign,
};

macro_rules! implement_common {
    ($name:ident, $bits:expr, $type:ident) => {
        impl $name {
            pub fn min_value() -> $name {
                $name::MIN
            }

            pub fn max_value() -> $name {
                $name::MAX
            }

            pub fn new(value: $type) -> $name {
                assert!(value <= $name::MAX.0 && value >= $name::MIN.0);
                $name(value)
            }

            pub fn wrapping_sub(self, rhs: Self) -> Self {
                $name(self.0.wrapping_sub(rhs.0)).mask()
            }

            pub fn wrapping_add(self, rhs: Self) -> Self {
                $name(self.0.wrapping_add(rhs.0)).mask()
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.mask().0 == other.mask().0
            }
        }

        impl Eq for $name {}

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<Ordering> {
                self.mask().0.partial_cmp(&other.mask().0)
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &$name) -> Ordering {
                self.mask().0.cmp(&other.mask().0)
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, h: &mut H) {
                self.mask().0.hash(h)
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
                let &$name(ref value) = self;
                <$type as Display>::fmt(value, f)
            }
        }
        impl UpperHex for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
                let &$name(ref value) = self;
                <$type as UpperHex>::fmt(value, f)
            }
        }
        impl LowerHex for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
                let &$name(ref value) = self;
                <$type as LowerHex>::fmt(value, f)
            }
        }
        impl Octal for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
                let &$name(ref value) = self;
                <$type as Octal>::fmt(value, f)
            }
        }
        impl Binary for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
                let &$name(ref value) = self;
                <$type as Binary>::fmt(value, f)
            }
        }

        impl<T> Shr<T> for $name
        where
            $type: Shr<T, Output = $type>,
        {
            type Output = $name;

            fn shr(self, rhs: T) -> $name {
                $name(self.mask().0.shr(rhs))
            }
        }

        impl<T> Shl<T> for $name
        where
            $type: Shl<T, Output = $type>,
        {
            type Output = $name;

            fn shl(self, rhs: T) -> $name {
                $name(self.mask().0.shl(rhs))
            }
        }

        impl<T> ShrAssign<T> for $name
        where
            $type: ShrAssign<T>,
        {
            fn shr_assign(&mut self, rhs: T) {
                *self = self.mask();
                self.0.shr_assign(rhs);
            }
        }

        impl<T> ShlAssign<T> for $name
        where
            $type: ShlAssign<T>,
        {
            fn shl_assign(&mut self, rhs: T) {
                *self = self.mask();
                self.0.shl_assign(rhs);
            }
        }

        impl BitOr<$name> for $name {
            type Output = $name;

            fn bitor(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitor(rhs.mask().0))
            }
        }

        impl<'a> BitOr<&'a $name> for $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitor(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitor(rhs.mask().0))
            }
        }

        impl<'a> BitOr<$name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitor(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitor(rhs.mask().0))
            }
        }

        impl<'a> BitOr<&'a $name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitor(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitor(rhs.mask().0))
            }
        }

        impl BitOrAssign<$name> for $name {
            fn bitor_assign(&mut self, other: $name) {
                *self = self.mask();
                self.0.bitor_assign(other.mask().0)
            }
        }

        impl BitXor<$name> for $name {
            type Output = $name;

            fn bitxor(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitxor(rhs.mask().0))
            }
        }

        impl<'a> BitXor<&'a $name> for $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitxor(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitxor(rhs.mask().0))
            }
        }

        impl<'a> BitXor<$name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitxor(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitxor(rhs.mask().0))
            }
        }

        impl<'a> BitXor<&'a $name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitxor(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitxor(rhs.mask().0))
            }
        }

        impl BitXorAssign<$name> for $name {
            fn bitxor_assign(&mut self, other: $name) {
                *self = self.mask();
                self.0.bitxor_assign(other.mask().0)
            }
        }

        impl Not for $name {
            type Output = $name;

            fn not(self) -> $name {
                $name(self.mask().0.not())
            }
        }

        impl<'a> Not for &'a $name {
            type Output = <$name as Not>::Output;

            fn not(self) -> $name {
                $name(self.mask().0.not())
            }
        }

        impl BitAnd<$name> for $name {
            type Output = $name;

            fn bitand(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitand(rhs.mask().0))
            }
        }

        impl<'a> BitAnd<&'a $name> for $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitand(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitand(rhs.mask().0))
            }
        }

        impl<'a> BitAnd<$name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitand(self, rhs: $name) -> Self::Output {
                $name(self.mask().0.bitand(rhs.mask().0))
            }
        }

        impl<'a> BitAnd<&'a $name> for &'a $name {
            type Output = <$name as BitOr<$name>>::Output;

            fn bitand(self, rhs: &'a $name) -> Self::Output {
                $name(self.mask().0.bitand(rhs.mask().0))
            }
        }

        impl BitAndAssign<$name> for $name {
            fn bitand_assign(&mut self, other: $name) {
                *self = self.mask();
                self.0.bitand_assign(other.mask().0)
            }
        }

        impl std::ops::Add<$name> for $name {
            type Output = $name;
            #[allow(unused_comparisons)]
            fn add(self, other: $name) -> $name {
                if self.0 > 0 && other.0 > 0 {
                    debug_assert!(Self::MAX.0 - other.0 >= self.0);
                } else if self.0 < 0 && other.0 < 0 {
                    debug_assert!(Self::MIN.0 - other.0 <= self.0);
                }
                self.wrapping_add(other)
            }
        }

        impl std::ops::Sub<$name> for $name {
            type Output = $name;
            #[allow(unused_comparisons)]
            fn sub(self, other: $name) -> $name {
                if self > other {
                    debug_assert!(Self::MAX.0 + other.0 >= self.0);
                } else if self < other {
                    debug_assert!(Self::MIN.0 + other.0 <= self.0);
                }
                self.wrapping_sub(other)
            }
        }
    };
}

macro_rules! define_unsigned {
    ($name:ident, $bits:expr, $type:ident) => {define_unsigned!(#[doc=""], $name, $bits, $type);};
    (#[$doc:meta], $name:ident, $bits:expr, $type:ident) => {

       #[$doc]
        #[allow(non_camel_case_types)]
        #[derive(Default, Clone, Copy, Debug, Serialize, Deserialize)]
        pub struct $name($type);

        impl $name {
            pub const MAX: Self = $name(((1 as $type) << $bits) -1 );
            pub const MIN: Self = $name(0);

            fn mask(self) -> Self {
                $name(self.0 & ( ((1 as $type) << $bits).overflowing_sub(1).0))
            }
        }

        implement_common!($name, $bits, $type);
    }
}

define_unsigned!(#[doc="The 1-bit unsigned integer type."], u1, 1, u8);
define_unsigned!(#[doc="The 2-bit unsigned integer type."], u2, 2, u8);
define_unsigned!(#[doc="The 3-bit unsigned integer type."], u3, 3, u8);
define_unsigned!(#[doc="The 4-bit unsigned integer type."], u4, 4, u8);
define_unsigned!(#[doc="The 5-bit unsigned integer type."], u5, 5, u8);
define_unsigned!(#[doc="The 6-bit unsigned integer type."], u6, 6, u8);
define_unsigned!(#[doc="The 7-bit unsigned integer type."], u7, 7, u8);

define_unsigned!(#[doc="The 9-bit unsigned integer type."], u9, 9, u16);
define_unsigned!(#[doc="The 10-bit unsigned integer type."], u10, 10, u16);
define_unsigned!(#[doc="The 11-bit unsigned integer type."], u11, 11, u16);
define_unsigned!(#[doc="The 12-bit unsigned integer type."], u12, 12, u16);
define_unsigned!(#[doc="The 13-bit unsigned integer type."], u13, 13, u16);
define_unsigned!(#[doc="The 14-bit unsigned integer type."], u14, 14, u16);
define_unsigned!(#[doc="The 15-bit unsigned integer type."], u15, 15, u16);
define_unsigned!(#[doc="The 17-bit unsigned integer type."], u17, 17, u32);
define_unsigned!(#[doc="The 18-bit unsigned integer type."], u18, 18, u32);
define_unsigned!(#[doc="The 19-bit unsigned integer type."], u19, 19, u32);

define_unsigned!(#[doc="The 20-bit unsigned integer type."], u20, 20, u32);
define_unsigned!(#[doc="The 21-bit unsigned integer type."], u21, 21, u32);
define_unsigned!(#[doc="The 22-bit unsigned integer type."], u22, 22, u32);
define_unsigned!(#[doc="The 23-bit unsigned integer type."], u23, 23, u32);
define_unsigned!(#[doc="The 24-bit unsigned integer type."], u24, 24, u32);

define_unsigned!(#[doc="The 48-bit unsigned integer type."], u48, 48, u64);
define_unsigned!(#[doc="The 56-bit unsigned integer type."], u56, 56, u64);
