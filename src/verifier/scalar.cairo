use option::OptionTrait;
use traits::{TryInto, Into};
use integer::NumericLiteral;
use debug::PrintTrait;
use hash::LegacyHash;

use alexandria_math::mod_arithmetics::{
    mult_inverse, pow_mod, add_mod, sub_mod, mult_mod, div_mod, add_inverse_mod
};

use renegade_contracts::utils::constants::SCALAR_FIELD_ORDER;

// TODO: When deserializing Scalars from calldata / storage, we need to assert that they are
// within the scalar field order.
// Best way to do this is probably to accept felts for calldata, and call .into() then.
#[derive(Default, Drop, Copy, PartialEq, PartialOrd, Serde, starknet::Store)]
struct Scalar {
    inner: felt252
}

#[generate_trait]
impl ScalarImpl of ScalarTrait {
    fn inverse(self: @Scalar) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = mult_inverse((*self.inner).into(), SCALAR_FIELD_ORDER).try_into().unwrap();
        Scalar { inner }
    }

    fn pow(self: @Scalar, exponent: u256) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = pow_mod((*self.inner).into(), exponent, SCALAR_FIELD_ORDER).try_into().unwrap();
        Scalar { inner }
    }
}

// -----------------------------
// | ARITHMETIC IMPLEMENTATION |
// -----------------------------

// ------------
// | ADDITION |
// ------------

impl ScalarAdd of Add<Scalar> {
    fn add(lhs: Scalar, rhs: Scalar) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = add_mod(lhs.inner.into(), rhs.inner.into(), SCALAR_FIELD_ORDER)
            .try_into()
            .unwrap();
        Scalar { inner }
    }
}

impl ScalarAddEq of AddEq<Scalar> {
    fn add_eq(ref self: Scalar, other: Scalar) {
        self = Add::add(self, other);
    }
}

// ---------------
// | SUBTRACTION |
// ---------------

impl ScalarSub of Sub<Scalar> {
    fn sub(lhs: Scalar, rhs: Scalar) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = sub_mod(lhs.inner.into(), rhs.inner.into(), SCALAR_FIELD_ORDER)
            .try_into()
            .unwrap();
        Scalar { inner }
    }
}

impl ScalarSubEq of SubEq<Scalar> {
    fn sub_eq(ref self: Scalar, other: Scalar) {
        self = Sub::sub(self, other);
    }
}

// ------------------
// | MULTIPLICATION |
// ------------------

impl ScalarMul of Mul<Scalar> {
    fn mul(lhs: Scalar, rhs: Scalar) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = mult_mod(lhs.inner.into(), rhs.inner.into(), SCALAR_FIELD_ORDER)
            .try_into()
            .unwrap();
        Scalar { inner }
    }
}

impl ScalarMulEq of MulEq<Scalar> {
    fn mul_eq(ref self: Scalar, other: Scalar) {
        self = Mul::mul(self, other);
    }
}

// ------------
// | DIVISION |
// ------------

impl ScalarDiv of Div<Scalar> {
    fn div(lhs: Scalar, rhs: Scalar) -> Scalar {
        // Under the hood, this is implemented as
        // lhs * rhs.inverse()
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = div_mod(lhs.inner.into(), rhs.inner.into(), SCALAR_FIELD_ORDER)
            .try_into()
            .unwrap();
        Scalar { inner }
    }
}

impl ScalarDivEq of DivEq<Scalar> {
    fn div_eq(ref self: Scalar, other: Scalar) {
        self = Div::div(self, other);
    }
}

// ------------
// | NEGATION |
// ------------

impl ScalarNeg of Neg<Scalar> {
    fn neg(a: Scalar) -> Scalar {
        // Safe to unwrap b/c scalar field is smaller than base field
        let inner = add_inverse_mod(a.inner.into(), SCALAR_FIELD_ORDER).try_into().unwrap();
        Scalar { inner }
    }
}

// -----------------------
// | MISC IMPLEMENTATION |
// -----------------------

// --------------
// | CONVERSION |
// --------------

impl IntoScalar<T, impl TIntoU256: Into<T, u256>> of Into<T, Scalar> {
    fn into(self: T) -> Scalar {
        let inner_u256 = self.into() % SCALAR_FIELD_ORDER;
        // Safe to unwrap b/c scalar field is smaller than base field
        Scalar { inner: inner_u256.try_into().unwrap() }
    }
}

impl ScalarIntoU256 of Into<Scalar, u256> {
    fn into(self: Scalar) -> u256 {
        self.inner.into()
    }
}

impl ScalarIntoFelt of Into<Scalar, felt252> {
    fn into(self: Scalar) -> felt252 {
        self.inner
    }
}

// ------------
// | ZEROABLE |
// ------------

impl ScalarZeroable of Zeroable<Scalar> {
    fn zero() -> Scalar {
        Scalar { inner: 0 }
    }

    fn is_zero(self: Scalar) -> bool {
        self.inner == 0
    }

    fn is_non_zero(self: Scalar) -> bool {
        !Zeroable::is_zero(self)
    }
}

// ---------
// | DEBUG |
// ---------

impl ScalarPrintTrait of PrintTrait<Scalar> {
    fn print(self: Scalar) {
        self.inner.print();
    }
}

// --------
// | HASH |
// --------

impl ScalarLegacyHash of LegacyHash<Scalar> {
    fn hash(state: felt252, value: Scalar) -> felt252 {
        LegacyHash::hash(state, value.inner)
    }
}
