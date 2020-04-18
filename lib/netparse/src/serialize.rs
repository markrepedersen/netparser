use ux::*;
use cookie_factory as cf;
use std::io;
use bitvec::{
    store::BitStore,
    order::Msb0,
    prelude::*,
};

pub type BitOutput = BitVec<Msb0, u8>;

pub fn bits<W, F>(f: F) -> impl cf::SerializeFn<W>
where
    W: io::Write,
    F: Fn(&mut BitOutput),
{
    move |mut out: cf::WriteContext<W>| {
        let mut bo = BitOutput::new();
        f(&mut bo);

        io::Write::write(&mut out, bo.as_slice())?;
        Ok(out)
    }
}

pub trait WriteLastNBits {
    fn write_last_n_bits<B: BitStore>(&mut self, b: B, num_bits: usize);
}

impl WriteLastNBits for BitOutput {
    fn write_last_n_bits<B: BitStore>(&mut self, b: B, num_bits: usize) {
        let bitslice = b.bits::<Msb0>();
        let start = bitslice.len() - num_bits;
        self.extend_from_slice(&bitslice[start..])
    }
}

pub trait BitSerialize {
    fn write(&self, b: &mut BitOutput);
}

macro_rules! impl_bit_serialize_for_ux {
    ($($width: expr),*) => {
        $(
            paste::item! {
                impl BitSerialize for [<u $width>] {
                    fn write(&self, b: &mut BitOutput) {
                        b.write_last_n_bits(u16::from(*self), $width);
                    }
                }
            }
        )*
    };
}

impl_bit_serialize_for_ux!(2, 3, 4, 6, 13);
