use crate::core::ux::*;

use nom::{
    bits::complete::take as take_bits,
    combinator::map,
    error::{ErrorKind as NomErrorKind, ParseError as NomParseError},
    ErrorConvert, Slice,
};
use std::{fmt, ops::RangeFrom};

pub type Input<'a> = &'a [u8];
pub type Result<'a, T> = nom::IResult<Input<'a>, T, Error<Input<'a>>>;
pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, T> = nom::IResult<BitInput<'a>, T, Error<BitInput<'a>>>;

pub trait BitParsable
where
    Self: Sized,
{
    fn parse(i: BitInput) -> BitResult<Self>;
}

impl BitParsable for u8 {
    fn parse(i: BitInput) -> BitResult<Self> {
        map(take_bits(8usize), Self::from_be)(i)
    }
}

macro_rules! impl_bit_parsable_for_ux {
    ($($width: expr),*) => {
        $(
            paste::item! {
                impl BitParsable for [<u $width>] {
                    fn parse(i: BitInput) -> BitResult<Self> {
                        map(take_bits($width as usize), Self::new)(i)
                    }
                }
            }
        )*
    };
}

impl_bit_parsable_for_ux!(1, 2, 3, 4, 6, 7, 12, 13, 20, 24, 48);

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        Error { errors }
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<'a> fmt::Debug for Error<&'a [u8]> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "/!\\ ersatz parsing error\n")?;

        let mut shown_input = None;
        let margin_left = 4;
        let margin_str = " ".repeat(margin_left);
        let maxlen = 60;
        let print_slice =
            |f: &mut fmt::Formatter, s: &[u8], offset: usize, len: usize| -> fmt::Result {
                let (s, offset, len) = {
                    let avail_after = s.len() - offset;
                    let after = std::cmp::min(avail_after, maxlen / 2);

                    let avail_before = offset;
                    let before = std::cmp::min(avail_before, maxlen / 2);

                    let new_start = offset - before;
                    let new_end = offset + after;
                    let new_offset = before;
                    let new_len = std::cmp::min(new_end - new_start, len);

                    (&s[new_start..new_end], new_offset, new_len)
                };

                write!(f, "{}", margin_str)?;
                for b in s {
                    write!(f, "{:02X} ", b)?;
                }
                write!(f, "\n")?;

                write!(f, "{}", margin_str)?;
                for i in 0..s.len() {
                    if i == offset + len - 1 {
                        write!(f, "~~")?;
                    } else if (offset..offset + len).contains(&i) {
                        write!(f, "~~~")?;
                    } else {
                        write!(f, "   ")?;
                    };
                }
                write!(f, "\n")?;

                Ok(())
            };

        for (input, kind) in self.errors.iter().rev() {
            let prefix = match kind {
                ErrorKind::Context(ctx) => format!("...in {}", ctx),
                ErrorKind::Nom(err) => format!("nom error {:?}", err),
            };

            write!(f, "{}\n", prefix)?;
            match shown_input {
                None => {
                    shown_input.replace(input);
                    print_slice(f, input, 0, input.len())?;
                }
                Some(parent_input) => {
                    use nom::Offset;
                    let offset = parent_input.offset(input);
                    print_slice(f, parent_input, offset, input.len())?;
                }
            };
        }
        Ok(())
    }
}

impl<I> NomParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}
