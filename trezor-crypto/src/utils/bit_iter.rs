pub trait Bits {
    const SIZE: usize;

    fn bits(self) -> u32;
}

impl Bits for u8 {
    const SIZE: usize = 8;

    fn bits(self) -> u32 {
        self as u32
    }
}

impl<'a> Bits for &'a u8 {
    const SIZE: usize = 8;

    fn bits(self) -> u32 {
        *self as u32
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Bits11(u16);

impl Bits for Bits11 {
    const SIZE: usize = 11;

    fn bits(self) -> u32 {
        self.0 as u32
    }
}

impl From<u16> for Bits11 {
    fn from(val: u16) -> Self {
        Bits11(val)
    }
}

impl From<Bits11> for u16 {
    fn from(val: Bits11) -> Self {
        val.0
    }
}

pub struct BitIter<In: Bits, Out: Bits, I: Iterator<Item = In> + Sized> {
    _phantom: ::std::marker::PhantomData<Out>,
    source: I,
    read: usize,
    buffer: u64,
}

impl<In, Out, I> BitIter<In, Out, I>
where
    In: Bits,
    Out: Bits,
    I: Iterator<Item = In>,
{
    pub fn new(source: I) -> Self {
        let source = source.into_iter();

        BitIter {
            _phantom: ::std::marker::PhantomData,
            source,
            read: 0,
            buffer: 0,
        }
    }
}

impl<In, Out, I> Iterator for BitIter<In, Out, I>
where
    In: Bits,
    Out: Bits + From<u16>,
    I: Iterator<Item = In>,
{
    type Item = Out;

    fn next(&mut self) -> Option<Out> {
        while self.read < Out::SIZE {
            let bits = self.source.next()?.bits() as u64;

            self.read += In::SIZE;
            self.buffer |= bits << (64 - self.read);
        }

        let result = (self.buffer >> (64 - Out::SIZE)) as u16;

        self.buffer <<= Out::SIZE;
        self.read -= Out::SIZE;

        Some(result.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.source.size_hint();

        (
            (lower * In::SIZE) / Out::SIZE,
            upper.map(|n| (n * In::SIZE) / Out::SIZE),
        )
    }
}
