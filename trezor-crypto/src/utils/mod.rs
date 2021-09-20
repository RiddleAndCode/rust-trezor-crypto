mod bit_iter;

pub use bit_iter::{BitIter, Bits, Bits11};

pub trait IterExt: Iterator + Sized {
    fn bits<Out>(self) -> BitIter<Self::Item, Out, Self>
    where
        Out: Bits,
        Self::Item: Bits,
        Self: Sized,
    {
        BitIter::new(self)
    }

    fn join(self, separator: &str) -> String
    where
        Self::Item: AsRef<str>,
    {
        let mut out = String::new();
        let mut iter = self.peekable();
        while let Some(item) = iter.next() {
            out.push_str(item.as_ref());
            if iter.peek().is_some() {
                out.push_str(separator)
            }
        }
        out
    }
}

impl<I: Iterator + Sized> IterExt for I {}
