/// Stream peek hook for later PII / DLP scanners.
pub trait Inspector: Send {
    fn on_bytes(&mut self, dir: Dir, bytes: &[u8]);
}

#[derive(Clone, Copy, Debug)]
pub enum Dir {
    Upstream,
    Downstream,
}

pub struct NoopInspector;

impl Inspector for NoopInspector {
    #[inline]
    fn on_bytes(&mut self, _dir: Dir, _bytes: &[u8]) {}
}
