use anyhow::{anyhow, Result};

pub trait BpfStruct {
    fn to_struct<T>(&self) -> Result<&T>;
}

impl BpfStruct for Vec<u8> {
    fn to_struct<T>(&self) -> Result<&T> {
        let (head, body, _tail) = unsafe { self.align_to::<T>() };
        if head.is_empty() {
            return Err(anyhow!("to struct failed"));
        }
        Ok(&body[0])
    }
}
