use anyhow::anyhow;
use plain::Error;

pub fn to_err(err: Error) -> anyhow::Error {
    match err {
        Error::TooShort => { anyhow!("TooShort") }
        Error::BadAlignment => { anyhow!("TooShort") }
    }
}