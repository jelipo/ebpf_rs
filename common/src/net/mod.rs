use strum_macros::FromRepr;

#[derive(FromRepr, Debug, PartialEq)]
pub enum AddressFamily {
    Inet = 2,
    Inet6 = 10,
}
