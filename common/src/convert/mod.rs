// pub fn to_bpf_struct<T: Sized>(vec: Vec<u8>) -> Result<T>
//     where [(); size_of::<T>()]:
// {
//     let data: [u8; size_of::<T>()] = vec.try_into()
//         .map_err(|_| anyhow!("ensure that the size of type is equal to the length of the vec"))?;
//     let key = unsafe { std::mem::transmute::<[u8; size_of::<T>()], T>(data) };
//     Ok(key)
// }
