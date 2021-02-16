// macro_rules! return_exception {
//     ($res:expr) => {
//         match $res {
//             HandlerInvocationResult::Exception(e) => return HandlerInvocationResult::Error(e),
//             _ => {}
//         }
//     };
// }

macro_rules! try_or_to_exception {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => {
                let (exception, data) = err.to_exception();
                return HandlerInvocationResult::Exception {
                    name: exception,
                    data,
                };
            }
        }
    };
}

macro_rules! try_or_exception {
    ($expr:expr, $exception:expr) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => {
                let mut data: hashbrown::HashMap<SmolStr, SmolStr> = hashbrown::HashMap::new();
                data.insert("error".into(), err.to_string().into());
                return HandlerInvocationResult::Exception {
                    name: $exception.clone(),
                    data,
                };
            }
        }
    };
}

macro_rules! try_option_or_exception {
    ($expr:expr, $exception:expr) => {
        match $expr {
            core::option::Option::Some(val) => val,
            core::option::Option::None => {
                return HandlerInvocationResult::Exception {
                    name: $exception.clone(),
                    data: Default::default(),
                };
            }
        }
    };
}
